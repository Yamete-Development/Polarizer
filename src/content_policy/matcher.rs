//! Aho-Corasick-backed native content-policy matcher.

use std::collections::HashMap;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use uuid::Uuid;

use super::model::{RulePattern, WildcardPatternType};
use super::normalization::{
    NormalizedText, SecurityNormalizedText, is_security_pattern_eligible, is_token_character,
    normalize_pattern, security_normalize_pattern,
};
use super::resolver::ByteSpan;

/// Input accepted by the policy compiler.  Keeping rule and pattern identity
/// here lets compilation remain independent of the eventual policy evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternDefinition {
    pub rule_id: Uuid,
    pub pattern_id: Uuid,
    pub pattern: String,
    pub pattern_type: WildcardPatternType,
}

impl PatternDefinition {
    pub fn new(
        rule_id: Uuid,
        pattern_id: Uuid,
        pattern: impl Into<String>,
        pattern_type: WildcardPatternType,
    ) -> Self {
        Self {
            rule_id,
            pattern_id,
            pattern: pattern.into(),
            pattern_type,
        }
    }

    pub fn from_rule_pattern(rule_id: Uuid, pattern: &RulePattern) -> Self {
        Self::new(
            rule_id,
            pattern.id,
            pattern.pattern.clone(),
            pattern.pattern_type,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MatchDetails {
    #[default]
    None,
    PatternsAndSpans,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MatchOptions {
    pub details: MatchDetails,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternMatch {
    pub pattern_id: Uuid,
    pub pattern_type: WildcardPatternType,
    pub normalized_span: ByteSpan,
    pub original_span: ByteSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleTrigger {
    pub rule_id: Uuid,
    /// Empty when `MatchOptions::details` is `MatchDetails::None`.
    pub matches: Vec<PatternMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MatchReport {
    pub triggers: Vec<RuleTrigger>,
}

impl MatchReport {
    pub fn is_empty(&self) -> bool {
        self.triggers.is_empty()
    }

    pub fn rule_ids(&self) -> impl Iterator<Item = Uuid> + '_ {
        self.triggers.iter().map(|trigger| trigger.rule_id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MatcherBuildError {
    #[error("pattern {pattern_id} for rule {rule_id} is empty after normalization")]
    EmptyPattern { rule_id: Uuid, pattern_id: Uuid },
    #[error("failed to compile Aho-Corasick matcher: {0}")]
    Automaton(String),
}

#[derive(Debug, Clone)]
struct CompiledPattern {
    text: String,
    pattern_type: WildcardPatternType,
    targets: Vec<PatternTarget>,
}

#[derive(Debug, Clone, Copy)]
struct PatternTarget {
    rule_id: Uuid,
    pattern_id: Uuid,
}

#[derive(Debug)]
struct MatcherView {
    automaton: AhoCorasick,
    patterns: Vec<CompiledPattern>,
}

impl MatcherView {
    fn compile(patterns: Vec<CompiledPattern>) -> Result<Self, MatcherBuildError> {
        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .build(patterns.iter().map(|pattern| pattern.text.as_bytes()))
            .map_err(|error| MatcherBuildError::Automaton(error.to_string()))?;

        Ok(Self {
            automaton,
            patterns,
        })
    }
}

/// Immutable matcher suitable for sharing between evaluator calls.
#[derive(Debug)]
pub struct CompiledMatcher {
    canonical: MatcherView,
    security: Option<MatcherView>,
}

impl CompiledMatcher {
    pub fn compile<I>(definitions: I) -> Result<Self, MatcherBuildError>
    where
        I: IntoIterator<Item = PatternDefinition>,
    {
        let mut definitions = definitions.into_iter().collect::<Vec<_>>();
        definitions.sort_by_key(|definition| {
            (
                definition.rule_id,
                definition.pattern_id,
                definition.pattern_type,
            )
        });

        let mut canonical_patterns = Vec::<CompiledPattern>::new();
        let mut canonical_indexes = HashMap::<(String, WildcardPatternType), usize>::new();
        let mut security_patterns = Vec::<CompiledPattern>::new();
        let mut security_indexes = HashMap::<(String, WildcardPatternType), usize>::new();

        for definition in definitions {
            let text = normalize_pattern(&definition.pattern);
            if text.is_empty() {
                return Err(MatcherBuildError::EmptyPattern {
                    rule_id: definition.rule_id,
                    pattern_id: definition.pattern_id,
                });
            }

            let target = PatternTarget {
                rule_id: definition.rule_id,
                pattern_id: definition.pattern_id,
            };
            insert_pattern(
                &mut canonical_patterns,
                &mut canonical_indexes,
                text,
                definition.pattern_type,
                target,
            );

            if definition.pattern_type != WildcardPatternType::Phrase {
                let authored_literal = authored_literal(&definition);
                if is_security_pattern_eligible(authored_literal) {
                    let security_text = security_normalize_pattern(authored_literal);
                    if !security_text.is_empty() {
                        insert_pattern(
                            &mut security_patterns,
                            &mut security_indexes,
                            security_text,
                            definition.pattern_type,
                            target,
                        );
                    }
                }
            }
        }

        Ok(Self {
            canonical: MatcherView::compile(canonical_patterns)?,
            security: (!security_patterns.is_empty())
                .then(|| MatcherView::compile(security_patterns))
                .transpose()?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.canonical.patterns.is_empty()
    }

    pub fn match_text(&self, input: &str, options: MatchOptions) -> MatchReport {
        let normalized = NormalizedText::new(input);
        let security = SecurityNormalizedText::new(input);
        self.match_normalized_with_security(&normalized, Some(&security), &[], options)
    }

    /// Match a surface that was normalized once by shared message analysis.
    /// Callers may run a cheap no-detail pass and only request attribution
    /// details after a rule that needs spans or logging actually triggers.
    pub fn match_normalized(
        &self,
        normalized: &NormalizedText,
        options: MatchOptions,
    ) -> MatchReport {
        self.match_view(&self.canonical, normalized, &[], options)
    }

    /// Match the auxiliary security representation alongside a canonical
    /// surface. Excluded source ranges are used for message URLs and email
    /// addresses, where dots and punctuation are structural rather than
    /// obfuscation.
    pub fn match_normalized_with_security(
        &self,
        normalized: &NormalizedText,
        security: Option<&SecurityNormalizedText>,
        security_excluded_spans: &[ByteSpan],
        options: MatchOptions,
    ) -> MatchReport {
        let canonical = self.match_view(&self.canonical, normalized, &[], options);
        let Some(security) = security else {
            return canonical;
        };
        let Some(security_view) = &self.security else {
            return canonical;
        };
        merge_reports(
            canonical,
            self.match_view(security_view, security, security_excluded_spans, options),
            options.details,
        )
    }

    pub fn match_security_normalized(
        &self,
        normalized: &SecurityNormalizedText,
        security_excluded_spans: &[ByteSpan],
        options: MatchOptions,
    ) -> MatchReport {
        let Some(security_view) = &self.security else {
            return MatchReport::default();
        };
        self.match_view(security_view, normalized, security_excluded_spans, options)
    }

    fn match_view<V: NormalizedInput>(
        &self,
        view: &MatcherView,
        normalized: &V,
        security_excluded_spans: &[ByteSpan],
        options: MatchOptions,
    ) -> MatchReport {
        let mut triggers = Vec::new();
        let mut trigger_indexes = HashMap::<Uuid, usize>::new();

        // One overlapping Aho-Corasick pass finds every compiled pattern,
        // including shorter patterns nested inside longer ones. Boundary
        // checks happen only for those candidate spans.
        for found in view
            .automaton
            .find_overlapping_iter(normalized.as_str().as_bytes())
        {
            let pattern = &view.patterns[found.pattern().as_usize()];
            let span = ByteSpan {
                start: found.start(),
                end: found.end(),
            };
            if !matches_boundary(normalized, span, pattern.pattern_type) {
                continue;
            }
            let Some(original_span) = normalized.span_for(span) else {
                continue;
            };
            if security_excluded_spans
                .iter()
                .any(|excluded| normalized.span_is_within_original(span, *excluded))
            {
                continue;
            }

            for target in &pattern.targets {
                let trigger_index = *trigger_indexes.entry(target.rule_id).or_insert_with(|| {
                    let index = triggers.len();
                    triggers.push(RuleTrigger {
                        rule_id: target.rule_id,
                        matches: Vec::new(),
                    });
                    index
                });

                if options.details == MatchDetails::PatternsAndSpans {
                    triggers[trigger_index].matches.push(PatternMatch {
                        pattern_id: target.pattern_id,
                        pattern_type: pattern.pattern_type,
                        normalized_span: span,
                        original_span,
                    });
                }
            }
        }

        MatchReport { triggers }
    }

    pub fn matched_rule_ids(&self, input: &str) -> Vec<Uuid> {
        self.match_text(input, MatchOptions::default())
            .rule_ids()
            .collect()
    }
}

trait NormalizedInput {
    fn as_str(&self) -> &str;
    fn span_for(&self, normalized: ByteSpan) -> Option<ByteSpan>;
    fn span_is_within_original(&self, normalized: ByteSpan, original: ByteSpan) -> bool;
    fn is_token_character(character: char) -> bool;
}

impl NormalizedInput for NormalizedText {
    fn as_str(&self) -> &str {
        self.as_str()
    }

    fn span_for(&self, normalized: ByteSpan) -> Option<ByteSpan> {
        self.span_for(normalized)
    }

    fn span_is_within_original(&self, normalized: ByteSpan, original: ByteSpan) -> bool {
        self.span_is_within_original(normalized, original)
    }

    fn is_token_character(character: char) -> bool {
        is_token_character(character)
    }
}

impl NormalizedInput for SecurityNormalizedText {
    fn as_str(&self) -> &str {
        self.as_str()
    }

    fn span_for(&self, normalized: ByteSpan) -> Option<ByteSpan> {
        self.span_for(normalized)
    }

    fn span_is_within_original(&self, normalized: ByteSpan, original: ByteSpan) -> bool {
        self.span_is_within_original(normalized, original)
    }

    fn is_token_character(character: char) -> bool {
        // Underscores are compactable obfuscation separators in this view,
        // including Discord's paired underline delimiters. Canonical matching
        // still treats underscores as token characters for identifiers.
        is_token_character(character) && character != '_'
    }
}

fn insert_pattern(
    patterns: &mut Vec<CompiledPattern>,
    indexes: &mut HashMap<(String, WildcardPatternType), usize>,
    text: String,
    pattern_type: WildcardPatternType,
    target: PatternTarget,
) {
    let key = (text.clone(), pattern_type);
    if let Some(&index) = indexes.get(&key) {
        patterns[index].targets.push(target);
    } else {
        let index = patterns.len();
        indexes.insert(key, index);
        patterns.push(CompiledPattern {
            text,
            pattern_type,
            targets: vec![target],
        });
    }
}

fn authored_literal(definition: &PatternDefinition) -> &str {
    let pattern = definition.pattern.as_str();
    match definition.pattern_type {
        WildcardPatternType::Prefix => pattern.strip_suffix('*').unwrap_or(pattern),
        WildcardPatternType::Suffix => pattern.strip_prefix('*').unwrap_or(pattern),
        WildcardPatternType::Contains => pattern
            .strip_prefix('*')
            .and_then(|pattern| pattern.strip_suffix('*'))
            .unwrap_or(pattern),
        WildcardPatternType::ExactWord | WildcardPatternType::Phrase => pattern,
    }
}

fn merge_reports(
    mut primary: MatchReport,
    secondary: MatchReport,
    details: MatchDetails,
) -> MatchReport {
    let mut indexes = primary
        .triggers
        .iter()
        .enumerate()
        .map(|(index, trigger)| (trigger.rule_id, index))
        .collect::<HashMap<_, _>>();

    for trigger in secondary.triggers {
        let index = *indexes.entry(trigger.rule_id).or_insert_with(|| {
            let index = primary.triggers.len();
            primary.triggers.push(RuleTrigger {
                rule_id: trigger.rule_id,
                matches: Vec::new(),
            });
            index
        });
        if details == MatchDetails::PatternsAndSpans {
            for item in trigger.matches {
                if !primary.triggers[index].matches.iter().any(|existing| {
                    existing.pattern_id == item.pattern_id
                        && existing.pattern_type == item.pattern_type
                        && existing.original_span == item.original_span
                }) {
                    primary.triggers[index].matches.push(item);
                }
            }
        }
    }

    primary
}

fn matches_boundary<V: NormalizedInput>(
    normalized: &V,
    span: ByteSpan,
    pattern_type: WildcardPatternType,
) -> bool {
    let text = normalized.as_str();
    let left_ok = span.start == 0
        || text[..span.start]
            .chars()
            .next_back()
            .is_some_and(|character| !V::is_token_character(character));
    let right_ok = span.end == text.len()
        || text[span.end..]
            .chars()
            .next()
            .is_some_and(|character| !V::is_token_character(character));

    match pattern_type {
        WildcardPatternType::ExactWord | WildcardPatternType::Phrase => left_ok && right_ok,
        WildcardPatternType::Prefix => left_ok,
        WildcardPatternType::Suffix => right_ok,
        WildcardPatternType::Contains => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition(
        rule_id: u128,
        pattern_id: u128,
        pattern: &str,
        pattern_type: WildcardPatternType,
    ) -> PatternDefinition {
        PatternDefinition::new(
            Uuid::from_u128(rule_id),
            Uuid::from_u128(pattern_id),
            pattern,
            pattern_type,
        )
    }

    #[test]
    fn wildcard_boundaries_are_directional() {
        let matcher = CompiledMatcher::compile([
            definition(1, 11, "bad", WildcardPatternType::ExactWord),
            definition(2, 12, "pre", WildcardPatternType::Prefix),
            definition(3, 13, "fix", WildcardPatternType::Suffix),
            definition(4, 14, "ad", WildcardPatternType::Contains),
        ])
        .unwrap();

        // `*ad*` is unanchored, so it also matches inside the exact word "bad".
        assert_eq!(
            matcher.matched_rule_ids("bad prelude suffix"),
            vec![
                Uuid::from_u128(1),
                Uuid::from_u128(4),
                Uuid::from_u128(2),
                Uuid::from_u128(3)
            ]
        );
        // `pre*` anchors left and `*fix` anchors right; "prefix" satisfies both.
        assert_eq!(
            matcher.matched_rule_ids("prefix"),
            vec![Uuid::from_u128(2), Uuid::from_u128(3)]
        );
        assert_eq!(matcher.matched_rule_ids("badly"), vec![Uuid::from_u128(4)]);
        assert!(
            !matcher
                .matched_rule_ids("badly")
                .contains(&Uuid::from_u128(1))
        );
    }

    #[test]
    fn phrases_use_external_token_boundaries_and_canonical_separators() {
        let matcher =
            CompiledMatcher::compile([definition(1, 11, "red green", WildcardPatternType::Phrase)])
                .unwrap();

        assert_eq!(
            matcher.matched_rule_ids("a red—\tgreen b"),
            vec![Uuid::from_u128(1)]
        );
        assert!(matcher.matched_rule_ids("xred green").is_empty());
        assert!(matcher.matched_rule_ids("red greenish").is_empty());
    }

    #[test]
    fn duplicate_patterns_trigger_a_rule_once_but_details_are_available() {
        let matcher = CompiledMatcher::compile([
            definition(1, 11, "BAD", WildcardPatternType::ExactWord),
            definition(1, 12, "b\u{200b}ad", WildcardPatternType::ExactWord),
            definition(2, 21, "bad", WildcardPatternType::ExactWord),
        ])
        .unwrap();

        let report = matcher.match_text(
            "bad",
            MatchOptions {
                details: MatchDetails::PatternsAndSpans,
            },
        );
        assert_eq!(report.triggers.len(), 2);
        assert_eq!(report.triggers[0].rule_id, Uuid::from_u128(1));
        assert_eq!(report.triggers[0].matches.len(), 2);
        assert_eq!(report.triggers[1].rule_id, Uuid::from_u128(2));
    }

    #[test]
    fn details_include_exact_original_bytes_after_nfkc_and_invisibles() {
        let matcher =
            CompiledMatcher::compile([definition(1, 11, "fi", WildcardPatternType::ExactWord)])
                .unwrap();
        let report = matcher.match_text(
            "\u{FB01}\u{200b}",
            MatchOptions {
                details: MatchDetails::PatternsAndSpans,
            },
        );
        assert_eq!(
            report.triggers[0].matches[0].original_span,
            ByteSpan { start: 0, end: 3 }
        );
    }

    #[test]
    fn security_view_matches_inserted_punctuation_but_not_whitespace() {
        let matcher =
            CompiledMatcher::compile([definition(1, 11, "wumpus", WildcardPatternType::ExactWord)])
                .unwrap();

        for candidate in [
            "wum.pus",
            "wum-pus",
            "wum_pus",
            "w.u.m.p.u.s",
            "w\u{e002e}u\u{e002e}m\u{e002e}p\u{e002e}u\u{e002e}s",
        ] {
            let report = matcher.match_text(
                candidate,
                MatchOptions {
                    details: MatchDetails::PatternsAndSpans,
                },
            );
            assert_eq!(
                report.rule_ids().collect::<Vec<_>>(),
                vec![Uuid::from_u128(1)]
            );
            assert_eq!(
                report.triggers[0].matches[0].original_span,
                ByteSpan {
                    start: 0,
                    end: candidate.len()
                }
            );
        }

        for candidate in ["wum pus", "wum\tpus", "wum\npus", "wum  pus"] {
            assert!(
                matcher.matched_rule_ids(candidate).is_empty(),
                "{candidate:?}"
            );
        }
    }

    #[test]
    fn security_view_matches_discord_markdown_split_literals() {
        let matcher =
            CompiledMatcher::compile([definition(1, 11, "wumpus", WildcardPatternType::ExactWord)])
                .unwrap();

        for candidate in [
            "wu**m**p**us**",
            "wu__m__p__us__",
            "wu~~m~~p~~us~~",
            "wu||m||p||us||",
            "wu`m`p`us`",
            "wu[m](https://example.com)pus",
        ] {
            let report = matcher.match_text(
                candidate,
                MatchOptions {
                    details: MatchDetails::PatternsAndSpans,
                },
            );
            assert_eq!(
                report.rule_ids().collect::<Vec<_>>(),
                vec![Uuid::from_u128(1)],
                "candidate: {candidate:?}"
            );
            assert_eq!(
                report.triggers[0].matches[0].original_span,
                ByteSpan {
                    start: 0,
                    end: candidate.rfind("us").unwrap() + 2
                }
            );
        }
    }

    #[test]
    fn masked_link_labels_match_across_excluded_destinations() {
        let matcher =
            CompiledMatcher::compile([definition(1, 11, "wumpus", WildcardPatternType::ExactWord)])
                .unwrap();
        let candidate = "wu[m](https://example.com)pus";
        let url_start = candidate.find("https://").unwrap();
        let url_end = candidate[url_start..].find(')').unwrap() + url_start;
        let report = matcher.match_normalized_with_security(
            &NormalizedText::new(candidate),
            Some(&SecurityNormalizedText::new(candidate)),
            &[ByteSpan {
                start: url_start,
                end: url_end,
            }],
            MatchOptions::default(),
        );

        assert_eq!(
            report.rule_ids().collect::<Vec<_>>(),
            vec![Uuid::from_u128(1)]
        );
    }

    #[test]
    fn security_view_preserves_wildcard_directions_and_excludes_phrases() {
        let matcher = CompiledMatcher::compile([
            definition(1, 11, "word*", WildcardPatternType::Prefix),
            definition(2, 12, "*tail", WildcardPatternType::Suffix),
            definition(3, 13, "*term*", WildcardPatternType::Contains),
            definition(4, 14, "red green", WildcardPatternType::Phrase),
        ])
        .unwrap();

        assert!(
            matcher
                .matched_rule_ids("w.o.r.ding")
                .contains(&Uuid::from_u128(1))
        );
        assert!(
            matcher
                .matched_rule_ids("my.t.a.i.l")
                .contains(&Uuid::from_u128(2))
        );
        assert!(
            matcher
                .matched_rule_ids("long.t.e.r.m.value")
                .contains(&Uuid::from_u128(3))
        );
        assert!(
            !matcher
                .matched_rule_ids("xwording")
                .contains(&Uuid::from_u128(1))
        );
        assert!(
            !matcher
                .matched_rule_ids("tailx")
                .contains(&Uuid::from_u128(2))
        );

        let security_only = matcher.match_security_normalized(
            &SecurityNormalizedText::new("red green"),
            &[],
            MatchOptions::default(),
        );
        assert!(security_only.is_empty());
        assert!(
            matcher
                .matched_rule_ids("red green")
                .contains(&Uuid::from_u128(4))
        );
    }

    #[test]
    fn security_view_is_conservative_about_scripts_and_accents() {
        let matcher = CompiledMatcher::compile([
            definition(1, 11, "paypal", WildcardPatternType::ExactWord),
            definition(2, 12, "cafe", WildcardPatternType::ExactWord),
            definition(3, 13, "inter", WildcardPatternType::ExactWord),
        ])
        .unwrap();

        assert!(
            matcher
                .matched_rule_ids("раypal")
                .contains(&Uuid::from_u128(1))
        );
        assert!(
            matcher
                .matched_rule_ids("pαypal")
                .contains(&Uuid::from_u128(1))
        );
        for candidate in ["раура", "ραυπαλ", "مرحبا", "नमस्ते", "你好", "café"]
        {
            assert!(
                matcher.matched_rule_ids(candidate).is_empty(),
                "{candidate:?}"
            );
        }
        assert!(
            matcher
                .matched_rule_ids("inter")
                .contains(&Uuid::from_u128(3))
        );
        assert!(
            !matcher
                .matched_rule_ids("İnter")
                .contains(&Uuid::from_u128(3))
        );
    }

    #[test]
    fn canonical_unicode_casefolding_and_combining_boundaries_are_native() {
        let matcher = CompiledMatcher::compile([
            definition(1, 11, "ss", WildcardPatternType::ExactWord),
            definition(2, 12, "σσσσ", WildcardPatternType::ExactWord),
            definition(3, 13, "i", WildcardPatternType::ExactWord),
            definition(4, 14, "i\u{307}", WildcardPatternType::ExactWord),
        ])
        .unwrap();

        for candidate in ["ß", "ẞ"] {
            assert_eq!(
                matcher.matched_rule_ids(candidate),
                vec![Uuid::from_u128(1)],
                "{candidate:?}"
            );
        }
        assert_eq!(matcher.matched_rule_ids("ΣσςΣ"), vec![Uuid::from_u128(2)]);
        assert_eq!(matcher.matched_rule_ids("İ"), vec![Uuid::from_u128(4)]);
        assert!(!matcher.matched_rule_ids("İ").contains(&Uuid::from_u128(3)));
    }

    #[test]
    fn canonical_and_security_matches_dedupe_but_authored_ids_are_retained() {
        let matcher = CompiledMatcher::compile([
            definition(1, 11, "wumpus", WildcardPatternType::ExactWord),
            definition(1, 12, "WUMPUS", WildcardPatternType::ExactWord),
        ])
        .unwrap();

        let canonical = matcher.match_text(
            "wumpus",
            MatchOptions {
                details: MatchDetails::PatternsAndSpans,
            },
        );
        assert_eq!(canonical.triggers.len(), 1);
        assert_eq!(canonical.triggers[0].matches.len(), 2);

        let obfuscated = matcher.match_text(
            "wum.pus",
            MatchOptions {
                details: MatchDetails::PatternsAndSpans,
            },
        );
        assert_eq!(obfuscated.triggers.len(), 1);
        assert_eq!(obfuscated.triggers[0].matches.len(), 2);
        assert_eq!(
            obfuscated.triggers[0]
                .matches
                .iter()
                .map(|item| item.pattern_id)
                .collect::<Vec<_>>(),
            vec![Uuid::from_u128(11), Uuid::from_u128(12)]
        );
    }

    #[test]
    fn auxiliary_matches_can_be_excluded_by_original_structural_ranges() {
        let matcher = CompiledMatcher::compile([definition(
            1,
            11,
            "examplecom",
            WildcardPatternType::ExactWord,
        )])
        .unwrap();
        let candidate = "example.com";
        let canonical = NormalizedText::new(candidate);
        let security = SecurityNormalizedText::new(candidate);
        let report = matcher.match_normalized_with_security(
            &canonical,
            Some(&security),
            &[ByteSpan {
                start: 0,
                end: candidate.len(),
            }],
            MatchOptions::default(),
        );
        assert!(report.is_empty());
    }
}
