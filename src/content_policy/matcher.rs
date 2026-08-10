//! Aho-Corasick-backed native content-policy matcher.

use std::collections::HashMap;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use uuid::Uuid;

use super::model::{RulePattern, WildcardPatternType};
use super::normalization::{NormalizedText, normalize_pattern};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchDetails {
    None,
    PatternsAndSpans,
}

impl Default for MatchDetails {
    fn default() -> Self {
        Self::None
    }
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

/// Immutable matcher suitable for sharing between evaluator calls.
#[derive(Debug)]
pub struct CompiledMatcher {
    automaton: AhoCorasick,
    patterns: Vec<CompiledPattern>,
}

impl CompiledMatcher {
    pub fn compile<I>(definitions: I) -> Result<Self, MatcherBuildError>
    where
        I: IntoIterator<Item = PatternDefinition>,
    {
        let mut patterns = Vec::<CompiledPattern>::new();
        let mut indexes = HashMap::<(String, WildcardPatternType), usize>::new();

        for definition in definitions {
            let text = normalize_pattern(&definition.pattern);
            if text.is_empty() {
                return Err(MatcherBuildError::EmptyPattern {
                    rule_id: definition.rule_id,
                    pattern_id: definition.pattern_id,
                });
            }

            let key = (text.clone(), definition.pattern_type);
            let target = PatternTarget {
                rule_id: definition.rule_id,
                pattern_id: definition.pattern_id,
            };
            if let Some(&index) = indexes.get(&key) {
                patterns[index].targets.push(target);
            } else {
                let index = patterns.len();
                indexes.insert(key, index);
                patterns.push(CompiledPattern {
                    text,
                    pattern_type: definition.pattern_type,
                    targets: vec![target],
                });
            }
        }

        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .build(patterns.iter().map(|pattern| pattern.text.as_bytes()))
            .map_err(|error| MatcherBuildError::Automaton(error.to_string()))?;

        Ok(Self {
            automaton,
            patterns,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    pub fn match_text(&self, input: &str, options: MatchOptions) -> MatchReport {
        let normalized = NormalizedText::new(input);
        self.match_normalized(&normalized, options)
    }

    /// Match a surface that was normalized once by shared message analysis.
    /// Callers may run a cheap no-detail pass and only request attribution
    /// details after a rule that needs spans or logging actually triggers.
    pub fn match_normalized(
        &self,
        normalized: &NormalizedText,
        options: MatchOptions,
    ) -> MatchReport {
        let mut triggers = Vec::new();
        let mut trigger_indexes = HashMap::<Uuid, usize>::new();

        // One overlapping Aho-Corasick pass finds every compiled pattern,
        // including shorter patterns nested inside longer ones. Boundary
        // checks happen only for those candidate spans.
        for found in self
            .automaton
            .find_overlapping_iter(normalized.as_str().as_bytes())
        {
            let pattern = &self.patterns[found.pattern().as_usize()];
            let span = ByteSpan {
                start: found.start(),
                end: found.end(),
            };
            if !matches_boundary(normalized.as_str(), span, pattern.pattern_type) {
                continue;
            }
            let Some(original_span) = normalized.span_for(span) else {
                continue;
            };

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

fn matches_boundary(text: &str, span: ByteSpan, pattern_type: WildcardPatternType) -> bool {
    let left_ok = span.start == 0
        || text[..span.start]
            .chars()
            .next_back()
            .is_some_and(|character| !is_token_character(character));
    let right_ok = span.end == text.len()
        || text[span.end..]
            .chars()
            .next()
            .is_some_and(|character| !is_token_character(character));

    match pattern_type {
        WildcardPatternType::ExactWord | WildcardPatternType::Phrase => left_ok && right_ok,
        WildcardPatternType::Prefix => left_ok,
        WildcardPatternType::Suffix => right_ok,
        WildcardPatternType::Contains => true,
    }
}

fn is_token_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
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

        assert_eq!(
            matcher.matched_rule_ids("bad prelude suffix"),
            vec![Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3)]
        );
        assert_eq!(matcher.matched_rule_ids("prefix"), vec![Uuid::from_u128(3)]);
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
}
