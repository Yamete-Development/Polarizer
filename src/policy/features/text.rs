use std::collections::HashSet;

use aho_corasick::AhoCorasick;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unicode_normalization::{UnicodeNormalization, char::is_combining_mark};

use super::{FeatureProvider, ProviderCategory, ProviderError, ProviderOutput};
use crate::content_policy::normalization::{
    ByteSpan, NormalizedText as CanonicalNormalizedText, SecurityNormalizedText,
    is_security_pattern_eligible, normalize_pattern, security_normalize_pattern,
};
use crate::policy::model::Action;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedText {
    pub text: String,
    pub spans: Vec<OriginalSpan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginalSpan {
    pub original_start_character: u32,
    pub original_end_character: u32,
}

pub struct NormalizedTextProvider;

#[async_trait]
impl FeatureProvider for NormalizedTextProvider {
    fn name(&self) -> &str {
        "text.normalized"
    }
    fn version(&self) -> &str {
        "nfkc-lower-v1"
    }

    async fn resolve(
        &self,
        action: &Action,
        _: &serde_json::Value,
    ) -> Result<ProviderOutput, ProviderError> {
        let content = action
            .attributes
            .get("content")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let normalized = normalize_with_spans(content);
        Ok(ProviderOutput {
            value: serde_json::to_value(normalized).map_err(|_| ProviderError::Internal)?,
            cache_hit: false,
            input_hash: Some(crate::policy::runtime::sha256_hex(content.as_bytes())),
        })
    }

    fn redact_for_trace(&self, output: &ProviderOutput) -> serde_json::Value {
        let normalized = serde_json::from_value::<NormalizedText>(output.value.clone()).ok();
        let text = normalized
            .as_ref()
            .map(|value| value.text.as_str())
            .unwrap_or("");
        serde_json::json!({
            "normalized_text_sha256": crate::policy::runtime::sha256_hex(text.as_bytes()),
            "normalized_character_count": text.chars().count(),
            "span_count": normalized.as_ref().map_or(0, |value| value.spans.len()),
        })
    }
}

pub fn normalize_with_spans(input: &str) -> NormalizedText {
    let mut text = String::new();
    let mut spans = Vec::new();
    for (original_index, character) in input.chars().enumerate() {
        let expanded: String = character
            .to_string()
            .nfkc()
            .flat_map(char::to_lowercase)
            .collect();
        for normalized in expanded.chars() {
            text.push(normalized);
            spans.push(OriginalSpan {
                original_start_character: original_index as u32,
                original_end_character: original_index as u32 + 1,
            });
        }
    }
    NormalizedText { text, spans }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AutomodConfiguration {
    #[serde(default)]
    pub literals: Vec<AutomodPattern>,
    #[serde(default)]
    pub regexes: Vec<AutomodPattern>,
    #[serde(default)]
    pub whitelist_pattern_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AutomodPattern {
    pub id: String,
    pub pattern: String,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
}

fn default_confidence() -> f64 {
    1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomodMatch {
    pub pattern_id: String,
    pub normalized_start_character: u32,
    pub normalized_end_character: u32,
    pub original_start_character: u32,
    pub original_end_character: u32,
    pub confidence: f64,
}

pub struct AutomodMatchProvider;

#[async_trait]
impl FeatureProvider for AutomodMatchProvider {
    fn name(&self) -> &str {
        "automod.matches"
    }
    fn version(&self) -> &str {
        "automod-v2"
    }

    fn category(&self) -> ProviderCategory {
        ProviderCategory::Check
    }

    async fn resolve(
        &self,
        action: &Action,
        configuration: &serde_json::Value,
    ) -> Result<ProviderOutput, ProviderError> {
        let config: AutomodConfiguration = serde_json::from_value(configuration.clone())
            .map_err(|error| ProviderError::InvalidInput(error.to_string()))?;
        let content = action
            .attributes
            .get("content")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let normalized = normalize_with_spans(content);
        let mut matches = literal_matches(content, &config)?;

        for pattern in &config.regexes {
            if config.whitelist_pattern_ids.contains(&pattern.id) {
                continue;
            }
            let matcher = regex::Regex::new(&pattern.pattern).map_err(|_| {
                ProviderError::InvalidInput(format!("invalid regex pattern {}", pattern.id))
            })?;
            for found in matcher.find_iter(&normalized.text) {
                if let Some(item) = mapped_match(
                    &normalized,
                    &pattern.id,
                    found.start(),
                    found.end(),
                    pattern.confidence,
                ) {
                    matches.push(item);
                }
            }
        }
        Ok(ProviderOutput {
            value: serde_json::to_value(matches).map_err(|_| ProviderError::Internal)?,
            cache_hit: false,
            input_hash: Some(crate::policy::runtime::sha256_hex(content.as_bytes())),
        })
    }

    fn redact_for_trace(&self, output: &ProviderOutput) -> serde_json::Value {
        serde_json::json!({
            "match_count": output.value.as_array().map_or(0, Vec::len),
        })
    }
}

fn literal_matches(
    content: &str,
    config: &AutomodConfiguration,
) -> Result<Vec<AutomodMatch>, ProviderError> {
    if config.literals.is_empty() {
        return Ok(Vec::new());
    }

    let canonical = CanonicalNormalizedText::new(content);
    let canonical_patterns: Vec<_> = config
        .literals
        .iter()
        .map(|item| normalize_pattern(&item.pattern))
        .collect();
    let canonical_matcher = AhoCorasick::new(&canonical_patterns)
        .map_err(|_| ProviderError::InvalidInput("invalid literal patterns".into()))?;
    let mut matches = Vec::new();

    for found in canonical_matcher.find_iter(canonical.as_str()) {
        let pattern = &config.literals[found.pattern().as_usize()];
        if config.whitelist_pattern_ids.contains(&pattern.id) {
            continue;
        }
        if let Some(item) = mapped_view_match(
            content,
            canonical.as_str(),
            canonical.span_for(ByteSpan {
                start: found.start(),
                end: found.end(),
            }),
            &pattern.id,
            found.start(),
            found.end(),
            pattern.confidence,
        ) {
            matches.push(item);
        }
    }

    let security_patterns: Vec<_> = config
        .literals
        .iter()
        .enumerate()
        .filter(|(_, pattern)| {
            is_security_pattern_eligible(&pattern.pattern)
                && !config.whitelist_pattern_ids.contains(&pattern.id)
        })
        .map(|(index, pattern)| (index, security_normalize_pattern(&pattern.pattern)))
        .collect();

    if !security_patterns.is_empty() {
        let security_pattern_strings: Vec<_> = security_patterns
            .iter()
            .map(|(_, pattern)| pattern.as_str())
            .collect();
        let security_matcher = AhoCorasick::new(&security_pattern_strings)
            .map_err(|_| ProviderError::InvalidInput("invalid literal patterns".into()))?;
        let security = SecurityNormalizedText::new(content);
        let structural_spans = auxiliary_structural_spans(content);

        for found in security_matcher.find_iter(security.as_str()) {
            let (pattern_index, _) = security_patterns[found.pattern().as_usize()];
            let pattern = &config.literals[pattern_index];
            let normalized_span = ByteSpan {
                start: found.start(),
                end: found.end(),
            };
            let original_span = security.span_for(normalized_span);
            if structural_spans
                .iter()
                .any(|structural| security.span_is_within_original(normalized_span, *structural))
            {
                continue;
            }
            if let Some(item) = mapped_view_match(
                content,
                security.as_str(),
                original_span,
                &pattern.id,
                found.start(),
                found.end(),
                pattern.confidence,
            ) {
                matches.push(item);
            }
        }
    }

    Ok(deduplicate_literal_matches(matches))
}

fn auxiliary_structural_spans(input: &str) -> Vec<ByteSpan> {
    let bytes = input.as_bytes();
    let mut spans = Vec::new();
    let mut cursor = 0;

    while cursor < bytes.len() {
        if starts_with_ignore_ascii_case(bytes, cursor, b"http://")
            || starts_with_ignore_ascii_case(bytes, cursor, b"https://")
        {
            let end = structural_token_end(bytes, cursor);
            spans.push(ByteSpan { start: cursor, end });
            cursor = end;
            continue;
        }

        if bytes[cursor].is_ascii_alphanumeric()
            && (cursor == 0 || !is_domain_byte(bytes[cursor - 1]))
        {
            let start = cursor;
            while cursor < bytes.len() && is_domain_byte(bytes[cursor]) {
                cursor += 1;
            }
            if is_structural_domain(&bytes[start..cursor]) {
                spans.push(ByteSpan { start, end: cursor });
            }
            continue;
        }

        cursor += 1;
    }

    spans.extend(dotted_initial_spans(input));
    spans.sort_unstable();
    merge_byte_spans(spans)
}

fn is_structural_domain(candidate: &[u8]) -> bool {
    let labels = candidate.split(|byte| *byte == b'.').collect::<Vec<_>>();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label[0] == b'-'
                || label[label.len() - 1] == b'-'
                || !label
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
    {
        return false;
    }

    let first = labels[0];
    let suffix = labels[labels.len() - 1];
    suffix.len() >= 2
        && suffix.iter().all(u8::is_ascii_alphabetic)
        && (is_likely_domain_suffix(suffix)
            || first.eq_ignore_ascii_case(b"example")
            || first.eq_ignore_ascii_case(b"www"))
}

fn is_likely_domain_suffix(suffix: &[u8]) -> bool {
    [
        b"ai".as_slice(),
        b"app",
        b"biz",
        b"co",
        b"com",
        b"dev",
        b"edu",
        b"example",
        b"gov",
        b"info",
        b"io",
        b"invalid",
        b"local",
        b"mil",
        b"net",
        b"org",
        b"test",
        b"uk",
        b"xyz",
    ]
    .iter()
    .any(|known| suffix.eq_ignore_ascii_case(known))
}

fn dotted_initial_spans(input: &str) -> Vec<ByteSpan> {
    let bytes = input.as_bytes();
    let mut spans = Vec::new();
    let mut cursor = 0;

    while cursor < bytes.len() {
        if !bytes[cursor].is_ascii_alphabetic()
            || (cursor > 0
                && (bytes[cursor - 1].is_ascii_alphanumeric()
                    || matches!(bytes[cursor - 1], b'_' | b'.')))
        {
            cursor += 1;
            continue;
        }

        let start = cursor;
        let mut initials = 1;
        let mut end = cursor + 1;
        while end + 1 < bytes.len() && bytes[end] == b'.' && bytes[end + 1].is_ascii_alphabetic() {
            initials += 1;
            end += 2;
        }

        let at_end_boundary =
            end == bytes.len() || !(bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_');
        if initials == 4 && at_end_boundary {
            if end < bytes.len() && bytes[end] == b'.' {
                end += 1;
            }
            spans.push(ByteSpan { start, end });
            cursor = end;
        } else {
            cursor = start + 1;
        }
    }

    spans
}

fn merge_byte_spans(spans: Vec<ByteSpan>) -> Vec<ByteSpan> {
    let mut merged: Vec<ByteSpan> = Vec::with_capacity(spans.len());
    for span in spans {
        if let Some(previous) = merged.last_mut()
            && span.start <= previous.end
        {
            previous.end = previous.end.max(span.end);
        } else {
            merged.push(span);
        }
    }
    merged
}

fn is_domain_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')
}

fn structural_token_end(bytes: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < bytes.len()
        && !bytes[end].is_ascii_whitespace()
        && !matches!(bytes[end], b'<' | b'>' | b'`')
    {
        end += 1;
    }
    while end > start
        && matches!(
            bytes[end - 1],
            b'.' | b',' | b'!' | b'?' | b';' | b':' | b'\'' | b'"' | b')' | b']' | b'}'
        )
    {
        end -= 1;
    }
    end
}

fn starts_with_ignore_ascii_case(bytes: &[u8], start: usize, needle: &[u8]) -> bool {
    bytes.get(start..start + needle.len()).is_some_and(|value| {
        value
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn deduplicate_literal_matches(matches: Vec<AutomodMatch>) -> Vec<AutomodMatch> {
    let mut seen = HashSet::new();
    matches
        .into_iter()
        .filter(|item| {
            seen.insert((
                item.pattern_id.clone(),
                item.normalized_start_character,
                item.normalized_end_character,
                item.original_start_character,
                item.original_end_character,
            ))
        })
        .collect()
}

fn mapped_view_match(
    content: &str,
    view: &str,
    original_span: Option<ByteSpan>,
    id: &str,
    byte_start: usize,
    byte_end: usize,
    confidence: f64,
) -> Option<AutomodMatch> {
    let (normalized_start, normalized_end) = character_range(view, byte_start, byte_end)?;
    if adjacent_combining_mark(view, byte_start, byte_end) {
        return None;
    }
    let original_span = original_span?;
    let (original_start, original_end) =
        character_range(content, original_span.start, original_span.end)?;
    Some(AutomodMatch {
        pattern_id: id.to_owned(),
        normalized_start_character: normalized_start as u32,
        normalized_end_character: normalized_end as u32,
        original_start_character: original_start as u32,
        original_end_character: original_end as u32,
        confidence,
    })
}

fn adjacent_combining_mark(view: &str, byte_start: usize, byte_end: usize) -> bool {
    (byte_start > 0
        && view[..byte_start]
            .chars()
            .next_back()
            .is_some_and(is_combining_mark))
        || (byte_end < view.len()
            && view[byte_end..]
                .chars()
                .next()
                .is_some_and(is_combining_mark))
}

fn character_range(text: &str, byte_start: usize, byte_end: usize) -> Option<(usize, usize)> {
    if byte_start >= byte_end
        || byte_end > text.len()
        || !text.is_char_boundary(byte_start)
        || !text.is_char_boundary(byte_end)
    {
        return None;
    }
    Some((
        text[..byte_start].chars().count(),
        text[..byte_end].chars().count(),
    ))
}

fn mapped_match(
    normalized: &NormalizedText,
    id: &str,
    byte_start: usize,
    byte_end: usize,
    confidence: f64,
) -> Option<AutomodMatch> {
    let start = normalized.text[..byte_start].chars().count();
    let end = normalized.text[..byte_end].chars().count();
    if start >= end {
        return None;
    }
    let first = normalized.spans.get(start)?;
    let last = normalized.spans.get(end - 1)?;
    Some(AutomodMatch {
        pattern_id: id.to_owned(),
        normalized_start_character: start as u32,
        normalized_end_character: end as u32,
        original_start_character: first.original_start_character,
        original_end_character: last.original_end_character,
        confidence,
    })
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::policy::model::{DataHandlingClass, Product, Scope, ScopeType, Subject};

    fn action(content: &str) -> Action {
        Action {
            id: Uuid::now_v7(),
            action_type: "hub.message.created".into(),
            schema_version: 1,
            scope: Scope {
                scope_type: ScopeType::Hub,
                id: "hub-1".into(),
                product: Some(Product::Hub),
            },
            subject: Subject::default(),
            occurred_at: Utc::now(),
            attributes: serde_json::json!({"content": content}),
            data_handling: DataHandlingClass::Sensitive,
            prism_payload: None,
        }
    }

    fn configuration(
        literals: &[(&str, &str)],
        regexes: &[(&str, &str)],
        whitelist_pattern_ids: &[&str],
    ) -> serde_json::Value {
        serde_json::json!({
            "literals": literals
                .iter()
                .map(|(id, pattern)| serde_json::json!({"id": id, "pattern": pattern}))
                .collect::<Vec<_>>(),
            "regexes": regexes
                .iter()
                .map(|(id, pattern)| serde_json::json!({"id": id, "pattern": pattern}))
                .collect::<Vec<_>>(),
            "whitelist_pattern_ids": whitelist_pattern_ids,
        })
    }

    async fn matches_for(
        content: &str,
        literals: &[(&str, &str)],
        regexes: &[(&str, &str)],
        whitelist_pattern_ids: &[&str],
    ) -> Result<Vec<AutomodMatch>, ProviderError> {
        let output = AutomodMatchProvider
            .resolve(
                &action(content),
                &configuration(literals, regexes, whitelist_pattern_ids),
            )
            .await?;
        serde_json::from_value(output.value).map_err(|_| ProviderError::Internal)
    }

    #[test]
    fn normalization_keeps_character_spans() {
        let result = normalize_with_spans("Ａß");
        assert_eq!(result.text, "aß");
        assert_eq!(result.spans[0].original_start_character, 0);
        assert_eq!(result.spans[1].original_start_character, 1);
    }

    #[tokio::test]
    async fn literals_normalize_nfkc_and_full_casefold_symmetrically() {
        for candidate in ["ß", "ẞ", "ss", "ＳＳ"] {
            let matches = matches_for(candidate, &[("sharp-s", "ss")], &[], &[])
                .await
                .unwrap();
            assert_eq!(matches.len(), 1, "candidate: {candidate}");
        }

        let matches = matches_for("xﬁy", &[("ligature", "fi")], &[], &[])
            .await
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].normalized_start_character, 1);
        assert_eq!(matches[0].normalized_end_character, 3);
        assert_eq!(matches[0].original_start_character, 1);
        assert_eq!(matches[0].original_end_character, 2);

        let sigma = matches_for("ΟΣ ος", &[("sigma", "οσ")], &[], &[])
            .await
            .unwrap();
        assert_eq!(sigma.len(), 2);

        assert!(
            matches_for("İ", &[("plain-i", "i")], &[], &[])
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            matches_for("İ", &[("dotted-i", "i\u{307}")], &[], &[])
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn literals_match_inserted_punctuation_and_controls_but_not_whitespace() {
        for candidate in ["wum.pus", "wum-pus", "wum_pus", "w.u.m.p.u.s"] {
            let matches = matches_for(candidate, &[("wumpus", "wumpus")], &[], &[])
                .await
                .unwrap();
            assert_eq!(matches.len(), 1, "candidate: {candidate}");
            assert_eq!(matches[0].normalized_start_character, 0);
            assert_eq!(matches[0].normalized_end_character, 6);
            assert_eq!(matches[0].original_start_character, 0);
            assert_eq!(
                matches[0].original_end_character,
                candidate.chars().count() as u32
            );
        }

        for candidate in ["wum pus", "wum\t pus", "wum\npus", "wum  pus", "wum/pus"] {
            assert!(
                matches_for(candidate, &[("wumpus", "wumpus")], &[], &[])
                    .await
                    .unwrap()
                    .is_empty(),
                "candidate: {candidate}"
            );
        }

        for control in [
            '\u{200b}',  // zero-width space
            '\u{2060}',  // word joiner
            '\u{feff}',  // BOM
            '\u{00ad}',  // soft hyphen
            '\u{202e}',  // bidi override
            '\u{e002e}', // tag full stop
        ] {
            let candidate = format!("wum{control}pus");
            let matches = matches_for(&candidate, &[("wumpus", "wumpus")], &[], &[])
                .await
                .unwrap();
            assert_eq!(matches.len(), 1, "control: U+{:04X}", control as u32);
            assert_eq!(matches[0].original_start_character, 0);
            assert_eq!(
                matches[0].original_end_character,
                candidate.chars().count() as u32
            );
        }
    }

    #[tokio::test]
    async fn literals_match_discord_markdown_split_words() {
        for candidate in [
            "wu**m**p**us**",
            "wu__m__p__us__",
            "wu~~m~~p~~us~~",
            "wu||m||p||us||",
            "wu`m`p`us`",
            "wu[m](https://example.com)pus",
        ] {
            let matches = matches_for(candidate, &[("wumpus", "wumpus")], &[], &[])
                .await
                .unwrap();
            assert_eq!(matches.len(), 1, "candidate: {candidate:?}");
            assert_eq!(matches[0].original_start_character, 0);
            let rendered_end = candidate.rfind("us").unwrap() + 2;
            assert_eq!(
                matches[0].original_end_character,
                candidate[..rendered_end].chars().count() as u32
            );
        }
    }

    #[tokio::test]
    async fn auxiliary_literals_skip_structural_dots_only() {
        for (candidate, literal) in [
            ("example.com", "examplecom"),
            ("example.wumpus", "examplewumpus"),
            ("name@example.com", "examplecom"),
            ("A.B.C.D", "abcd"),
            ("a.b.c.d", "abcd"),
            ("v1.2.3", "v123"),
            ("1.2.3.4", "1234"),
        ] {
            let matches = matches_for(candidate, &[("structural", literal)], &[], &[])
                .await
                .unwrap();
            assert!(
                matches.is_empty(),
                "candidate: {candidate}, literal: {literal}"
            );
        }

        let nearby = matches_for(
            "visit example.com then wum.pus",
            &[("obfuscated", "wumpus")],
            &[],
            &[],
        )
        .await
        .unwrap();
        assert_eq!(nearby.len(), 1);
        assert_eq!(nearby[0].pattern_id, "obfuscated");
        assert_eq!(nearby[0].original_start_character, 23);
        assert_eq!(nearby[0].original_end_character, 30);

        // Authored punctuation remains canonical literal behavior. Structural
        // exclusion applies only to the auxiliary compacted representation.
        let canonical = matches_for(
            "example.com",
            &[("authored-domain", "example.com")],
            &[],
            &[],
        )
        .await
        .unwrap();
        assert_eq!(canonical.len(), 1);
        assert_eq!(canonical[0].pattern_id, "authored-domain");

        let canonical_substring = matches_for(
            "example.wumpus",
            &[("canonical-substring", "wumpus")],
            &[],
            &[],
        )
        .await
        .unwrap();
        assert_eq!(canonical_substring.len(), 1);
        assert_eq!(canonical_substring[0].pattern_id, "canonical-substring");
    }

    #[tokio::test]
    async fn literals_use_conservative_mixed_script_matching() {
        for candidate in ["раypal", "pαypal"] {
            let matches = matches_for(candidate, &[("paypal", "paypal")], &[], &[])
                .await
                .unwrap();
            assert_eq!(matches.len(), 1, "candidate: {candidate}");
        }

        for candidate in ["раура", "ραυπαλ", "مرحبا", "कक्षा", "漢字", "café"]
        {
            let matches = matches_for(candidate, &[("paypal", "paypal")], &[], &[])
                .await
                .unwrap();
            assert!(matches.is_empty(), "candidate: {candidate}");
        }

        let accent = matches_for("cafe\u{301}", &[("accented", "café")], &[], &[])
            .await
            .unwrap();
        assert_eq!(accent.len(), 1);
        assert_eq!(accent[0].original_start_character, 0);
        assert_eq!(accent[0].original_end_character, 5);

        let unaccented = matches_for("café", &[("unaccented", "cafe")], &[], &[])
            .await
            .unwrap();
        assert!(unaccented.is_empty());
    }

    #[tokio::test]
    async fn literal_matches_keep_character_spans_for_multibyte_source_ranges() {
        let expanded = matches_for("éxßy", &[("sharp-s", "ss")], &[], &[])
            .await
            .unwrap();
        assert_eq!(expanded.len(), 1);
        assert_eq!(expanded[0].normalized_start_character, 2);
        assert_eq!(expanded[0].normalized_end_character, 4);
        assert_eq!(expanded[0].original_start_character, 2);
        assert_eq!(expanded[0].original_end_character, 3);

        let punctuation = matches_for("éwum.pusy", &[("wumpus", "wumpus")], &[], &[])
            .await
            .unwrap();
        assert_eq!(punctuation.len(), 1);
        assert_eq!(punctuation[0].normalized_start_character, 1);
        assert_eq!(punctuation[0].normalized_end_character, 7);
        assert_eq!(punctuation[0].original_start_character, 1);
        assert_eq!(punctuation[0].original_end_character, 8);

        let control = matches_for("éwum\u{200b}pusy", &[("wumpus", "wumpus")], &[], &[])
            .await
            .unwrap();
        assert_eq!(control.len(), 1);
        assert_eq!(control[0].original_start_character, 1);
        assert_eq!(control[0].original_end_character, 8);
    }

    #[tokio::test]
    async fn literals_preserve_whitelists_and_deduplicate_two_views() {
        let matches = matches_for("wumpus", &[("term", "wumpus")], &[], &[])
            .await
            .unwrap();
        assert_eq!(matches.len(), 1);

        let whitelisted = matches_for(
            "wumpus",
            &[("literal-safe", "wumpus")],
            &[("regex-safe", "wumpus")],
            &["literal-safe", "regex-safe"],
        )
        .await
        .unwrap();
        assert!(whitelisted.is_empty());
    }

    #[tokio::test]
    async fn regexes_keep_raw_source_semantics_and_errors() {
        let matches = matches_for("WUM.PUS", &[], &[("raw-regex", r"(?i)wum\.pus")], &[])
            .await
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].original_start_character, 0);
        assert_eq!(matches[0].original_end_character, 7);

        let raw_source = matches_for("Ａ", &[], &[("raw-source", "Ａ")], &[])
            .await
            .unwrap();
        assert!(raw_source.is_empty());

        let invalid_json = AutomodMatchProvider
            .resolve(&action("content"), &serde_json::json!({"literals": "bad"}))
            .await;
        assert!(matches!(invalid_json, Err(ProviderError::InvalidInput(_))));

        let invalid_regex = matches_for("content", &[], &[("bad-regex", "[")], &[]).await;
        assert!(
            matches!(invalid_regex, Err(ProviderError::InvalidInput(error)) if error.contains("bad-regex"))
        );
    }

    #[tokio::test]
    async fn automod_trace_redaction_contains_metadata_only() {
        let output = AutomodMatchProvider
            .resolve(
                &action("wum.pus"),
                &configuration(&[("term", "wumpus")], &[], &[]),
            )
            .await
            .unwrap();
        let trace = AutomodMatchProvider.redact_for_trace(&output);
        let trace_json = serde_json::to_string(&trace).unwrap();
        assert_eq!(trace["match_count"], 1);
        assert!(!trace_json.contains("wum.pus"));
        assert!(!trace_json.contains("wumpus"));
        assert!(!trace_json.contains("normalized"));
        assert!(!trace_json.contains("security"));
    }
}
