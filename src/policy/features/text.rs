use aho_corasick::AhoCorasick;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use super::{FeatureProvider, ProviderCategory, ProviderError, ProviderOutput};
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

#[derive(Debug, Clone, Serialize)]
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
        let mut matches = Vec::new();

        if !config.literals.is_empty() {
            let patterns: Vec<_> = config
                .literals
                .iter()
                .map(|item| item.pattern.as_str())
                .collect();
            let matcher = AhoCorasick::new(patterns)
                .map_err(|_| ProviderError::InvalidInput("invalid literal patterns".into()))?;
            for found in matcher.find_iter(&normalized.text) {
                let pattern = &config.literals[found.pattern().as_usize()];
                if config.whitelist_pattern_ids.contains(&pattern.id) {
                    continue;
                }
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
    use super::*;

    #[test]
    fn normalization_keeps_character_spans() {
        let result = normalize_with_spans("Ａß");
        assert_eq!(result.text, "aß");
        assert_eq!(result.spans[0].original_start_character, 0);
        assert_eq!(result.spans[1].original_start_character, 1);
    }
}
