use std::{collections::BTreeMap, sync::Arc};

use sha2::{Digest, Sha256};

use super::{
    model::Surface,
    resolver::{ByteSpan, DeliveryEffects},
};

pub const DEFAULT_SAFE_NAME: &str = "InterChat User";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Presentation {
    pub message_content: Arc<str>,
    pub display_name: Arc<str>,
    pub username: Arc<str>,
    pub server_name: Arc<str>,
    pub hub_name: Arc<str>,
    /// Extracted once during shared analysis. These are original message byte
    /// spans and are reused for STRIP_LINK across every destination profile.
    pub url_spans: Arc<[ByteSpan]>,
}

impl Presentation {
    pub fn surface(&self, surface: Surface) -> &str {
        match surface {
            Surface::MessageContent | Surface::UrlDomain => &self.message_content,
            Surface::DisplayName => &self.display_name,
            Surface::Username => &self.username,
            Surface::ServerName => &self.server_name,
            Surface::HubName => &self.hub_name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryVariant {
    pub message_content: Arc<str>,
    pub display_name: Arc<str>,
    pub username: Arc<str>,
    pub server_name: Arc<str>,
    pub hub_name: Arc<str>,
    pub suppress_links: bool,
    pub fingerprint: [u8; 32],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransformationError {
    #[error("transformation span {start}..{end} is outside the source")]
    SpanOutOfBounds { start: usize, end: usize },
    #[error("transformation span {start}..{end} is not on UTF-8 character boundaries")]
    InvalidCharacterBoundary { start: usize, end: usize },
}

/// Materialize one immutable delivery variant. The canonical presentation is
/// never mutated and an unchanged field reuses its existing `Arc<str>`.
pub fn materialize_variant(
    canonical: &Presentation,
    effects: &DeliveryEffects,
) -> Result<DeliveryVariant, TransformationError> {
    debug_assert!(!effects.is_blocked());

    let mut message_spans = effects
        .censor_spans
        .get(&Surface::MessageContent)
        .cloned()
        .unwrap_or_default();
    if effects.strip_links {
        message_spans.extend(canonical.url_spans.iter().copied());
    }
    let message_content = transform_or_reuse(
        &canonical.message_content,
        message_spans,
        effects.strip_links,
        &canonical.url_spans,
    )?;

    let display_name = transformed_name(canonical, effects, Surface::DisplayName)?;
    let username = transformed_name(canonical, effects, Surface::Username)?;
    let server_name = transformed_name(canonical, effects, Surface::ServerName)?;
    let hub_name = transformed_name(canonical, effects, Surface::HubName)?;

    let fingerprint = variant_fingerprint(
        &message_content,
        &display_name,
        &username,
        &server_name,
        &hub_name,
        effects.suppress_links,
    );
    Ok(DeliveryVariant {
        message_content,
        display_name,
        username,
        server_name,
        hub_name,
        suppress_links: effects.suppress_links,
        fingerprint,
    })
}

fn transformed_name(
    canonical: &Presentation,
    effects: &DeliveryEffects,
    surface: Surface,
) -> Result<Arc<str>, TransformationError> {
    if let Some(replacement) = effects.name_replacements.get(&surface) {
        return Ok(Arc::from(replacement.replacement.as_str()));
    }
    let spans = effects
        .censor_spans
        .get(&surface)
        .cloned()
        .unwrap_or_default();
    let original = canonical.surface(surface);
    if spans.is_empty() {
        return Ok(match surface {
            Surface::DisplayName => canonical.display_name.clone(),
            Surface::Username => canonical.username.clone(),
            Surface::ServerName => canonical.server_name.clone(),
            Surface::HubName => canonical.hub_name.clone(),
            Surface::MessageContent | Surface::UrlDomain => unreachable!(),
        });
    }
    Ok(Arc::from(censor_spans(original, &spans)?))
}

fn transform_or_reuse(
    original: &Arc<str>,
    mut censor: Vec<ByteSpan>,
    strip_links: bool,
    url_spans: &[ByteSpan],
) -> Result<Arc<str>, TransformationError> {
    if !strip_links && censor.is_empty() {
        return Ok(original.clone());
    }
    if strip_links {
        // Links are removed, not censored. Split the two transformations and
        // apply from right to left to preserve original byte coordinates.
        validate_spans(original, url_spans)?;
        validate_spans(original, &censor)?;
        censor.retain(|span| !url_spans.iter().any(|url| overlaps(*span, *url)));
        let censored = censor_spans(original, &censor)?;
        let mut value = censored;
        let mut links = url_spans.to_vec();
        links.sort_unstable_by_key(|span| std::cmp::Reverse(span.start));
        // Censoring preserves character count but not byte length. To keep URL
        // byte coordinates reliable, URLs overlapping censorship were removed
        // above and non-ASCII censorship before a URL can still change bytes.
        // Therefore remove URLs from the original first, then remap remaining
        // censorship spans through the removals.
        if !links.is_empty() {
            let (stripped, remapped) = remove_spans_and_remap_censors(original, &links, &censor)?;
            value = censor_spans(&stripped, &remapped)?;
        }
        return Ok(Arc::from(value));
    }
    Ok(Arc::from(censor_spans(original, &censor)?))
}

fn remove_spans_and_remap_censors(
    original: &str,
    removals: &[ByteSpan],
    censors: &[ByteSpan],
) -> Result<(String, Vec<ByteSpan>), TransformationError> {
    let removals = merge_spans(removals.to_vec());
    validate_spans(original, &removals)?;
    let mut output = String::with_capacity(original.len());
    let mut cursor = 0;
    for removal in &removals {
        output.push_str(&original[cursor..removal.start]);
        cursor = removal.end;
    }
    output.push_str(&original[cursor..]);

    let remapped = censors
        .iter()
        .filter_map(|span| {
            if removals.iter().any(|removal| overlaps(*span, *removal)) {
                return None;
            }
            let removed_before_start = removals
                .iter()
                .filter(|removal| removal.end <= span.start)
                .map(|removal| removal.end - removal.start)
                .sum::<usize>();
            let removed_before_end = removals
                .iter()
                .filter(|removal| removal.end <= span.end)
                .map(|removal| removal.end - removal.start)
                .sum::<usize>();
            ByteSpan::new(
                span.start - removed_before_start,
                span.end - removed_before_end,
            )
        })
        .collect();
    Ok((output, remapped))
}

pub fn censor_spans(original: &str, spans: &[ByteSpan]) -> Result<String, TransformationError> {
    let spans = merge_spans(spans.to_vec());
    validate_spans(original, &spans)?;
    let mut output = String::with_capacity(original.len());
    let mut cursor = 0;
    for span in spans {
        output.push_str(&original[cursor..span.start]);
        output.push_str(&censor_fragment(&original[span.start..span.end]));
        cursor = span.end;
    }
    output.push_str(&original[cursor..]);
    Ok(output)
}

fn censor_fragment(fragment: &str) -> String {
    let characters = fragment.chars().collect::<Vec<_>>();
    match characters.as_slice() {
        [] => String::new(),
        [_] => "#".to_owned(),
        [_, _] => "##".to_owned(),
        [first, middle @ .., last] => {
            let mut output = String::with_capacity(fragment.len());
            output.push(*first);
            output.extend(std::iter::repeat_n('#', middle.len()));
            output.push(*last);
            output
        }
    }
}

fn validate_spans(original: &str, spans: &[ByteSpan]) -> Result<(), TransformationError> {
    for span in spans {
        if span.start >= span.end || span.end > original.len() {
            return Err(TransformationError::SpanOutOfBounds {
                start: span.start,
                end: span.end,
            });
        }
        if !original.is_char_boundary(span.start) || !original.is_char_boundary(span.end) {
            return Err(TransformationError::InvalidCharacterBoundary {
                start: span.start,
                end: span.end,
            });
        }
    }
    Ok(())
}

fn merge_spans(mut spans: Vec<ByteSpan>) -> Vec<ByteSpan> {
    spans.sort_unstable();
    let mut output = Vec::<ByteSpan>::with_capacity(spans.len());
    for span in spans {
        if let Some(last) = output.last_mut()
            && span.start <= last.end
        {
            last.end = last.end.max(span.end);
            continue;
        }
        output.push(span);
    }
    output
}

fn overlaps(left: ByteSpan, right: ByteSpan) -> bool {
    left.start < right.end && right.start < left.end
}

fn variant_fingerprint(
    message: &str,
    display_name: &str,
    username: &str,
    server_name: &str,
    hub_name: &str,
    suppress_links: bool,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    for value in [message, display_name, username, server_name, hub_name] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.update([u8::from(suppress_links)]);
    hash.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PolicyProfileKey {
    pub version: u64,
    pub fingerprint: [u8; 32],
}

/// Group destination targets by immutable compiled profile. The expensive
/// server-policy evaluation is then performed once per returned group.
pub fn group_destinations_by_profile<T>(
    destinations: impl IntoIterator<Item = (PolicyProfileKey, T)>,
) -> BTreeMap<PolicyProfileKey, Vec<T>> {
    let mut groups = BTreeMap::new();
    for (profile, destination) in destinations {
        groups
            .entry(profile)
            .or_insert_with(Vec::new)
            .push(destination);
    }
    groups
}

/// Group already-materialized delivery variants so each distinct transformed
/// payload is serialized once and shared by every destination that needs it.
pub fn group_destinations_by_variant<T>(
    destinations: impl IntoIterator<Item = (DeliveryVariant, T)>,
) -> BTreeMap<[u8; 32], (DeliveryVariant, Vec<T>)> {
    let mut groups: BTreeMap<[u8; 32], (DeliveryVariant, Vec<T>)> = BTreeMap::new();
    for (variant, destination) in destinations {
        match groups.entry(variant.fingerprint) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.get_mut().1.push(destination);
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((variant, vec![destination]));
            }
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn censor_output_preserves_edges() {
        assert_eq!(
            censor_spans("a", &[ByteSpan { start: 0, end: 1 }]).unwrap(),
            "#"
        );
        assert_eq!(
            censor_spans("ab", &[ByteSpan { start: 0, end: 2 }]).unwrap(),
            "##"
        );
        assert_eq!(
            censor_spans("abc", &[ByteSpan { start: 0, end: 3 }]).unwrap(),
            "a#c"
        );
        assert_eq!(
            censor_spans("terrible", &[ByteSpan { start: 0, end: 8 }]).unwrap(),
            "t######e"
        );
    }

    #[test]
    fn censor_uses_utf8_byte_spans_without_corrupting_text() {
        assert_eq!(
            censor_spans("xÃ©clair!", &[ByteSpan { start: 1, end: 8 }]).unwrap(),
            "xÃ©####r!"
        );
    }

    #[test]
    fn unchanged_variants_reuse_canonical_arcs() {
        let canonical = Presentation {
            message_content: Arc::from("hello"),
            display_name: Arc::from("name"),
            ..Presentation::default()
        };
        let variant = materialize_variant(&canonical, &DeliveryEffects::default()).unwrap();
        assert!(Arc::ptr_eq(
            &variant.message_content,
            &canonical.message_content
        ));
        assert!(Arc::ptr_eq(&variant.display_name, &canonical.display_name));
    }

    #[test]
    fn identical_variants_share_one_delivery_group() {
        let canonical = Presentation {
            message_content: Arc::from("hello"),
            ..Presentation::default()
        };
        let variant = materialize_variant(&canonical, &DeliveryEffects::default()).unwrap();
        let groups = group_destinations_by_variant([(variant.clone(), "one"), (variant, "two")]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups.into_values().next().unwrap().1, vec!["one", "two"]);
    }

    #[test]
    fn profile_grouping_evaluates_unique_profiles_not_destinations() {
        let shared = PolicyProfileKey {
            version: 1,
            fingerprint: [1; 32],
        };
        let distinct = PolicyProfileKey {
            version: 2,
            fingerprint: [2; 32],
        };
        let groups = group_destinations_by_profile(
            (0..700).map(|index| (if index < 650 { shared } else { distinct }, index)),
        );
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[&shared].len(), 650);
        assert_eq!(groups[&distinct].len(), 50);
    }

    #[test]
    fn strip_link_and_censor_compose_from_original_coordinates() {
        let canonical = Presentation {
            message_content: Arc::from("bad https://example.test awful"),
            url_spans: Arc::from([ByteSpan { start: 4, end: 24 }]),
            ..Presentation::default()
        };
        let effects = DeliveryEffects {
            censor_spans: BTreeMap::from([(
                Surface::MessageContent,
                vec![
                    ByteSpan { start: 0, end: 3 },
                    ByteSpan { start: 25, end: 30 },
                ],
            )]),
            strip_links: true,
            ..DeliveryEffects::default()
        };
        let variant = materialize_variant(&canonical, &effects).unwrap();
        assert_eq!(&*variant.message_content, "b#d  a###l");
    }
}
