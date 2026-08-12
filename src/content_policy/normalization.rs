//! Deterministic text normalization for native content-policy matching.
//!
//! Normalized byte offsets are deliberately kept alongside the normalized
//! text.  A matcher can therefore inspect a cheap canonical representation and
//! still report a span in the administrator-visible input.

use std::{fmt, ops::Range};

use icu_casemap::CaseMapper;
use icu_properties::{
    CodePointSetData,
    props::{DefaultIgnorableCodePoint, Script},
    script::ScriptWithExtensionsBorrowed,
};
use unicode_normalization::{
    UnicodeNormalization,
    char::{canonical_combining_class, compose, decompose_compatible, is_combining_mark},
};

pub use super::resolver::ByteSpan;

/// Bump this whenever canonical or auxiliary security matching semantics
/// change. Compiled policy fingerprints should include this value so a
/// process restart cannot reuse a snapshot compiled with older Unicode data.
pub const NORMALIZATION_SECURITY_VERSION: &str = "unicode17-icu2.2-security-v3";

/// Text after the policy normalization pipeline, with normalized-to-original
/// byte provenance for every emitted UTF-8 scalar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedText {
    text: String,
    spans: Vec<NormalizedCharSpan>,
}

/// One extracted source range: `text` is normalized into the surface, while
/// `attributed` is the full original range the surface reports for it. The two
/// differ when a fragment carries bytes that should not be matchable, such as
/// the `www.` prefix of a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SurfaceSpan {
    pub attributed: ByteSpan,
    pub text: ByteSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NormalizedCharSpan {
    normalized: ByteSpan,
    original: ByteSpan,
}

/// An auxiliary, provenance-preserving view used for conservative obfuscation
/// resistance. Unlike [`NormalizedText`], this view keeps whitespace and
/// ordinary punctuation intact.
#[derive(Clone, PartialEq, Eq)]
pub struct SecurityNormalizedText {
    text: String,
    spans: Vec<NormalizedCharSpan>,
}

impl fmt::Debug for SecurityNormalizedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecurityNormalizedText")
            .field("byte_len", &self.text.len())
            .field("span_count", &self.spans.len())
            .finish_non_exhaustive()
    }
}

impl NormalizedText {
    /// Apply whole-input NFKC followed by default, locale-independent full
    /// Unicode case folding, invisible-format removal, and separator
    /// canonicalization exactly once to `input`.
    pub fn new(input: &str) -> Self {
        Self::from_mapped(canonical_mapped(input))
    }

    /// Normalize selected, non-overlapping source ranges while retaining their
    /// coordinates in `input`. A single mapped space is inserted between
    /// ranges so several extracted surfaces remain independently matchable.
    pub(crate) fn from_original_spans(input: &str, original_spans: &[SurfaceSpan]) -> Self {
        let mut mapped = Vec::new();
        let mut previous: Option<ByteSpan> = None;

        for &surface_span in original_spans {
            let SurfaceSpan { attributed, text } = surface_span;
            if text.start >= text.end
                || attributed.start > text.start
                || attributed.end < text.end
                || attributed.end > input.len()
                || !input.is_char_boundary(attributed.start)
                || !input.is_char_boundary(attributed.end)
                || !input.is_char_boundary(text.start)
                || !input.is_char_boundary(text.end)
            {
                continue;
            }

            if let Some(previous) = previous
                && previous.end < attributed.start
            {
                mapped.push((' ', span(previous.end, attributed.start)));
            }

            let first = mapped.len();
            let fragment = &input[text.start..text.end];
            mapped.extend(
                canonical_mapped(fragment)
                    .into_iter()
                    .map(|(character, original)| {
                        (
                            character,
                            span(original.start + text.start, original.end + text.start),
                        )
                    }),
            );

            // Bytes trimmed from the matchable text still belong to this
            // surface, so they stay inside the reported original span.
            if mapped.len() > first {
                mapped[first].1.start = attributed.start;
                if let Some(last) = mapped.last_mut() {
                    last.1.end = attributed.end;
                }
            }
            previous = Some(attributed);
        }

        Self::from_mapped(mapped)
    }

    fn from_mapped(mapped: Vec<(char, ByteSpan)>) -> Self {
        let mut result = Self {
            text: String::new(),
            spans: Vec::new(),
        };

        let mut pending_separator: Option<ByteSpan> = None;
        for (character, original) in mapped {
            if is_ignored_format(character) {
                continue;
            }

            if !is_joiner(character)
                && (character.is_whitespace() || is_separator_punctuation(character))
            {
                pending_separator = Some(merge_spans(pending_separator, original));
                continue;
            }

            if let Some(separator) = pending_separator.take()
                && !result.text.is_empty()
            {
                result.push(' ', separator);
            }
            result.push(character, original);
        }

        result
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Map a normalized UTF-8 byte range back to the smallest exact source
    /// range containing all source scalars contributing to that range.
    pub fn original_span(&self, normalized: Range<usize>) -> Option<ByteSpan> {
        original_span(&self.text, &self.spans, normalized)
    }

    pub fn span_for(&self, normalized: ByteSpan) -> Option<ByteSpan> {
        self.original_span(normalized.start..normalized.end)
    }

    fn push(&mut self, character: char, original: ByteSpan) {
        let start = self.text.len();
        self.text.push(character);
        self.spans.push(NormalizedCharSpan {
            normalized: span(start, self.text.len()),
            original,
        });
    }
}

impl SecurityNormalizedText {
    /// Build the auxiliary security view. Whitespace and unapproved
    /// punctuation remain visible; only approved separators and contextual
    /// Latin joiners are removed.
    pub fn new(input: &str) -> Self {
        let mapped = security_mapped(input);
        let mut result = Self {
            text: String::new(),
            spans: Vec::new(),
        };
        for (character, original) in mapped {
            result.push(character, original);
        }
        result
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Map a security-view UTF-8 byte range back to its original source span.
    pub fn original_span(&self, normalized: Range<usize>) -> Option<ByteSpan> {
        original_span(&self.text, &self.spans, normalized)
    }

    pub fn span_for(&self, normalized: ByteSpan) -> Option<ByteSpan> {
        self.original_span(normalized.start..normalized.end)
    }

    fn push(&mut self, character: char, original: ByteSpan) {
        let start = self.text.len();
        self.text.push(character);
        self.spans.push(NormalizedCharSpan {
            normalized: span(start, self.text.len()),
            original,
        });
    }
}

/// Normalize a pattern with the same canonicalization as candidate text.
/// Pattern provenance is intentionally discarded because patterns do not come
/// from the evaluated message.
pub fn normalize_pattern(pattern: &str) -> String {
    NormalizedText::new(pattern).text
}

/// Normalize an authored literal for the auxiliary security matcher. The
/// caller must first apply [`is_security_pattern_eligible`]; phrases and URL
/// domains are intentionally outside this view.
pub fn security_normalize_pattern(pattern: &str) -> String {
    SecurityNormalizedText::new(pattern).text
}

/// Return whether an authored literal is safe and useful for the auxiliary
/// single-token security matcher.
///
/// Callers should pass the literal body after parsing wildcard direction, and
/// should exclude phrases and `URL_DOMAIN` patterns. The check deliberately
/// rejects authored digits, whitespace, punctuation, and symbols. A pattern
/// may still contain ordinary Latin letters with accents; those are preserved
/// rather than transliterated by the security view.
pub fn is_security_pattern_eligible(pattern: &str) -> bool {
    if pattern.is_empty()
        || !pattern
            .chars()
            .all(|character| character.is_alphabetic() || is_combining_mark(character))
    {
        return false;
    }

    let canonical = normalize_pattern(pattern);
    let mut alphabetic_count = 0;
    for character in canonical.chars() {
        if is_combining_mark(character) {
            continue;
        }
        if !character.is_alphabetic() || !is_latin_letter(character) {
            return false;
        }
        alphabetic_count += 1;
    }
    alphabetic_count >= 4
}

fn canonical_mapped(input: &str) -> Vec<(char, ByteSpan)> {
    fold_mapped(mapped_nfkc(input))
}

fn fold_mapped(mapped: Vec<(char, ByteSpan)>) -> Vec<(char, ByteSpan)> {
    // ICU full case folding is context-insensitive. Folding each provenance
    // carrying NFKC segment is therefore equivalent to folding the complete
    // NFKC string, while preserving expansion provenance (for example, ß →
    // ss and İ → i + U+0307).
    let case_mapper = CaseMapper::new();
    let mut folded = Vec::new();
    for (character, original) in mapped {
        let scalar = character.to_string();
        let result = case_mapper.fold_string(&scalar);
        folded.extend(result.chars().map(|character| (character, original)));
    }
    folded
}

fn security_mapped(input: &str) -> Vec<(char, ByteSpan)> {
    let folded = fold_mapped(mapped_nfkc(input));
    let visible: Vec<_> = folded
        .into_iter()
        .filter(|(character, _)| !is_ignored_format(*character))
        .collect();

    // Remove default-ignorable code points only when they split a Latin token.
    // This catches joiners, variation selectors, tag characters, and future
    // Unicode additions without destroying legitimate emoji or non-Latin
    // shaping sequences. Adjacency skips combining marks, other ignorables,
    // and approved inserted punctuation to resolve the token base on each
    // side. Thus repeated forms such as `wum.\u{e002e}_pus` reduce
    // deterministically.
    let without_contextual_ignorables: Vec<_> = visible
        .iter()
        .enumerate()
        .filter_map(|(index, &(character, original))| {
            if is_default_ignorable(character)
                && neighboring_character(&visible, index, 1, is_ignorable_neighbor)
                    .is_some_and(is_latin_character)
                && neighboring_character(&visible, index, -1, is_ignorable_neighbor)
                    .is_some_and(is_latin_character)
            {
                None
            } else {
                Some((character, original))
            }
        })
        .collect();

    let mut compacted = Vec::with_capacity(without_contextual_ignorables.len());
    for (index, &(character, original)) in without_contextual_ignorables.iter().enumerate() {
        if is_security_separator(character)
            && neighboring_character(
                &without_contextual_ignorables,
                index,
                1,
                is_security_separator,
            )
            .is_some_and(is_security_letter_or_mark)
            && neighboring_character(
                &without_contextual_ignorables,
                index,
                -1,
                is_security_separator,
            )
            .is_some_and(is_security_letter_or_mark)
        {
            continue;
        }

        compacted.push((character, original));
    }

    map_mixed_script_tokens(compacted)
}

fn neighboring_character(
    text: &[(char, ByteSpan)],
    index: usize,
    direction: isize,
    skip: impl Fn(char) -> bool,
) -> Option<char> {
    let mut cursor = index as isize + direction;
    while cursor >= 0 && (cursor as usize) < text.len() {
        let character = text[cursor as usize].0;
        if skip(character) {
            cursor += direction;
            continue;
        }
        return Some(character);
    }
    None
}

fn map_mixed_script_tokens(mut text: Vec<(char, ByteSpan)>) -> Vec<(char, ByteSpan)> {
    let mut start = 0;
    while start < text.len() {
        if !is_token_component(text[start].0) {
            start += 1;
            continue;
        }

        let mut end = start + 1;
        while end < text.len() && is_token_component(text[end].0) {
            end += 1;
        }

        let has_latin = text[start..end]
            .iter()
            .any(|(character, _)| is_latin_letter(*character));
        let has_mapped_confusable = text[start..end]
            .iter()
            .any(|(character, _)| confusable_mapping(*character).is_some());

        if has_latin && has_mapped_confusable {
            for (character, _) in &mut text[start..end] {
                if let Some(mapped) = confusable_mapping(*character) {
                    *character = mapped;
                }
            }
        }
        start = end;
    }
    text
}

fn confusable_mapping(character: char) -> Option<char> {
    let mapped = match character {
        // Unicode 17 conservative common-shape subset. This is deliberately
        // not a UTS #39 skeleton or a general transliteration table.
        'α' => 'a',
        'β' => 'b',
        'ε' => 'e',
        'ι' => 'i',
        'κ' => 'k',
        'ο' => 'o',
        'ρ' => 'p',
        'τ' => 't',
        'χ' => 'x',
        'ϲ' => 'c',
        'а' => 'a',
        'в' => 'b',
        'с' => 'c',
        'е' => 'e',
        'і' => 'i',
        'к' => 'k',
        'м' => 'm',
        'н' => 'h',
        'о' => 'o',
        'р' => 'p',
        'т' => 't',
        'х' => 'x',
        'у' => 'y',
        'ѕ' => 's',
        'ј' => 'j',
        _ => return None,
    };

    let scripts = ScriptWithExtensionsBorrowed::new();
    (scripts.has_script(character, Script::Greek)
        || scripts.has_script(character, Script::Cyrillic))
    .then_some(mapped)
}

fn is_latin_character(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || (character.is_alphabetic()
            && ScriptWithExtensionsBorrowed::new().has_script(character, Script::Latin))
}

fn is_latin_letter(character: char) -> bool {
    character.is_ascii_alphabetic()
        || (character.is_alphabetic()
            && ScriptWithExtensionsBorrowed::new().has_script(character, Script::Latin))
}

/// Classify characters that continue native matcher tokens. Matcher
/// integration should use this helper so combining marks do not create false
/// word boundaries after canonical normalization.
pub fn is_token_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_' || is_combining_mark(character)
}

fn is_token_component(character: char) -> bool {
    character.is_alphanumeric() || is_combining_mark(character)
}

fn is_security_separator(character: char) -> bool {
    matches!(character, '.' | '-' | '_')
}

fn is_security_letter_or_mark(character: char) -> bool {
    character.is_alphabetic() || is_combining_mark(character)
}

fn is_ignorable_neighbor(character: char) -> bool {
    is_combining_mark(character)
        || is_default_ignorable(character)
        || is_security_separator(character)
}

fn is_joiner(character: char) -> bool {
    matches!(character, '\u{200c}' | '\u{200d}')
}

fn is_default_ignorable(character: char) -> bool {
    CodePointSetData::new::<DefaultIgnorableCodePoint>().contains(character)
}

fn source_chars(input: &str) -> Vec<(char, ByteSpan)> {
    input
        .char_indices()
        .map(|(start, character)| {
            let end = start + character.len_utf8();
            (character, span(start, end))
        })
        .collect()
}

fn mapped_nfkc(input: &str) -> Vec<(char, ByteSpan)> {
    // Implement NFKC as mapped compatibility decomposition, canonical
    // ordering, and canonical composition. Every decomposed scalar initially
    // retains its own source span. Composition unions only the spans of the
    // scalars it actually consumes, so adjacent unchanged marks and letters
    // keep narrow provenance without a whole-input fallback.
    let mut decomposed = Vec::new();
    for (character, original) in source_chars(input) {
        decompose_compatible(character, |decomposed_character| {
            decomposed.push((decomposed_character, original));
        });
    }
    canonical_order_mapped(&mut decomposed);
    let composed = canonical_compose_mapped(decomposed);

    debug_assert_eq!(
        composed
            .iter()
            .map(|(character, _)| *character)
            .collect::<String>(),
        input.nfkc().collect::<String>()
    );
    composed
}

fn canonical_order_mapped(mapped: &mut [(char, ByteSpan)]) {
    let mut pending_start = 0;
    for index in 0..=mapped.len() {
        if index == mapped.len() || canonical_combining_class(mapped[index].0) == 0 {
            mapped[pending_start..index]
                .sort_by_key(|(character, _)| canonical_combining_class(*character));
            pending_start = index.saturating_add(1);
        }
    }
}

fn canonical_compose_mapped(mapped: Vec<(char, ByteSpan)>) -> Vec<(char, ByteSpan)> {
    let mut composed: Vec<(char, ByteSpan)> = Vec::with_capacity(mapped.len());
    let mut starter_index: Option<usize> = None;
    let mut last_combining_class = 0;

    for (character, original) in mapped {
        let combining_class = canonical_combining_class(character);
        if let Some(index) = starter_index
            && (last_combining_class == 0 || last_combining_class < combining_class)
            && let Some(composition) = compose(composed[index].0, character)
        {
            composed[index].0 = composition;
            composed[index].1 = span(
                composed[index].1.start.min(original.start),
                composed[index].1.end.max(original.end),
            );
            continue;
        }

        if combining_class == 0 {
            starter_index = Some(composed.len());
            last_combining_class = 0;
        } else {
            last_combining_class = combining_class;
        }
        composed.push((character, original));
    }

    composed
}

fn merge_spans(first: Option<ByteSpan>, second: ByteSpan) -> ByteSpan {
    match first {
        Some(first) => span(first.start.min(second.start), first.end.max(second.end)),
        None => second,
    }
}

fn original_span(
    text: &str,
    spans: &[NormalizedCharSpan],
    normalized: Range<usize>,
) -> Option<ByteSpan> {
    if normalized.start >= normalized.end
        || normalized.end > text.len()
        || !text.is_char_boundary(normalized.start)
        || !text.is_char_boundary(normalized.end)
    {
        return None;
    }

    let mut original: Option<ByteSpan> = None;
    for entry in spans {
        if entry.normalized.end <= normalized.start {
            continue;
        }
        if entry.normalized.start >= normalized.end {
            break;
        }
        original = Some(merge_spans(original, entry.original));
    }
    original
}

const fn span(start: usize, end: usize) -> ByteSpan {
    ByteSpan { start, end }
}

fn is_ignored_format(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{115f}'
            | '\u{1160}'
            | '\u{17b4}'
            | '\u{17b5}'
            | '\u{180e}'
            | '\u{200b}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
    )
}

fn is_separator_punctuation(character: char) -> bool {
    character.is_ascii_punctuation()
        || matches!(
            character,
            '\u{00a1}'
                | '\u{00ab}'
                | '\u{00b7}'
                | '\u{00bb}'
                | '\u{00bf}'
                | '\u{037e}'
                | '\u{0387}'
                | '\u{055a}'..='\u{055f}'
                | '\u{0589}'
                | '\u{05be}'
                | '\u{05c0}'
                | '\u{05c3}'
                | '\u{05c6}'
                | '\u{0609}'..='\u{060d}'
                | '\u{061b}'
                | '\u{061e}'..='\u{061f}'
                | '\u{066a}'..='\u{066d}'
                | '\u{06d4}'
                | '\u{0700}'..='\u{070d}'
                | '\u{07f7}'..='\u{07f9}'
                | '\u{0964}'..='\u{0965}'
                | '\u{0e4f}'
                | '\u{0f04}'..='\u{0f12}'
                | '\u{104a}'..='\u{104f}'
                | '\u{1360}'..='\u{1368}'
                | '\u{166d}'..='\u{166e}'
                | '\u{16eb}'..='\u{16ed}'
                | '\u{17d4}'..='\u{17d6}'
                | '\u{1800}'..='\u{1805}'
                | '\u{1a1e}'..='\u{1a1f}'
                | '\u{1aa0}'..='\u{1aa6}'
                | '\u{1b4e}'..='\u{1b55}'
                | '\u{1b5a}'..='\u{1b5d}'
                | '\u{1bfc}'..='\u{1bff}'
                | '\u{1c3b}'..='\u{1c3f}'
                | '\u{1c7e}'..='\u{1c7f}'
                | '\u{1cc0}'..='\u{1cc7}'
                | '\u{2000}'..='\u{206f}'
                | '\u{2e00}'..='\u{2e7f}'
                | '\u{3000}'..='\u{303f}'
                | '\u{a874}'..='\u{a877}'
                | '\u{fe10}'..='\u{fe19}'
                | '\u{fe30}'..='\u{fe4f}'
                | '\u{ff01}'..='\u{ff0f}'
                | '\u{ff1a}'..='\u{ff20}'
                | '\u{ff3b}'..='\u{ff40}'
                | '\u{ff5b}'..='\u{ff65}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfkc_lowercase_and_original_span_are_preserved() {
        let text = NormalizedText::new("ＦI\u{FB01} e\u{301}");
        assert_eq!(text.as_str(), "fifi é");
        let start = text.as_str().find("fi").unwrap();
        assert_eq!(text.original_span(start..start + 2), Some(span(0, 4)));
        let accent = text.as_str().find('é').unwrap();
        assert_eq!(
            text.original_span(accent..accent + 'é'.len_utf8()),
            Some(span(8, 11))
        );
    }

    #[test]
    fn invisible_formats_are_removed_and_their_bytes_remain_in_the_span() {
        let text = NormalizedText::new("A\u{200b}B\u{2060}C");
        assert_eq!(text.as_str(), "abc");
        assert_eq!(text.original_span(0..3), Some(span(0, 9)));
    }

    #[test]
    fn punctuation_and_whitespace_collapse_to_mapped_spaces() {
        let text = NormalizedText::new("Foo— \tbar");
        assert_eq!(text.as_str(), "foo bar");
        let space = text.as_str().find(' ').unwrap();
        assert_eq!(text.original_span(space..space + 1), Some(span(3, 8)));
    }

    #[test]
    fn canonical_normalization_uses_full_default_case_folding() {
        assert_eq!(normalize_pattern("ß ẞ Σ σ ς"), "ss ss σ σ σ");
        assert_eq!(normalize_pattern("İ"), "i\u{307}");
        assert_ne!(normalize_pattern("İ"), "i");
        assert_eq!(normalize_pattern("cafe\u{301}"), "café");
        assert_eq!(normalize_pattern("café"), "café");
    }

    #[test]
    fn compatibility_expansions_and_case_fold_expansions_keep_provenance() {
        let decomposed = NormalizedText::new("e\u{301}");
        assert_eq!(decomposed.as_str(), "é");
        assert_eq!(decomposed.original_span(0.."é".len()), Some(span(0, 3)));

        let ligature = NormalizedText::new("ﬁ");
        assert_eq!(ligature.as_str(), "fi");
        assert_eq!(ligature.original_span(0..2), Some(span(0, 3)));

        let fullwidth = NormalizedText::new("ＷＵＭＰＵＳ");
        assert_eq!(fullwidth.as_str(), "wumpus");
        assert_eq!(
            fullwidth.original_span(0..fullwidth.len()),
            Some(span(0, 18))
        );

        let sharp_s = NormalizedText::new("ß");
        assert_eq!(sharp_s.as_str(), "ss");
        assert_eq!(sharp_s.original_span(0..2), Some(span(0, 2)));
    }

    #[test]
    fn mapped_nfkc_keeps_unrelated_output_spans_narrow() {
        let devanagari = NormalizedText::new("XकिY");
        assert_eq!(devanagari.as_str(), "xकिy");
        assert_eq!(devanagari.original_span(0..1), Some(span(0, 1)));
        assert_eq!(devanagari.original_span(1..4), Some(span(1, 4)));
        assert_eq!(devanagari.original_span(4..7), Some(span(4, 7)));
        assert_eq!(devanagari.original_span(7..8), Some(span(7, 8)));

        let latin = NormalizedText::new("Ae\u{301}Z");
        assert_eq!(latin.as_str(), "aéz");
        assert_eq!(latin.original_span(0..1), Some(span(0, 1)));
        assert_eq!(latin.original_span(1..3), Some(span(1, 4)));
        assert_eq!(latin.original_span(3..4), Some(span(4, 5)));

        let reordered = NormalizedText::new("Ae\u{301}\u{323}Z");
        assert_eq!(reordered.as_str(), "aẹ\u{301}z");
        let acute = reordered.as_str().find('\u{301}').unwrap();
        assert_eq!(reordered.original_span(acute..acute + 2), Some(span(2, 4)));
        let final_z = reordered.as_str().find('z').unwrap();
        assert_eq!(
            reordered.original_span(final_z..final_z + 1),
            Some(span(6, 7))
        );
    }

    #[test]
    fn hangul_composition_and_expansions_have_precise_partial_spans() {
        for input in ["X가Y", "XㄱㅏY"] {
            let hangul = NormalizedText::new(input);
            assert_eq!(hangul.as_str(), "x가y");
            assert_eq!(hangul.original_span(0..1), Some(span(0, 1)));
            assert_eq!(hangul.original_span(1..4), Some(span(1, 7)));
            assert_eq!(hangul.original_span(4..5), Some(span(7, 8)));
        }

        let compatibility = NormalizedText::new("XﬁY");
        assert_eq!(compatibility.as_str(), "xfiy");
        assert_eq!(compatibility.original_span(0..1), Some(span(0, 1)));
        assert_eq!(compatibility.original_span(1..2), Some(span(1, 4)));
        assert_eq!(compatibility.original_span(2..3), Some(span(1, 4)));
        assert_eq!(compatibility.original_span(3..4), Some(span(4, 5)));

        let casefold = NormalizedText::new("AßZ");
        assert_eq!(casefold.as_str(), "assz");
        assert_eq!(casefold.original_span(0..1), Some(span(0, 1)));
        assert_eq!(casefold.original_span(1..2), Some(span(1, 3)));
        assert_eq!(casefold.original_span(2..3), Some(span(1, 3)));
        assert_eq!(casefold.original_span(3..4), Some(span(3, 4)));
    }

    #[test]
    fn security_view_compacts_only_approved_inserted_punctuation() {
        for candidate in ["wum.pus", "wum-pus", "wum_pus", "w.u.m.p.u.s"] {
            let text = SecurityNormalizedText::new(candidate);
            assert_eq!(text.as_str(), "wumpus", "candidate: {candidate}");
            assert_eq!(
                text.original_span(0..text.len()),
                Some(span(0, candidate.len()))
            );
        }

        for candidate in [
            "wum pus",
            "wum\tpus",
            "wum\t pus",
            "wum\npus",
            "wum  pus",
            "wum/pus",
        ] {
            assert_eq!(SecurityNormalizedText::new(candidate).as_str(), candidate);
        }

        for numeric in ["1.2", "v1.2.3", "1.2.3.4"] {
            assert_eq!(SecurityNormalizedText::new(numeric).as_str(), numeric);
        }

        for mixed_input in [
            "wum.\u{200b}pus",
            "wum.\u{200d}pus",
            "wum.\u{200c}_pus",
            "wum.-\u{200d}__pus",
        ] {
            let mixed = SecurityNormalizedText::new(mixed_input);
            assert_eq!(mixed.as_str(), "wumpus", "candidate: {mixed_input}");
            assert_eq!(
                mixed.original_span(0..mixed.len()),
                Some(span(0, mixed_input.len()))
            );
        }
    }

    #[test]
    fn security_debug_output_is_redacted() {
        let debug = format!("{:?}", SecurityNormalizedText::new("secret.wumpus"));
        assert!(debug.contains("byte_len"));
        assert!(debug.contains("span_count"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("wumpus"));
    }

    #[test]
    fn security_view_maps_only_mixed_common_confusables() {
        assert_eq!(SecurityNormalizedText::new("раypal").as_str(), "paypal");
        assert_eq!(SecurityNormalizedText::new("pαypal").as_str(), "paypal");
        assert_eq!(SecurityNormalizedText::new("раура").as_str(), "раура");
        assert_eq!(SecurityNormalizedText::new("ραυπαλ").as_str(), "ραυπαλ");
        assert_eq!(SecurityNormalizedText::new("123α").as_str(), "123α");

        for genuine in ["مرحبا", "कक्षा", "漢字", "café"] {
            assert_eq!(SecurityNormalizedText::new(genuine).as_str(), genuine);
        }
    }

    #[test]
    fn high_confidence_controls_are_removed_with_complete_spans() {
        let controls = [
            '\u{00ad}', // soft hyphen
            '\u{200b}', // zero-width space
            '\u{2060}', // word joiner
            '\u{feff}', // byte-order mark
            '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}',
            '\u{2068}', '\u{2069}',
        ];

        for control in controls {
            let candidate = format!("wum{control}pus");
            let canonical = NormalizedText::new(&candidate);
            let security = SecurityNormalizedText::new(&candidate);
            assert_eq!(
                canonical.as_str(),
                "wumpus",
                "control: U+{:04X}",
                control as u32
            );
            assert_eq!(
                security.as_str(),
                "wumpus",
                "control: U+{:04X}",
                control as u32
            );
            assert_eq!(
                canonical.original_span(0..canonical.len()),
                Some(span(0, candidate.len()))
            );
            assert_eq!(
                security.original_span(0..security.len()),
                Some(span(0, candidate.len()))
            );
        }
    }

    #[test]
    fn joiners_and_variation_selectors_are_preserved_in_legitimate_sequences() {
        for sequence in [
            "👩‍👩‍👧‍👦",
            "👩‍💻",
            "👍🏽",
            "🇺🇳",
            "❤️",
            "✈️",
            "ب\u{200c}ت",
            "क्\u{200d}ष",
        ] {
            assert_eq!(NormalizedText::new(sequence).as_str(), sequence);
            assert_eq!(SecurityNormalizedText::new(sequence).as_str(), sequence);
        }

        assert_eq!(
            SecurityNormalizedText::new("wum\u{200d}pus").as_str(),
            "wumpus"
        );
        assert_eq!(
            SecurityNormalizedText::new("wum\u{200c}pus").as_str(),
            "wumpus"
        );
    }

    #[test]
    fn contextual_joiners_resolve_latin_bases_across_combining_marks() {
        assert_eq!(
            SecurityNormalizedText::new("İ\u{200d}x").as_str(),
            "i\u{307}x"
        );
        assert_eq!(
            SecurityNormalizedText::new("q\u{301}\u{200c}x").as_str(),
            "q\u{301}x"
        );
        assert_eq!(
            SecurityNormalizedText::new("q\u{200d}\u{301}x").as_str(),
            "q\u{301}x"
        );

        // Joiner removal must still precede approved punctuation compaction.
        assert_eq!(
            SecurityNormalizedText::new("q\u{301}.\u{200d}_x").as_str(),
            "q\u{301}x"
        );
    }

    #[test]
    fn default_ignorables_inside_latin_tokens_cannot_split_literals() {
        for invisible in ['\u{e002e}', '\u{fe0f}', '\u{e0100}', '\u{180b}'] {
            let candidate =
                format!("w{invisible}u{invisible}m{invisible}p{invisible}u{invisible}s");
            assert_eq!(
                SecurityNormalizedText::new(&candidate).as_str(),
                "wumpus",
                "invisible: U+{:04X}",
                invisible as u32
            );
        }
    }

    #[test]
    fn security_pattern_eligibility_has_one_conservative_boundary() {
        assert!(is_security_pattern_eligible("wumpus"));
        assert!(is_security_pattern_eligible("café"));
        assert!(is_security_pattern_eligible("cafe\u{301}"));
        assert!(!is_security_pattern_eligible("wum"));
        assert!(!is_security_pattern_eligible("wum pus"));
        assert!(!is_security_pattern_eligible("wum-pus"));
        assert!(!is_security_pattern_eligible("wump3"));
        assert!(!is_security_pattern_eligible("1234"));
        assert!(!is_security_pattern_eligible("αβγδ"));
        assert!(!is_security_pattern_eligible("*wumpus"));
        assert_eq!(security_normalize_pattern("wum-pus"), "wumpus");
        assert!(is_token_character('\u{301}'));
        assert!(is_token_character('_'));
        assert!(!is_token_character('-'));
    }
}
