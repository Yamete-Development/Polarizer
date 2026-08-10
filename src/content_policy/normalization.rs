//! Deterministic text normalization for native content-policy matching.
//!
//! Normalized byte offsets are deliberately kept alongside the normalized
//! text.  A matcher can therefore inspect a cheap canonical representation and
//! still report a span in the administrator-visible input.

use std::ops::Range;

use unicode_normalization::{UnicodeNormalization, char::is_combining_mark};

pub use super::resolver::ByteSpan;

/// Text after the policy normalization pipeline, with normalized-to-original
/// byte provenance for every emitted UTF-8 scalar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedText {
    text: String,
    spans: Vec<NormalizedCharSpan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NormalizedCharSpan {
    normalized: ByteSpan,
    original: ByteSpan,
}

impl NormalizedText {
    /// Apply NFKC, lowercase, invisible-format removal, and separator
    /// canonicalization exactly once to `input`.
    pub fn new(input: &str) -> Self {
        let source = source_chars(input);

        // Keep the whole-input NFKC result as the canonical source of truth.
        // The per-segment normalization below only supplies provenance.  A
        // segment is a starter and its following combining marks, which are
        // the only source characters that can compose across scalar bounds.
        let nfkc: String = input.nfkc().collect();
        let mut mapped = mapped_nfkc_segments(input, &source);

        // The segmentation mirrors Unicode normalization boundaries for the
        // forms relevant here.  Retain a safe fallback if a future Unicode
        // table introduces a composition crossing one of those boundaries.
        if mapped.iter().map(|(ch, _)| *ch).collect::<String>() != nfkc {
            mapped = nfkc.chars().map(|ch| (ch, span(0, input.len()))).collect();
        }

        Self::from_mapped(mapped)
    }

    /// Normalize selected, non-overlapping source ranges while retaining their
    /// coordinates in `input`. A single mapped space is inserted between
    /// ranges so several extracted surfaces remain independently matchable.
    pub(crate) fn from_original_spans(input: &str, original_spans: &[ByteSpan]) -> Self {
        let mut mapped = Vec::new();
        let mut previous: Option<ByteSpan> = None;

        for &source_span in original_spans {
            if source_span.start >= source_span.end
                || source_span.end > input.len()
                || !input.is_char_boundary(source_span.start)
                || !input.is_char_boundary(source_span.end)
            {
                continue;
            }

            if let Some(previous) = previous
                && previous.end < source_span.start
            {
                mapped.push((' ', span(previous.end, source_span.start)));
            }

            let fragment = &input[source_span.start..source_span.end];
            let source = source_chars(fragment);
            mapped.extend(mapped_nfkc_segments(fragment, &source).into_iter().map(
                |(character, original)| {
                    (
                        character,
                        span(
                            original.start + source_span.start,
                            original.end + source_span.start,
                        ),
                    )
                },
            ));
            previous = Some(source_span);
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
            for lowercase in character.to_lowercase() {
                if is_ignored_format(lowercase) {
                    continue;
                }

                if lowercase.is_whitespace() || is_separator_punctuation(lowercase) {
                    pending_separator = Some(merge_spans(pending_separator, original));
                    continue;
                }

                if let Some(separator) = pending_separator.take()
                    && !result.text.is_empty()
                {
                    result.push(' ', separator);
                }
                result.push(lowercase, original);
            }
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
        if normalized.start >= normalized.end
            || normalized.end > self.text.len()
            || !self.text.is_char_boundary(normalized.start)
            || !self.text.is_char_boundary(normalized.end)
        {
            return None;
        }

        let mut original: Option<ByteSpan> = None;
        for entry in &self.spans {
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

fn source_chars(input: &str) -> Vec<(char, ByteSpan)> {
    input
        .char_indices()
        .map(|(start, character)| {
            let end = start + character.len_utf8();
            (character, span(start, end))
        })
        .collect()
}

fn mapped_nfkc_segments(input: &str, source: &[(char, ByteSpan)]) -> Vec<(char, ByteSpan)> {
    let mut mapped = Vec::new();
    let mut index = 0;
    while index < source.len() {
        let segment_start = index;
        index += 1;
        while index < source.len()
            && (is_combining_mark(source[index].0)
                || (is_hangul_jamo(source[index - 1].0) && is_hangul_jamo(source[index].0)))
        {
            index += 1;
        }
        let segment_end = index;
        let original = span(source[segment_start].1.start, source[segment_end - 1].1.end);
        let text = &input[original.start..original.end];
        mapped.extend(text.nfkc().map(|character| (character, original)));
    }
    mapped
}

fn is_hangul_jamo(character: char) -> bool {
    matches!(
        character,
        '\u{1100}'..='\u{11ff}'
            | '\u{3130}'..='\u{318f}'
            | '\u{a960}'..='\u{a97f}'
            | '\u{d7b0}'..='\u{d7ff}'
    )
}

fn merge_spans(first: Option<ByteSpan>, second: ByteSpan) -> ByteSpan {
    match first {
        Some(first) => span(first.start.min(second.start), first.end.max(second.end)),
        None => second,
    }
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
            | '\u{200b}'..='\u{200f}'
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
}
