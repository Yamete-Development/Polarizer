//! Shared, deterministic content analysis for native policy evaluation.
//!
//! Analysis is intentionally independent of delivery destinations. It performs
//! each surface normalization once and extracts links without DNS, HTTP, or a
//! regular-expression engine.

use std::{collections::BTreeMap, sync::Arc};

use super::{
    delivery::Presentation,
    model::Surface,
    normalization::{NormalizedText, SecurityNormalizedText, SurfaceSpan},
    resolver::ByteSpan,
};

/// The immutable surface views shared by every native policy profile for one
/// presentation. Canonical text remains the source of truth; security text is
/// an auxiliary view used only for eligible literal patterns.
#[derive(Debug, Clone, Copy)]
pub struct AnalyzedSurfaces<'a> {
    pub normalized: &'a BTreeMap<Surface, NormalizedText>,
    pub security: &'a BTreeMap<Surface, SecurityNormalizedText>,
    pub security_excluded_spans: &'a [ByteSpan],
}

impl<'a> AnalyzedSurfaces<'a> {
    pub fn iter(&self) -> std::collections::btree_map::Iter<'a, Surface, NormalizedText> {
        self.normalized.iter()
    }
}

/// Immutable normalized content and original-coordinate link metadata shared
/// by all policy profiles evaluating one presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzedContent {
    /// Only non-empty surfaces are present. `URL_DOMAIN` contains extracted
    /// domains, while every other entry contains its presentation surface.
    pub normalized: BTreeMap<Surface, NormalizedText>,
    /// Auxiliary security views for non-URL surfaces. These retain source-byte
    /// provenance and keep ordinary whitespace as a hard separator.
    pub security: BTreeMap<Surface, SecurityNormalizedText>,
    /// Message ranges where punctuation is structural (URLs and email-like
    /// addresses), so auxiliary matching cannot compact across them.
    pub security_excluded_spans: Arc<[ByteSpan]>,
    /// Full original URL spans, including scheme and path, for STRIP_LINK.
    pub url_spans: Arc<[ByteSpan]>,
}

impl AnalyzedContent {
    pub fn from_presentation(presentation: &Presentation) -> Self {
        Self::new(presentation)
    }

    pub fn new(presentation: &Presentation) -> Self {
        let (url_spans, domain_spans) = extract_urls(&presentation.message_content);
        let mut security_excluded_spans = url_spans.clone();
        security_excluded_spans.extend(extract_email_spans(&presentation.message_content));
        security_excluded_spans.extend(extract_dotted_initial_spans(&presentation.message_content));
        security_excluded_spans.sort_unstable();
        security_excluded_spans = merge_spans(security_excluded_spans);
        let mut normalized = BTreeMap::new();
        let mut security = BTreeMap::new();

        for surface in Surface::ALL {
            if surface == Surface::UrlDomain {
                if !domain_spans.is_empty() {
                    normalized.insert(
                        surface,
                        NormalizedText::from_original_spans(
                            &presentation.message_content,
                            &domain_spans,
                        ),
                    );
                }
                continue;
            }

            let value = presentation.surface(surface);
            if !value.is_empty() {
                normalized.insert(surface, NormalizedText::new(value));
                security.insert(surface, SecurityNormalizedText::new(value));
            }
        }

        Self {
            normalized,
            security,
            security_excluded_spans: Arc::from(security_excluded_spans),
            url_spans: Arc::from(url_spans),
        }
    }

    pub fn surface(&self, surface: Surface) -> Option<&NormalizedText> {
        self.normalized.get(&surface)
    }

    pub fn normalized_surfaces(&self) -> AnalyzedSurfaces<'_> {
        AnalyzedSurfaces {
            normalized: &self.normalized,
            security: &self.security,
            security_excluded_spans: &self.security_excluded_spans,
        }
    }

    pub fn canonical_surfaces(&self) -> &BTreeMap<Surface, NormalizedText> {
        &self.normalized
    }

    pub fn url_spans(&self) -> &[ByteSpan] {
        &self.url_spans
    }
}

fn extract_email_spans(input: &str) -> Vec<ByteSpan> {
    let bytes = input.as_bytes();
    let mut spans = Vec::new();

    for (at, byte) in bytes.iter().enumerate() {
        if *byte != b'@' || at == 0 || at + 1 >= bytes.len() {
            continue;
        }

        let mut local_start = at;
        while local_start > 0 && is_email_local_byte(bytes[local_start - 1]) {
            local_start -= 1;
        }
        if local_start == at || !is_start_boundary(input, local_start) {
            continue;
        }

        let mut domain_end = at + 1;
        while domain_end < bytes.len() && is_email_domain_byte(bytes[domain_end]) {
            domain_end += 1;
        }
        if !valid_email_domain(&bytes[at + 1..domain_end]) {
            continue;
        }

        let end = trim_terminal_punctuation(bytes, local_start, domain_end);
        if end > at + 1 {
            spans.push(ByteSpan {
                start: local_start,
                end,
            });
        }
    }

    spans
}

fn is_email_local_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'.' | b'!'
                | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        )
}

fn is_email_domain_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')
}

fn valid_email_domain(domain: &[u8]) -> bool {
    let mut labels = domain.split(|byte| *byte == b'.');
    let Some(first) = labels.next() else {
        return false;
    };
    if first.is_empty() {
        return false;
    }

    let mut label_count = 1;
    let mut last = first;
    for label in labels {
        if label.is_empty()
            || label[0] == b'-'
            || label[label.len() - 1] == b'-'
            || !label.iter().all(u8::is_ascii_alphanumeric)
        {
            return false;
        }
        label_count += 1;
        last = label;
    }

    label_count >= 2
        && last.len() >= 2
        && last.iter().all(u8::is_ascii_alphabetic)
        && first
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn extract_dotted_initial_spans(input: &str) -> Vec<ByteSpan> {
    let bytes = input.as_bytes();
    let mut spans = Vec::new();
    let mut cursor = 0;

    while cursor < bytes.len() {
        if !bytes[cursor].is_ascii_alphabetic()
            || !input.is_char_boundary(cursor)
            || !is_start_boundary(input, cursor)
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

        if initials >= 4 {
            spans.push(ByteSpan { start, end });
            cursor = end;
        } else {
            cursor = start + 1;
        }
    }

    spans
}

fn merge_spans(mut spans: Vec<ByteSpan>) -> Vec<ByteSpan> {
    let mut merged: Vec<ByteSpan> = Vec::with_capacity(spans.len());
    for span in spans.drain(..) {
        if let Some(last) = merged.last_mut()
            && span.start <= last.end
        {
            last.end = last.end.max(span.end);
        } else {
            merged.push(span);
        }
    }
    merged
}

#[derive(Debug, Clone, Copy)]
struct UrlCandidate {
    url: ByteSpan,
    domain: SurfaceSpan,
}

fn extract_urls(input: &str) -> (Vec<ByteSpan>, Vec<SurfaceSpan>) {
    let bytes = input.as_bytes();
    let mut candidates = Vec::new();
    let mut cursor = 0;

    while cursor < bytes.len() {
        if !input.is_char_boundary(cursor) || !is_start_boundary(input, cursor) {
            cursor += 1;
            continue;
        }

        let candidate = parse_http_url(bytes, cursor).or_else(|| parse_domain_url(bytes, cursor));
        let Some(candidate) = candidate else {
            cursor += 1;
            continue;
        };

        candidates.push(candidate);
        cursor = candidate.url.end;
    }

    (
        candidates.iter().map(|candidate| candidate.url).collect(),
        candidates
            .iter()
            .map(|candidate| candidate.domain)
            .collect(),
    )
}

fn parse_http_url(bytes: &[u8], start: usize) -> Option<UrlCandidate> {
    let scheme_len = if starts_with_ignore_ascii_case(bytes, start, b"https://") {
        8
    } else if starts_with_ignore_ascii_case(bytes, start, b"http://") {
        7
    } else {
        return None;
    };

    let token_end = token_end(bytes, start);
    let authority_start = start + scheme_len;
    let authority_end = bytes[authority_start..token_end]
        .iter()
        .position(|byte| matches!(byte, b'/' | b'?' | b'#'))
        .map_or(token_end, |offset| authority_start + offset);
    let authority_end = trim_terminal_punctuation(bytes, authority_start, authority_end);
    let host_end = bytes[authority_start..authority_end]
        .iter()
        .position(|byte| *byte == b':')
        .map_or(authority_end, |offset| authority_start + offset);

    let domain_end = parse_domain_at(bytes, authority_start, host_end)?;
    if domain_end != host_end || !valid_port(bytes, host_end, authority_end) {
        return None;
    }

    let url_end = trim_terminal_punctuation(bytes, start, token_end);
    (url_end > start).then_some(UrlCandidate {
        url: ByteSpan {
            start,
            end: url_end,
        },
        domain: domain_span(
            bytes,
            ByteSpan {
                start: authority_start,
                end: domain_end,
            },
        ),
    })
}

fn parse_domain_url(bytes: &[u8], start: usize) -> Option<UrlCandidate> {
    let token_end = token_end(bytes, start);
    let domain_end = parse_domain_at(bytes, start, token_end)?;
    if !valid_domain_tail(bytes, domain_end, token_end) {
        return None;
    }
    let url_end = trim_terminal_punctuation(bytes, start, token_end);
    (url_end > start).then_some(UrlCandidate {
        url: ByteSpan {
            start,
            end: url_end,
        },
        domain: domain_span(
            bytes,
            ByteSpan {
                start,
                end: domain_end,
            },
        ),
    })
}

/// Keep every domain byte attributed to the URL_DOMAIN surface, but leave a
/// leading `www.` out of the matchable text: it is a routing label, not part
/// of the administrator-visible site name.
fn domain_span(bytes: &[u8], domain: ByteSpan) -> SurfaceSpan {
    let text_start = domain.start + 4;
    let strips_www = starts_with_ignore_ascii_case(bytes, domain.start, b"www.")
        && text_start < domain.end
        && bytes[text_start..domain.end].contains(&b'.');
    SurfaceSpan {
        attributed: domain,
        text: if strips_www {
            ByteSpan {
                start: text_start,
                end: domain.end,
            }
        } else {
            domain
        },
    }
}

fn parse_domain_at(bytes: &[u8], start: usize, limit: usize) -> Option<usize> {
    let mut cursor = start;
    let mut labels = 0;
    let mut last_label_start;
    let mut last_label_end;

    loop {
        let label_start = cursor;
        if cursor >= limit || !is_ascii_alphanumeric(bytes[cursor]) {
            return None;
        }
        cursor += 1;
        while cursor < limit && (is_ascii_alphanumeric(bytes[cursor]) || bytes[cursor] == b'-') {
            cursor += 1;
        }
        let label_end = cursor;
        if bytes[label_end - 1] == b'-' {
            return None;
        }
        labels += 1;
        last_label_start = label_start;
        last_label_end = label_end;

        if cursor >= limit
            || bytes[cursor] != b'.'
            || cursor + 1 >= limit
            || !is_ascii_alphanumeric(bytes[cursor + 1])
        {
            break;
        }
        cursor += 1;
    }

    if labels < 2
        || last_label_end - last_label_start < 2
        || !bytes[last_label_start..last_label_end]
            .iter()
            .all(|byte| byte.is_ascii_alphabetic())
    {
        return None;
    }
    Some(cursor)
}

fn valid_domain_tail(bytes: &[u8], start: usize, limit: usize) -> bool {
    if start == limit {
        return true;
    }
    if matches!(bytes[start], b'/' | b'?' | b'#') {
        return true;
    }
    bytes[start..limit].iter().all(|byte| {
        matches!(
            *byte,
            b'.' | b',' | b'!' | b'?' | b';' | b':' | b'\'' | b'"' | b'`' | b')' | b']' | b'}'
        )
    })
}

fn valid_port(bytes: &[u8], port_start: usize, authority_end: usize) -> bool {
    if port_start == authority_end {
        return true;
    }
    bytes[port_start + 1..authority_end]
        .iter()
        .all(u8::is_ascii_digit)
}

fn token_end(bytes: &[u8], start: usize) -> usize {
    let mut cursor = start;
    while cursor < bytes.len()
        && !bytes[cursor].is_ascii_whitespace()
        && !matches!(bytes[cursor], b'<' | b'>' | b'`')
    {
        cursor += 1;
    }
    cursor
}

fn trim_terminal_punctuation(bytes: &[u8], start: usize, mut end: usize) -> usize {
    while end > start
        && matches!(
            bytes[end - 1],
            b'.' | b',' | b'!' | b'?' | b';' | b':' | b'\'' | b'"' | b'`' | b')' | b']' | b'}'
        )
    {
        end -= 1;
    }
    end
}

fn is_start_boundary(input: &str, start: usize) -> bool {
    input[..start].chars().next_back().is_none_or(|character| {
        !character.is_alphanumeric() && !matches!(character, '_' | '-' | '@' | '.')
    })
}

fn starts_with_ignore_ascii_case(bytes: &[u8], start: usize, needle: &[u8]) -> bool {
    bytes.get(start..start + needle.len()).is_some_and(|value| {
        value
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn is_ascii_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn presentation(message: &str) -> Presentation {
        Presentation {
            message_content: Arc::from(message),
            ..Presentation::default()
        }
    }

    #[test]
    fn extracts_multiple_urls_and_domains_in_source_order() {
        let content = AnalyzedContent::new(&presentation(
            "see https://one.test/a, then www.two.example/path.",
        ));

        assert_eq!(
            content.url_spans(),
            &[
                ByteSpan { start: 4, end: 22 },
                ByteSpan { start: 29, end: 49 }
            ]
        );
        assert_eq!(
            content.surface(Surface::UrlDomain).unwrap().as_str(),
            "one test two example"
        );
    }

    #[test]
    fn trims_terminal_punctuation_without_trimming_url_content() {
        let message = "(https://example.test/path), www.other.test!";
        let content = AnalyzedContent::new(&presentation(message));

        assert_eq!(
            content.url_spans(),
            &[
                ByteSpan { start: 1, end: 26 },
                ByteSpan { start: 29, end: 43 },
            ]
        );
        for span in content.url_spans() {
            assert!(message.is_char_boundary(span.start));
            assert!(message.is_char_boundary(span.end));
            assert!(!matches!(
                message.as_bytes()[span.end - 1],
                b'.' | b',' | b'!' | b')'
            ));
        }
    }

    #[test]
    fn url_spans_use_utf8_byte_offsets() {
        let message = "é https://example.test 😊";
        let content = AnalyzedContent::new(&presentation(message));
        let span = content.url_spans()[0];

        assert_eq!(&message[span.start..span.end], "https://example.test");
        assert_eq!(span, ByteSpan { start: 3, end: 23 });
    }

    #[test]
    fn domain_matches_map_back_to_each_original_domain() {
        let message = "go https://one.test and www.two.example";
        let content = AnalyzedContent::new(&presentation(message));
        let domains = content.surface(Surface::UrlDomain).unwrap();

        let one = domains.as_str().find("one test").unwrap();
        let two = domains.as_str().find("two example").unwrap();
        assert_eq!(
            domains.original_span(one..one + "one test".len()),
            Some(ByteSpan { start: 11, end: 19 })
        );
        assert_eq!(
            domains.original_span(two..two + "two example".len()),
            Some(ByteSpan { start: 24, end: 39 })
        );
    }

    #[test]
    fn security_views_cover_literal_surfaces_but_not_url_domains() {
        let analyzed = AnalyzedContent::new(&Presentation {
            message_content: Arc::from("wum.pus https://example.com name@example.com A.B.C.D."),
            display_name: Arc::from("wum-pus"),
            username: Arc::from("wum_pus"),
            server_name: Arc::from("w.u.m.p.u.s"),
            hub_name: Arc::from("wum\u{200b}pus"),
            ..Presentation::default()
        });

        for surface in [
            Surface::MessageContent,
            Surface::DisplayName,
            Surface::Username,
            Surface::ServerName,
            Surface::HubName,
        ] {
            assert!(analyzed.security.contains_key(&surface), "{surface:?}");
        }
        assert!(!analyzed.security.contains_key(&Surface::UrlDomain));
        assert_eq!(analyzed.security[&Surface::DisplayName].as_str(), "wumpus");
        assert!(analyzed.security_excluded_spans.iter().any(|span| {
            &"wum.pus https://example.com name@example.com A.B.C.D."[span.start..span.end]
                == "https://example.com"
        }));
        assert!(analyzed.security_excluded_spans.iter().any(|span| {
            &"wum.pus https://example.com name@example.com A.B.C.D."[span.start..span.end]
                == "name@example.com"
        }));
    }

    #[test]
    fn security_exclusions_cover_all_extracted_domains_and_dotted_initial_case() {
        let message = "example.wumpus A.B.C.D. a.b.c.d.";
        let analyzed = AnalyzedContent::new(&presentation(message));

        for excluded in ["example.wumpus", "A.B.C.D", "a.b.c.d"] {
            assert!(
                analyzed
                    .security_excluded_spans
                    .iter()
                    .any(|span| &message[span.start..span.end] == excluded),
                "missing exclusion for {excluded:?}"
            );
        }
        assert_eq!(
            analyzed.surface(Surface::UrlDomain).unwrap().as_str(),
            "example wumpus"
        );
    }
}
