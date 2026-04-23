use std::collections::HashSet;

use super::parse::ParsedUrl;
use crate::config::Config;
use crate::detector::{Detector, EntropyDetector, RegexDetector, StructuralDetector};

pub struct Fingerprinter {
    detectors: Vec<Box<dyn Detector>>,
    always_normalize: HashSet<String>,
    never_normalize: HashSet<String>,
}

impl Fingerprinter {
    #[must_use]
    pub fn new(config: &Config) -> Self {
        let detectors = Self::build_detectors(config);
        Self {
            detectors,
            always_normalize: config.always_normalize_keys(),
            never_normalize: config.never_normalize_keys(),
        }
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn fingerprint(&self, parsed: &ParsedUrl) -> String {
        let mut buffer = String::with_capacity(256);
        self.fingerprint_into(parsed, &mut buffer);
        buffer
    }

    pub fn fingerprint_into(&self, parsed: &ParsedUrl, buffer: &mut String) {
        buffer.clear();
        if !parsed.scheme.is_empty() {
            buffer.push_str(&parsed.scheme);
            buffer.push_str("://");
            buffer.push_str(&parsed.host);
            if let Some(port) = parsed.port {
                buffer.push(':');
                buffer.push_str(&port.to_string());
            }
        }

        for segment in parsed.path.split('/').filter(|s| !s.is_empty()) {
            buffer.push('/');
            let normalized = normalize_segment(segment, &self.detectors);
            buffer.push_str(&normalized);
        }

        if let Some(query) = &parsed.query {
            let normalized_query = self.normalize_query(query);
            if !normalized_query.is_empty() {
                buffer.push('?');
                buffer.push_str(&normalized_query);
            }
        }
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn fingerprint_with_strip_query(&self, parsed: &ParsedUrl) -> String {
        let mut buffer = String::with_capacity(256);
        self.fingerprint_with_strip_query_into(parsed, &mut buffer);
        buffer
    }

    pub fn fingerprint_with_strip_query_into(&self, parsed: &ParsedUrl, buffer: &mut String) {
        self.fingerprint_into(parsed, buffer);
        if let Some(q_pos) = buffer.find('?') {
            buffer.truncate(q_pos);
        }
    }

    fn build_detectors(config: &Config) -> Vec<Box<dyn Detector>> {
        let mut detectors: Vec<Box<dyn Detector>> = Vec::new();

        detectors.push(Box::new(StructuralDetector::new(
            config.literal_segments(),
            &config.structural.pattern_segments,
        )));
        detectors.push(Box::new(RegexDetector::new(&config.general.patterns)));

        if config.general.patterns.iter().any(|p| p == "entropy") {
            detectors.push(Box::new(EntropyDetector::new(
                config.general.min_segment_len,
                config.general.entropy_threshold,
            )));
        }

        detectors.sort_by_key(|d| d.priority());
        detectors
    }

    fn normalize_query(&self, query: &str) -> String {
        let pairs: Vec<_> = url::form_urlencoded::parse(query.as_bytes()).collect();
        let mut normalized_pairs: Vec<(String, String)> = Vec::with_capacity(pairs.len());

        for (key, value) in pairs {
            let key_lower = key.to_lowercase();

            if self.always_normalize.contains(&key_lower) {
                normalized_pairs.push((key_lower, "{dynamic}".into()));
            } else if self.never_normalize.contains(&key_lower) {
                normalized_pairs.push((key_lower, value.into_owned()));
            } else {
                let normalized_value = normalize_query_value(&value, &self.detectors);
                normalized_pairs.push((key_lower, normalized_value));
            }
        }

        // Sort by (key, value) lexicographically — equivalent to BTreeMap grouping
        // + per-key value sorting, but with zero heap allocations for tree nodes.
        normalized_pairs.sort_unstable();

        let mut result = String::new();
        let mut first = true;
        for (key, value) in &normalized_pairs {
            if !first {
                result.push('&');
            }
            first = false;
            result.push_str(&url::form_urlencoded::byte_serialize(key.as_bytes()).collect::<String>());
            result.push('=');
            result.push_str(&url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>());
        }

        result
    }
}

fn normalize_segment(segment: &str, detectors: &[Box<dyn Detector>]) -> String {
    if let Some(cache_busted) = normalize_cache_bust(segment) {
        return cache_busted;
    }

    for detector in detectors {
        if let Some(placeholder) = detector.detect(segment) {
            if placeholder == "__STRUCTURAL__" {
                return segment.to_string();
            }
            return placeholder.to_string();
        }
    }

    segment.to_string()
}

fn normalize_cache_bust(segment: &str) -> Option<String> {
    // Handle patterns like file.HASH.ext, file.HASH.min.ext, file.HASH.prod.ext
    // Walk dots from right to left, skipping known suffixes (min, prod, dev, etc.)
    // and common locale codes (en, pt, fr, etc.) used in CDN asset paths.
    const KNOWN_SUFFIXES: &[&str] = &[
        "min", "prod", "dev", "map", "gz", "br", "zst",
        "en", "pt", "fr", "de", "es", "ja", "zh", "ru", "ko", "it",
    ];

    let dot_positions: Vec<usize> = segment
        .match_indices('.')
        .map(|(i, _)| i)
        .collect();

    if dot_positions.len() < 2 {
        return None;
    }

    // Extension is after the last dot
    let ext = &segment[dot_positions[dot_positions.len() - 1]..];
    if ext.len() <= 1 {
        return None;
    }

    // Walk backwards from the segment just before the last dot.
    // Segment index i is the text between dot_positions[i-1] and dot_positions[i].
    let mut idx = dot_positions.len() - 1;
    loop {
        let seg_start = if idx > 0 { dot_positions[idx - 1] + 1 } else { 0 };
        let seg_end = dot_positions[idx];
        let candidate = &segment[seg_start..seg_end];

        if candidate.is_empty() {
            return None;
        }

        if KNOWN_SUFFIXES.contains(&candidate) {
            if idx == 1 {
                return None;
            }
            idx -= 1;
            continue;
        }

        if looks_like_hash(candidate) {
            let name = &segment[..seg_start];
            if name.is_empty() {
                return None;
            }
            let suffix_and_ext = &segment[seg_end..];
            return Some(format!("{name}{{hash}}{suffix_and_ext}"));
        }

        return None;
    }
}

#[allow(clippy::cast_precision_loss)]
fn looks_like_hash(s: &str) -> bool {
    if s.len() < 8 {
        return false;
    }
    // Require at least one alphabetic character to avoid matching
    // pure numeric IDs (SKUs, product IDs, etc.) as hashes.
    // Real build hashes are hex-mixed (letters + digits).
    let has_alpha = s.chars().any(|c| c.is_ascii_alphabetic());
    if !has_alpha {
        return false;
    }
    let hex_chars = s.chars().filter(char::is_ascii_hexdigit).count();
    let ratio = hex_chars as f64 / s.len() as f64;
    ratio > 0.9
}

fn normalize_query_value(value: &str, detectors: &[Box<dyn Detector>]) -> String {
    for detector in detectors {
        if let Some(placeholder) = detector.detect(value) {
            if placeholder == "__STRUCTURAL__" {
                continue;
            }
            return placeholder.to_string();
        }
    }
    value.to_string()
}
