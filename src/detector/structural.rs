use super::Detector;
use ahash::AHashSet;
use regex::RegexSet;
use std::collections::HashSet;

pub struct StructuralDetector {
    literal_segments: AHashSet<String>,
    pattern_set: RegexSet,
}

impl StructuralDetector {
    /// Creates a new `StructuralDetector` from literal and pattern segments.
    ///
    /// # Panics
    ///
    /// Panics if the compiled `RegexSet` from pattern segments is invalid.
    /// This should never happen since patterns are simple anchored regexes.
    #[must_use]
    pub fn new(literal_segments: HashSet<String>, pattern_segments: &[String]) -> Self {
        let literal_segments: AHashSet<_> = literal_segments.into_iter().collect();
        let patterns: Vec<String> = if pattern_segments.is_empty() {
            vec![r"^v\d+$".into()]
        } else {
            pattern_segments.iter().map(|p| format!("^{p}$")).collect()
        };

        Self {
            literal_segments,
            pattern_set: RegexSet::new(&patterns).unwrap(),
        }
    }
}

impl Detector for StructuralDetector {
    fn name(&self) -> &'static str {
        "structural"
    }

    fn detect(&self, segment: &str) -> Option<&'static str> {
        if self.literal_segments.contains(segment) {
            return Some("__STRUCTURAL__");
        }

        if self.pattern_set.is_match(segment) {
            return Some("__STRUCTURAL__");
        }

        None
    }

    fn priority(&self) -> u8 {
        0
    }
}
