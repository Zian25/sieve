use super::Detector;
use regex::RegexSet;
use std::sync::LazyLock;

#[derive(Clone, Copy, PartialEq)]
pub enum PatternKind {
    Uuid,
    Hash,
    NumId,
    TimestampIso,
    Epoch,
    Base64,
    Mongo,
    ShortToken,
    Ulid,
}

impl PatternKind {
    pub fn name(self) -> &'static str {
        match self {
            PatternKind::Uuid => "uuid",
            PatternKind::Hash => "hash",
            PatternKind::NumId => "numid",
            PatternKind::TimestampIso => "timestamp",
            PatternKind::Epoch => "epoch",
            PatternKind::Base64 => "base64",
            PatternKind::Mongo => "mongo",
            PatternKind::ShortToken => "short_token",
            PatternKind::Ulid => "ulid",
        }
    }

    fn placeholder(self) -> &'static str {
        match self {
            PatternKind::Uuid => "{uuid}",
            PatternKind::Hash => "{hash}",
            PatternKind::NumId => "{id}",
            PatternKind::TimestampIso => "{date}",
            PatternKind::Epoch => "{epoch}",
            PatternKind::Base64 => "{token}",
            PatternKind::Mongo => "{mongo}",
            PatternKind::ShortToken => "{slug}",
            PatternKind::Ulid => "{ulid}",
        }
    }

    pub fn regex(self) -> &'static str {
        match self {
            PatternKind::Uuid => r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
            PatternKind::Hash => r"^[0-9a-fA-F]{16,}$",
            PatternKind::NumId => r"^\d{4,}$",
            PatternKind::TimestampIso => r"^\d{4}-\d{2}-\d{2}$",
            PatternKind::Epoch => r"^1\d{9}$",
            PatternKind::Base64 => r"^[A-Za-z0-9+/]{20,}={0,2}$",
            PatternKind::Mongo => r"^[0-9a-fA-F]{24}$",
            PatternKind::ShortToken => r"^[A-Za-z0-9_+\-]{8,19}$",
            PatternKind::Ulid => r"^[0-9A-HJKMNP-TV-Z]{26}$",
        }
    }

    pub const ALL: &'static [Self] = &[
        Self::Uuid, Self::Hash, Self::NumId, Self::TimestampIso,
        Self::Epoch, Self::Base64, Self::Mongo, Self::ShortToken, Self::Ulid,
    ];

    /// All pattern names including "entropy" (which is not a regex pattern
    /// but a detection mode handled separately by EntropyDetector).
    pub fn all_names() -> &'static [&'static str] {
        &[
            "uuid", "hash", "numid", "timestamp", "epoch",
            "base64", "mongo", "short_token", "ulid", "entropy",
        ]
    }
}

static DEFAULT_REGEX_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new(PatternKind::ALL.iter().map(|k| k.regex())).unwrap()
});

pub struct RegexDetector {
    regex_set: &'static RegexSet,
    has_short_token: bool,
    short_token_index: Option<usize>,
    /// Pre-computed (regex_set_index, placeholder) in priority order.
    /// Eliminates the O(N*M) .position() lookup in detect().
    ordered_indices: Vec<(usize, &'static str)>,
}

impl RegexDetector {
    /// Creates a new `RegexDetector` from a list of pattern names.
    ///
    /// # Panics
    ///
    /// Panics if the fallback regex set (`"^$"`) cannot be compiled.
    /// This should never happen in practice since the pattern is trivial.
    #[must_use]
    pub fn new(patterns: &[String]) -> Self {
        let regex_patterns: Vec<_> = patterns.iter()
            .filter(|p| p.as_str() != "entropy")
            .collect();
        let is_default = regex_patterns.len() == PatternKind::ALL.len()
            && regex_patterns.iter().all(|p| PatternKind::ALL.iter().any(|k| k.name() == p.as_str()));

        if is_default {
            let ordered_indices = Self::build_ordered_indices(PatternKind::ALL);
            return Self {
                regex_set: &*DEFAULT_REGEX_SET,
                has_short_token: true,
                short_token_index: Some(7), // ShortToken is index 7 in PatternKind::ALL
                ordered_indices,
            };
        }

        let mut kinds = Vec::new();
        let mut regexes = Vec::new();
        let mut has_short_token = false;
        let mut short_token_index = None;

        for kind in PatternKind::ALL {
            if patterns.iter().any(|p| p == kind.name()) {
                if *kind == PatternKind::ShortToken {
                    has_short_token = true;
                    short_token_index = Some(kinds.len());
                }
                kinds.push(*kind);
                regexes.push(kind.regex());
            }
        }

        // SAFETY: This leaks the RegexSet intentionally. In CLI usage the
        // process exits shortly after, reclaiming all memory. If used as a
        // library with many distinct custom pattern sets, callers may observe
        // unbounded growth. For the common case (default patterns), the
        // LazyLock fast path avoids this entirely.
        let regex_set = Box::leak(Box::new(
            RegexSet::new(&regexes).unwrap_or_else(|_| RegexSet::new(["^$"]).unwrap())
        ));

        let ordered_indices = Self::build_ordered_indices(&kinds);

        Self {
            regex_set,
            has_short_token,
            short_token_index,
            ordered_indices,
        }
    }

    fn build_ordered_indices(kinds: &[PatternKind]) -> Vec<(usize, &'static str)> {
        let priority_order = [
            PatternKind::Uuid,
            PatternKind::Mongo,
            PatternKind::Hash,
            PatternKind::NumId,
            PatternKind::TimestampIso,
            PatternKind::Epoch,
            PatternKind::Ulid,
            PatternKind::Base64,
        ];

        priority_order
            .iter()
            .filter_map(|kind| {
                kinds.iter().position(|k| *k == *kind).map(|i| (i, kind.placeholder()))
            })
            .collect()
    }
}

impl Detector for RegexDetector {
    fn name(&self) -> &'static str {
        "regex_set"
    }

    fn detect(&self, segment: &str) -> Option<&'static str> {
        if self.ordered_indices.is_empty() {
            return None;
        }

        let matches = self.regex_set.matches(segment);

        for &(i, placeholder) in &self.ordered_indices {
            if matches.matched(i) {
                return Some(placeholder);
            }
        }

        if self.has_short_token {
            if let Some(i) = self.short_token_index {
                if matches.matched(i) && is_likely_token(segment) {
                    return Some(PatternKind::ShortToken.placeholder());
                }
            }
        }

        None
    }

    fn priority(&self) -> u8 {
        1
    }
}

#[allow(clippy::cast_precision_loss)]
fn is_likely_token(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    let len = s.len();
    let non_lowercase = s.chars().filter(|c| !c.is_ascii_lowercase()).count();
    let ratio = non_lowercase as f64 / len as f64;

    // Semantic words like "darkMode2" have ~10% non-lowercase
    // Tokens like "23c6DSKX" have ~60%+ non-lowercase
    ratio >= 0.3
}
