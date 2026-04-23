mod entropy;
mod regex_set;
mod structural;

pub trait Detector {
    #[allow(dead_code)]
    fn name(&self) -> &'static str;
    fn detect(&self, segment: &str) -> Option<&'static str>;
    /// Lower priority runs first. Structural (0) runs before Regex (1) before Entropy (255).
    /// __STRUCTURAL__ returns bypass normalization entirely.
    fn priority(&self) -> u8;
}

pub use entropy::EntropyDetector;
pub use regex_set::{PatternKind, RegexDetector};
pub use structural::StructuralDetector;

#[must_use]
#[allow(clippy::cast_precision_loss, clippy::cast_lossless)]
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    let len = s.len() as f64;

    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }

    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = f64::from(count) / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}
