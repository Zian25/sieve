use super::Detector;
use crate::detector::shannon_entropy;

pub struct EntropyDetector {
    min_len: usize,
    threshold: f64,
}

impl EntropyDetector {
    #[must_use]
    pub fn new(min_len: usize, threshold: f64) -> Self {
        Self { min_len, threshold }
    }
}

impl Detector for EntropyDetector {
    fn name(&self) -> &'static str {
        "entropy"
    }

    fn detect(&self, segment: &str) -> Option<&'static str> {
        if segment.len() >= self.min_len && shannon_entropy(segment) > self.threshold {
            return Some("{hash}");
        }
        None
    }

    fn priority(&self) -> u8 {
        255
    }
}
