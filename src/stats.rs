use crate::dedup::DedupResult;

pub struct Stats {
    pub total_urls: usize,
    pub unique_fingerprints: usize,
    pub duplicates_removed: usize,
    pub duplicate_percentage: f64,
    pub invalid_urls: usize,
}

impl Stats {
    #[must_use]
#[allow(clippy::cast_precision_loss)]
    pub fn from_result(result: &DedupResult) -> Self {
        let duplicates_removed = result.total_urls.saturating_sub(result.unique_fingerprints);
        let duplicate_percentage = if result.total_urls > 0 {
            (duplicates_removed as f64 / result.total_urls as f64) * 100.0
        } else {
            0.0
        };

        Self {
            total_urls: result.total_urls,
            unique_fingerprints: result.unique_fingerprints,
            duplicates_removed,
            duplicate_percentage,
            invalid_urls: result.invalid_urls.len(),
        }
    }

    pub fn print(&self) {
        eprintln!();
        eprintln!("=== urlsieve Statistics ===");
        eprintln!("Total URLs processed:    {}", self.total_urls);
        eprintln!("Unique fingerprints:     {}", self.unique_fingerprints);
        eprintln!("Duplicates removed:      {}", self.duplicates_removed);
        eprintln!("Duplicate percentage:    {:.1}%", self.duplicate_percentage);
        if self.invalid_urls > 0 {
            eprintln!("Invalid URLs:          {}", self.invalid_urls);
        }
        eprintln!();
    }
}
