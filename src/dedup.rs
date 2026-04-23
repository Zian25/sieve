use std::hash::BuildHasher;
use std::sync::LazyLock;

use ahash::{AHashMap, AHashSet};
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};

use crate::cli::OutputFormat;
use crate::config::Config;
use crate::url::{parse_path, parse_url, Fingerprinter};

static STREAMING_HASHER: LazyLock<rapidhash::fast::GlobalState> =
    LazyLock::new(rapidhash::fast::GlobalState::default);

#[derive(Debug, Serialize)]
pub struct UrlGroup {
    pub fingerprint: String,
    pub representative: String,
    pub count: usize,
}

#[derive(Serialize)]
pub struct DedupResult {
    pub groups: Vec<UrlGroup>,
    pub total_urls: usize,
    pub unique_fingerprints: usize,
    pub invalid_urls: Vec<String>,
}

#[must_use]
pub fn deduplicate<R: BufRead>(
    reader: R,
    config: &Config,
    assume_scheme: &str,
    strip_query: bool,
    sort: bool,
    path_only: bool,
) -> DedupResult {
    let fingerprinter = Fingerprinter::new(config);
    let mut groups: AHashMap<String, (String, usize)> = AHashMap::new();
    let mut invalid_urls = Vec::new();
    let mut total_urls = 0;
    let mut fp_buffer = String::with_capacity(256);

    for line in reader.lines() {
        let Ok(line) = line else { continue };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        total_urls += 1;

        let parsed = if path_only {
            parse_path(trimmed)
        } else {
            parse_url(trimmed, assume_scheme)
        };
        let Some(parsed) = parsed else {
            invalid_urls.push(trimmed.to_string());
            continue;
        };

        if strip_query {
            fingerprinter.fingerprint_with_strip_query_into(&parsed, &mut fp_buffer);
        } else {
            fingerprinter.fingerprint_into(&parsed, &mut fp_buffer);
        }
        let fingerprint = fp_buffer.clone();

        let entry = groups.entry(fingerprint).or_insert_with(|| (trimmed.to_string(), 0));
        entry.1 += 1;
        // Keep the lexicographically smallest URL as representative for
        // deterministic output regardless of input order.
        if trimmed < entry.0.as_str() {
            entry.0 = trimmed.to_string();
        }
    }

    let unique_fingerprints = groups.len();
    let mut groups: Vec<_> = groups
        .into_iter()
        .map(|(fingerprint, (representative, count))| UrlGroup {
            fingerprint,
            representative,
            count,
        })
        .collect();
    if sort {
        groups.sort_unstable_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    }

    DedupResult {
        groups,
        total_urls,
        unique_fingerprints,
        invalid_urls,
    }
}

pub struct StreamStats {
    pub total_urls: usize,
    pub unique_fingerprints: usize,
    pub invalid_urls: usize,
}

/// Deduplicates URLs from a reader in streaming mode, writing unique fingerprints to a writer.
///
/// # Errors
///
/// Returns an error if reading, writing, or URL parsing fails.
pub fn deduplicate_stream<R: BufRead, W: Write>(
    reader: R,
    mut writer: W,
    config: &Config,
    assume_scheme: &str,
    strip_query: bool,
    format: OutputFormat,
    path_only: bool,
) -> Result<StreamStats, String> {
    let fingerprinter = Fingerprinter::new(config);
    let mut seen: AHashSet<u64> = AHashSet::new();
    let mut total_urls = 0;
    let mut unique_fingerprints = 0;
    let mut invalid_urls = 0;
    let mut fp_buffer = String::with_capacity(256);

    for line in reader.lines() {
        let Ok(line) = line else { continue };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        total_urls += 1;

        let parsed = if path_only {
            parse_path(trimmed)
        } else {
            parse_url(trimmed, assume_scheme)
        };
        let Some(parsed) = parsed else {
            invalid_urls += 1;
            continue;
        };

        if strip_query {
            fingerprinter.fingerprint_with_strip_query_into(&parsed, &mut fp_buffer);
        } else {
            fingerprinter.fingerprint_into(&parsed, &mut fp_buffer);
        }

        let hash = STREAMING_HASHER.hash_one(fp_buffer.as_bytes());

        if !seen.insert(hash) {
            continue;
        }

        unique_fingerprints += 1;

        match format {
            OutputFormat::Rep => {
                writeln!(writer, "{trimmed}")
                    .map_err(|e| format!("Failed to write output: {e}"))?;
            }
            OutputFormat::Jsonl => {
                let entry = serde_json::json!({
                    "fingerprint": fp_buffer,
                    "representative": trimmed,
                    "count": 1,
                });
                serde_json::to_writer(&mut writer, &entry)
                    .map_err(|e| format!("Failed to write JSONL: {e}"))?;
                writeln!(writer).map_err(|e| format!("Failed to write newline: {e}"))?;
            }
            _ => return Err("Streaming mode only supports rep or jsonl format".into()),
        }
    }

    writer.flush().map_err(|e| format!("Failed to flush output: {e}"))?;

    Ok(StreamStats {
        total_urls,
        unique_fingerprints,
        invalid_urls,
    })
}

/// Compares URLs from a reader against a baseline file, returning URLs with new fingerprints.
///
/// # Errors
///
/// Returns an error if reading, parsing, or loading the baseline fails.
#[allow(clippy::too_many_arguments)]
pub fn deduplicate_diff<R: BufRead>(
    reader: R,
    baseline_path: &str,
    config: &Config,
    assume_scheme: &str,
    strict: bool,
    strip_query: bool,
    sort: bool,
    path_only: bool,
) -> Result<Vec<String>, String> {
    let baseline_set = load_baseline(baseline_path, config, assume_scheme, strict, strip_query, path_only)?;
    let fingerprinter = Fingerprinter::new(config);

    let mut new_urls = Vec::new();
    let mut seen: AHashSet<String> = AHashSet::new();
    let mut fp_buffer = String::with_capacity(256);

    for line in reader.lines() {
        let Ok(line) = line else { continue };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parsed = if path_only {
            parse_path(trimmed)
        } else {
            parse_url(trimmed, assume_scheme)
        };
        let Some(parsed) = parsed else { continue };

        let key = if strict {
            trimmed.to_string()
        } else {
            if strip_query {
                fingerprinter.fingerprint_with_strip_query_into(&parsed, &mut fp_buffer);
            } else {
                fingerprinter.fingerprint_into(&parsed, &mut fp_buffer);
            }
            fp_buffer.clone()
        };

        if !baseline_set.contains(&key) && !seen.contains(&key) {
            seen.insert(key);
            new_urls.push(trimmed.to_string());
        }
    }

    if sort {
        new_urls.sort_unstable();
    }

    Ok(new_urls)
}

fn load_baseline(
    path: &str,
    config: &Config,
    assume_scheme: &str,
    strict: bool,
    strip_query: bool,
    path_only: bool,
) -> Result<AHashSet<String>, String> {
    let file = File::open(path)
        .map_err(|e| format!("Failed to open baseline file '{path}': {e}"))?;

    let fingerprinter = Fingerprinter::new(config);
    let mut set: AHashSet<String> = AHashSet::new();
    let reader = BufReader::with_capacity(256 * 1024, file);
    let mut fp_buffer = String::with_capacity(256);

    for line in reader.lines() {
        let Ok(line) = line else { continue };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parsed = if path_only {
            parse_path(trimmed)
        } else {
            parse_url(trimmed, assume_scheme)
        };
        let Some(parsed) = parsed else { continue };

        let key = if strict {
            trimmed.to_string()
        } else {
            if strip_query {
                fingerprinter.fingerprint_with_strip_query_into(&parsed, &mut fp_buffer);
            } else {
                fingerprinter.fingerprint_into(&parsed, &mut fp_buffer);
            }
            fp_buffer.clone()
        };

        set.insert(key);
    }

    Ok(set)
}

/// Writes invalid URLs to a file for later inspection.
///
/// # Errors
///
/// Returns an error if the file cannot be created or written.
pub fn write_invalid_urls(invalid_urls: &[String], path: &str) -> Result<(), String> {
    if invalid_urls.is_empty() {
        return Ok(());
    }

    let file = File::create(path)
        .map_err(|e| format!("Failed to create invalid output file: {e}"))?;
    let mut writer = BufWriter::with_capacity(256 * 1024, file);

    for url in invalid_urls {
        writeln!(writer, "{url}")
            .map_err(|e| format!("Failed to write invalid URL: {e}"))?;
    }

    writer.flush()
        .map_err(|e| format!("Failed to flush invalid output: {e}"))?;

    Ok(())
}
