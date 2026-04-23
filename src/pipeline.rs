use std::io::BufRead;

use ahash::{AHashMap, AHashSet};

use crate::config::Config;
use crate::url::parse_url;

pub struct CardinalityReport {
    pub position_stats: AHashMap<usize, PositionInfo>,
    pub query_param_stats: AHashMap<String, QueryParamInfo>,
}

pub struct PositionInfo {
    pub values: usize,
    pub sample: Vec<String>,
}

pub struct QueryParamInfo {
    pub unique_values: usize,
    #[allow(dead_code)]
    pub sample: Vec<String>,
}

pub struct AnalyzedInput {
    pub report: CardinalityReport,
}

#[must_use]
pub fn analyze_cardinality<R: BufRead>(
    reader: R,
    _config: &Config,
    assume_scheme: &str,
) -> AnalyzedInput {
    let mut position_values: AHashMap<usize, Vec<String>> = AHashMap::new();
    let mut query_param_values: AHashMap<String, Vec<String>> = AHashMap::new();

    for line in reader.lines() {
        let Ok(line) = line else { continue };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let Some(parsed) = parse_url(trimmed, assume_scheme) else { continue };

        let segments: Vec<&str> = parsed.path.split('/').filter(|s| !s.is_empty()).collect();
        for (i, segment) in segments.iter().enumerate() {
            position_values
                .entry(i)
                .or_default()
                .push(segment.to_string());
        }

        if let Some(query) = &parsed.query {
            let pairs: Vec<_> = url::form_urlencoded::parse(query.as_bytes()).collect();
            for (key, value) in pairs {
                query_param_values
                    .entry(key.to_string())
                    .or_default()
                    .push(value.to_string());
            }
        }
    }

    let mut position_stats = AHashMap::new();
    for (pos, values) in position_values {
        let unique: AHashSet<_> = values.iter().cloned().collect();
        let sample: Vec<_> = unique.iter().take(10).cloned().collect();
        position_stats.insert(
            pos,
            PositionInfo {
                values: unique.len(),
                sample,
            },
        );
    }

    let mut query_param_stats = AHashMap::new();
    for (key, values) in query_param_values {
        let unique: AHashSet<_> = values.iter().cloned().collect();
        let sample: Vec<_> = unique.iter().take(10).cloned().collect();
        query_param_stats.insert(
            key,
            QueryParamInfo {
                unique_values: unique.len(),
                sample,
            },
        );
    }

    AnalyzedInput {
        report: CardinalityReport {
            position_stats,
            query_param_stats,
        },
    }
}

pub fn print_cardinality_report(report: &CardinalityReport) {
    eprintln!("\n=== Cardinality Analysis ===\n");

    eprintln!("--- Path Segment Analysis ---");
    eprintln!("{:<10} {:<30} {:<10} Decision", "Position", "Pattern", "Unique");
    eprintln!("{}", "-".repeat(70));

    let mut positions: Vec<_> = report.position_stats.iter().collect();
    positions.sort_by_key(|(pos, _)| **pos);

    for (pos, info) in positions {
        let sample_str = info.sample.join(", ");
        let decision = if info.values > 500 {
            "DYNAMIC (entropy)"
        } else if info.values > 50 {
            "DYNAMIC (pattern)"
        } else if info.values > 5 {
            "MIXED"
        } else {
            "STATIC"
        };
        eprintln!("{:<10} {:<30} {:<10} {}", pos, sample_str, info.values, decision);
    }

    eprintln!("\n--- Query Parameter Analysis ---");
    eprintln!("{:<20} {:<10} Decision", "Key", "Unique");
    eprintln!("{}", "-".repeat(50));

    let mut params: Vec<_> = report.query_param_stats.iter().collect();
    params.sort_by_key(|(key, _)| key.as_str());

    for (key, info) in params {
        let decision = if info.unique_values > 50 {
            "DYNAMIC (normalize)"
        } else if info.unique_values > 5 {
            "MIXED"
        } else {
            "STATIC (keep)"
        };
        eprintln!("{:<20} {:<10} {}", key, info.unique_values, decision);
    }

    eprintln!();
}

#[must_use]
pub fn build_learned_config(report: &CardinalityReport) -> Config {
    let mut always_normalize = Vec::new();
    let mut never_normalize = Vec::new();

    for (key, info) in &report.query_param_stats {
        if info.unique_values > 50 {
            always_normalize.push(key.clone());
        } else if info.unique_values <= 5 {
            never_normalize.push(key.clone());
        }
        // Params with 6-50 unique values are intentionally left unclassified.
        // They fall through to the default heuristic (regex/entropy detection
        // on individual values), which handles the gray zone better than a
        // blanket always/never rule.
    }

    always_normalize.sort();
    never_normalize.sort();

    // Detect dynamic path segments and generate structural patterns.
    // Uses a sample of up to 10 unique values per position to infer the pattern.
    // Positions with extremely high cardinality (>500 unique values) are skipped
    // to avoid generating the catch-all [^/]+ pattern, which would match every
    // segment and destroy path-based deduplication. Those segments will be
    // handled by the entropy detector instead.
    let mut pattern_segments = Vec::new();
    for (_pos, info) in &report.position_stats {
        if info.values > 50 {
            // Skip catch-all generation for extremely high cardinality positions.
            if info.values > 500 {
                continue;
            }
            let is_numeric = info.sample.iter().all(|s| s.chars().all(|c| c.is_ascii_digit()));
            let is_uuid = info.sample.iter().all(|s| {
                s.len() == 36
                    && s.chars().filter(|c| *c == '-').count() == 4
                    && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
            });
            if is_uuid {
                pattern_segments.push(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}".into());
            } else if is_numeric {
                pattern_segments.push(r"\d+".into());
            }
            // Skip non-UUID, non-numeric patterns — let entropy detector handle them.
        }
    }

    pattern_segments.sort();
    pattern_segments.dedup();

    Config {
        general: crate::config::GeneralConfig::default(),
        normalize_params: crate::config::NormalizeParamsConfig {
            always_normalize,
            never_normalize,
        },
        structural: crate::config::StructuralConfig {
            literal_segments: crate::config::StructuralConfig::default().literal_segments,
            pattern_segments,
        },
    }
}

/// Saves a learned configuration as a TOML file.
///
/// # Errors
///
/// Returns an error if serialization or file writing fails.
pub fn save_learned_config(report: &CardinalityReport, path: &str) -> Result<(), String> {
    let config = build_learned_config(report);
    let toml_str = toml::to_string(&config)
        .map_err(|e| format!("Failed to serialize config: {e}"))?;

    std::fs::write(path, toml_str)
        .map_err(|e| format!("Failed to write config file: {e}"))?;

    eprintln!("Learned config saved to {path}");
    Ok(())
}
