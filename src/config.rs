use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::detector::PatternKind;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub normalize_params: NormalizeParamsConfig,
    #[serde(default)]
    pub structural: StructuralConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_min_segment_len")]
    pub min_segment_len: usize,
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
    #[serde(default = "default_patterns")]
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizeParamsConfig {
    #[serde(default)]
    pub always_normalize: Vec<String>,
    #[serde(default)]
    pub never_normalize: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralConfig {
    #[serde(default)]
    pub literal_segments: Vec<String>,
    #[serde(default)]
    pub pattern_segments: Vec<String>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            min_segment_len: default_min_segment_len(),
            entropy_threshold: default_entropy_threshold(),
            patterns: default_patterns(),
        }
    }
}

impl Default for NormalizeParamsConfig {
    fn default() -> Self {
        Self {
            always_normalize: vec![
                "token".into(),
                "session".into(),
                "session_id".into(),
                "user_id".into(),
                "auth".into(),
                "api_key".into(),
                "jwt".into(),
                "access_token".into(),
                "refresh_token".into(),
                "csrf".into(),
                "signature".into(),
                "ts".into(),
                "timestamp".into(),
                "_".into(),
                "cb".into(),
                "cachebust".into(),
                "rand".into(),
                "seed".into(),
            ],
            never_normalize: vec![
                "page".into(),
                "limit".into(),
                "offset".into(),
                "sort".into(),
                "order".into(),
                "format".into(),
                "callback".into(),
            ],
        }
    }
}

impl Default for StructuralConfig {
    fn default() -> Self {
        Self {
            literal_segments: vec![
                "api".into(),
                "graphql".into(),
                "health".into(),
                "status".into(),
                "favicon.ico".into(),
                "robots.txt".into(),
            ],
            pattern_segments: vec![r"v\d+".into()],
        }
    }
}

impl Config {
    /// Loads configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed as TOML.
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file {}: {}", path.display(), e))?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| format!("Failed to parse config file {}: {}", path.display(), e))?;
        Ok(config)
    }

    #[must_use]
    pub fn always_normalize_keys(&self) -> HashSet<String> {
        self.normalize_params.always_normalize.iter().cloned().collect()
    }

    #[must_use]
    pub fn never_normalize_keys(&self) -> HashSet<String> {
        self.normalize_params.never_normalize.iter().cloned().collect()
    }

    #[must_use]
    pub fn literal_segments(&self) -> HashSet<String> {
        self.structural.literal_segments.iter().cloned().collect()
    }

    pub fn apply_cli_overrides(
        &mut self,
        patterns: Option<&str>,
        min_segment_len: Option<usize>,
        entropy_threshold: Option<f64>,
        normalize_param_keys: Option<&str>,
        keep_param_keys: Option<&str>,
    ) {
        let valid = PatternKind::all_names();
        if let Some(p) = patterns {
            if p == "all" {
                self.general.patterns = valid.iter().map(|&s| s.into()).collect();
            } else {
                let requested: Vec<_> = p.split(',').map(str::trim).collect();
                let unknown: Vec<_> = requested.iter()
                    .filter(|&&name| !valid.contains(&name))
                    .copied()
                    .collect();

                if !unknown.is_empty() {
                    eprintln!("Warning: unknown pattern(s): {}. Valid patterns: {}",
                        unknown.join(", "), valid.join(", "));
                }

                self.general.patterns = requested.iter().map(std::string::ToString::to_string).collect();
            }
        }
        if let Some(v) = min_segment_len {
            self.general.min_segment_len = v;
        }
        if let Some(v) = entropy_threshold {
            self.general.entropy_threshold = v;
        }
        if let Some(keys) = normalize_param_keys {
            let new_keys: Vec<String> = keys.split(',').map(|s| s.trim().to_string()).collect();
            self.normalize_params.always_normalize.extend(new_keys);
        }
        if let Some(keys) = keep_param_keys {
            let new_keys: Vec<String> = keys.split(',').map(|s| s.trim().to_string()).collect();
            self.normalize_params.never_normalize.extend(new_keys);
        }
    }
}

fn default_min_segment_len() -> usize {
    8
}

fn default_entropy_threshold() -> f64 {
    3.5
}

fn default_patterns() -> Vec<String> {
    PatternKind::all_names().iter().map(|&s| s.into()).collect()
}
