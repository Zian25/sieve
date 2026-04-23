use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "urlsieve")]
#[command(about = "Intelligent URL deduplication tool for bug bounty workflows")]
#[command(version)]
#[allow(clippy::struct_excessive_bools)]
pub struct Cli {
    /// Input file (reads from stdin if omitted)
    #[arg(value_name = "INPUT", short = 'i', long)]
    pub input: Option<String>,

    /// Output file (writes to stdout if omitted)
    #[arg(short, long)]
    pub output: Option<String>,

    /// Output format
    #[arg(short, long, default_value = "rep")]
    pub format: OutputFormat,

    /// Config file (TOML)
    #[arg(short, long)]
    pub config: Option<String>,

    /// Show deduplication statistics
    #[arg(long)]
    pub stats: bool,

    /// Patterns to enable (comma-separated)
    #[arg(long)]
    pub patterns: Option<String>,

    /// Minimum segment length for entropy check
    #[arg(long)]
    pub min_segment_len: Option<usize>,

    /// Shannon entropy threshold for dynamic detection
    #[arg(long)]
    pub entropy_threshold: Option<f64>,

    /// Parameter keys whose values are always normalized (comma-separated)
    #[arg(long)]
    pub normalize_param_keys: Option<String>,

    /// Parameter keys whose values are never normalized (comma-separated)
    #[arg(long)]
    pub keep_param_keys: Option<String>,

    /// Remove query params entirely from fingerprint
    #[arg(long)]
    pub strip_query: bool,

    /// Prepend scheme to scheme-less URLs
    #[arg(long, default_value = "https")]
    pub assume_scheme: String,

    /// Write invalid/malformed URLs to file
    #[arg(long)]
    pub invalid_output: Option<String>,

    /// Analyze cardinality and print report
    #[arg(long)]
    pub learn: bool,

    /// Apply learned config during analysis
    #[arg(long, requires = "learn")]
    pub apply: bool,

    /// Save learned config to TOML file
    #[arg(long, requires = "learn")]
    pub save_config: Option<String>,

    /// Compare input against baseline file (fingerprint match)
    #[arg(long)]
    pub diff: Option<String>,

    /// Use exact URL matching in diff mode
    #[arg(long, requires = "diff")]
    pub diff_strict: bool,

    /// Sort output by fingerprint (deterministic but slower for large inputs)
    #[arg(long)]
    pub sort: bool,

    /// Treat input as paths/endpoints only (no scheme/host parsing)
    #[arg(long)]
    pub path_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// One representative URL per group
    Rep,
    /// URL with duplicate count as comment
    Counted,
    /// Structured JSON output (single JSON object)
    Json,
    /// JSON Lines (one JSON object per line, stream-friendly)
    Jsonl,
}
