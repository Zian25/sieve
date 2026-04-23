mod cli;
mod config;
mod dedup;
mod detector;
mod output;
mod pipeline;
mod stats;
mod url;

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, stdin, stdout};

use clap::Parser;

use cli::Cli;
use config::Config;
use dedup::{deduplicate, deduplicate_diff, deduplicate_stream, write_invalid_urls};
use output::{write_output, write_diff_output};
use pipeline::{analyze_cardinality, build_learned_config, print_cardinality_report, save_learned_config};
use stats::Stats;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let mut config = if let Some(config_path) = &cli.config {
        Config::load(std::path::Path::new(config_path))?
    } else {
        Config::default()
    };

    config.apply_cli_overrides(
        cli.patterns.as_deref(),
        cli.min_segment_len,
        cli.entropy_threshold,
        cli.normalize_param_keys.as_deref(),
        cli.keep_param_keys.as_deref(),
    );

    if cli.learn {
        run_learn(&cli, &config)?;
        return Ok(());
    }

    if let Some(baseline) = &cli.diff {
        run_diff(&cli, &config, baseline)?;
        return Ok(());
    }

    run_dedup(&cli, &config)?;

    Ok(())
}

fn run_learn(cli: &Cli, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    if cli.apply && cli.input.is_none() {
        return Err("--learn --apply requires --input (cannot reread stdin)".into());
    }

    let reader: Box<dyn BufRead> = match &cli.input {
        Some(path) => Box::new(BufReader::with_capacity(256 * 1024, File::open(path)?)),
        None => Box::new(BufReader::with_capacity(256 * 1024, stdin())),
    };

    let analyzed = analyze_cardinality(reader, config, &cli.assume_scheme);
    print_cardinality_report(&analyzed.report);

    if let Some(save_path) = &cli.save_config {
        save_learned_config(&analyzed.report, save_path)?;
    }

    if cli.apply {
        let learned_config = build_learned_config(&analyzed.report);
        if let Some(input_path) = &cli.input {
            let reader2 = BufReader::with_capacity(256 * 1024, File::open(input_path)?);
            let result = deduplicate(
                reader2,
                &learned_config,
                &cli.assume_scheme,
                cli.strip_query,
                cli.sort,
            );

            let writer: Box<dyn std::io::Write> = if let Some(output) = &cli.output {
                let file = File::create(output)?;
                Box::new(BufWriter::with_capacity(256 * 1024, file))
            } else {
                Box::new(BufWriter::with_capacity(256 * 1024, stdout()))
            };

            write_output(writer, &result, cli.format)?;

            if cli.stats {
                Stats::from_result(&result).print();
            }
        }
    }

    Ok(())
}

fn run_diff(cli: &Cli, config: &Config, baseline: &str) -> Result<(), Box<dyn std::error::Error>> {
    let reader: Box<dyn BufRead> = if let Some(input) = &cli.input {
        let file = File::open(input)?;
        Box::new(BufReader::with_capacity(256 * 1024, file))
    } else {
        Box::new(BufReader::with_capacity(256 * 1024, stdin()))
    };

    let new_urls = deduplicate_diff(
        reader,
        baseline,
        config,
        &cli.assume_scheme,
        cli.diff_strict,
        cli.strip_query,
        cli.sort,
    )?;

    let writer: Box<dyn std::io::Write> = if let Some(output) = &cli.output {
        let file = File::create(output)?;
        Box::new(BufWriter::with_capacity(256 * 1024, file))
    } else {
        Box::new(BufWriter::with_capacity(256 * 1024, stdout()))
    };

    write_diff_output(writer, &new_urls)?;

    Ok(())
}

fn run_dedup(cli: &Cli, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let can_stream = matches!(cli.format, cli::OutputFormat::Rep | cli::OutputFormat::Jsonl)
        && !cli.sort
        && cli.invalid_output.is_none();

    if can_stream {
        run_dedup_stream(cli, config)?;
    } else {
        run_dedup_batch(cli, config)?;
    }

    Ok(())
}

fn run_dedup_stream(cli: &Cli, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let reader: Box<dyn BufRead> = if let Some(input) = &cli.input {
        let file = File::open(input)?;
        Box::new(BufReader::with_capacity(256 * 1024, file))
    } else {
        Box::new(BufReader::with_capacity(256 * 1024, stdin()))
    };

    let writer: Box<dyn std::io::Write> = if let Some(output) = &cli.output {
        let file = File::create(output)?;
        Box::new(BufWriter::with_capacity(256 * 1024, file))
    } else {
        Box::new(BufWriter::with_capacity(256 * 1024, stdout()))
    };

    let stats = deduplicate_stream(
        reader,
        writer,
        config,
        &cli.assume_scheme,
        cli.strip_query,
        cli.format,
    )?;

    if cli.stats {
        eprintln!("\nTotal URLs: {}", stats.total_urls);
        eprintln!("Unique fingerprints: {}", stats.unique_fingerprints);
        eprintln!("Invalid URLs: {}", stats.invalid_urls);
    }

    Ok(())
}

fn run_dedup_batch(cli: &Cli, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let reader: Box<dyn BufRead> = if let Some(input) = &cli.input {
        let file = File::open(input)?;
        Box::new(BufReader::with_capacity(256 * 1024, file))
    } else {
        Box::new(BufReader::with_capacity(256 * 1024, stdin()))
    };

    let result = deduplicate(reader, config, &cli.assume_scheme, cli.strip_query, cli.sort);

    if let Some(invalid_path) = &cli.invalid_output {
        write_invalid_urls(&result.invalid_urls, invalid_path)?;
    }

    let writer: Box<dyn std::io::Write> = if let Some(output) = &cli.output {
        let file = File::create(output)?;
        Box::new(BufWriter::with_capacity(256 * 1024, file))
    } else {
        Box::new(BufWriter::with_capacity(256 * 1024, stdout()))
    };

    write_output(writer, &result, cli.format)?;

    if cli.stats {
        Stats::from_result(&result).print();
    }

    Ok(())
}
