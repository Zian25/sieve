use std::io::Write;

use crate::cli::OutputFormat;
use crate::dedup::DedupResult;

/// Writes deduplication results to a writer in the specified format.
///
/// # Errors
///
/// Returns an error if writing to the output fails.
pub fn write_output<W: Write>(
    mut writer: W,
    result: &DedupResult,
    format: OutputFormat,
) -> Result<(), String> {
    match format {
        OutputFormat::Rep => write_representative(&mut writer, result)?,
        OutputFormat::Counted => write_counted(&mut writer, result)?,
        OutputFormat::Json => write_json(&mut writer, result)?,
        OutputFormat::Jsonl => write_jsonl(&mut writer, result)?,
    }

    writer.flush().map_err(|e| format!("Failed to flush output: {e}"))?;
    Ok(())
}

fn write_representative<W: Write>(
    writer: &mut W,
    result: &DedupResult,
) -> Result<(), String> {
    for group in &result.groups {
        writeln!(writer, "{}", group.representative)
            .map_err(|e| format!("Failed to write output: {e}"))?;
    }
    Ok(())
}

fn write_counted<W: Write>(
    writer: &mut W,
    result: &DedupResult,
) -> Result<(), String> {
    for group in &result.groups {
        if group.count > 1 {
            writeln!(writer, "{}  # {} duplicates", group.representative, group.count)
                .map_err(|e| format!("Failed to write output: {e}"))?;
        } else {
            writeln!(writer, "{}", group.representative)
                .map_err(|e| format!("Failed to write output: {e}"))?;
        }
    }
    Ok(())
}

fn write_json<W: Write>(
    writer: &mut W,
    result: &DedupResult,
) -> Result<(), String> {
    serde_json::to_writer(&mut *writer, result)
        .map_err(|e| format!("Failed to write JSON: {e}"))?;

    writeln!(writer).map_err(|e| format!("Failed to write newline: {e}"))?;

    Ok(())
}

fn write_jsonl<W: Write>(
    writer: &mut W,
    result: &DedupResult,
) -> Result<(), String> {
    for group in &result.groups {
        serde_json::to_writer(&mut *writer, group)
            .map_err(|e| format!("Failed to write JSONL: {e}"))?;
        writeln!(writer).map_err(|e| format!("Failed to write newline: {e}"))?;
    }
    Ok(())
}

/// Writes diff output (new URLs not in baseline) to a writer.
///
/// # Errors
///
/// Returns an error if writing to the output fails.
pub fn write_diff_output<W: Write>(
    mut writer: W,
    urls: &[String],
) -> Result<(), String> {
    for url in urls {
        writeln!(writer, "{url}")
            .map_err(|e| format!("Failed to write output: {e}"))?;
    }

    writer.flush().map_err(|e| format!("Failed to flush output: {e}"))?;
    Ok(())
}
