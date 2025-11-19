use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::config;
use crate::processor::{self, HashResult, VerificationStatus};
use crate::util;

// ============================================================================
// Error Types
// ============================================================================

/// Detailed errors for checksum line parsing
#[derive(Debug)]
pub enum ParseError {
    EmptyOrComment,
    TooShort(usize),
    InvalidSeparator(String),
    InvalidHashLength(usize),
    NonHexCharacters(String),
}

// ============================================================================
// Checksum Verification Functions
// ============================================================================

/// Parse a line from a checksum file
///
/// Expected format: <128 hex chars><separator><filename>
/// Separators: "  " (two spaces), " *" (space+asterisk), or " " (single space)
fn parse_checksum_line(line: &str) -> Result<(&str, &str), ParseError> {
    let line = line.trim();

    // Skip empty lines and comments
    if line.is_empty() || line.starts_with('#') {
        return Err(ParseError::EmptyOrComment);
    }

    // Check minimum length (hash + separator + at least 1 char filename)
    if line.len() < config::HASH_HEX_SIZE + 1 {
        return Err(ParseError::TooShort(line.len()));
    }

    // Extract hash and remainder
    let (hash_part, rest) = line.split_at(config::HASH_HEX_SIZE);

    // Validate hash length
    if hash_part.len() != config::HASH_HEX_SIZE {
        return Err(ParseError::InvalidHashLength(hash_part.len()));
    }

    // Validate hash contains only hexadecimal characters
    if let Some(non_hex) = hash_part.chars().find(|&c| !c.is_ascii_hexdigit()) {
        return Err(ParseError::NonHexCharacters(format!(
            "character '{}' at position {}",
            non_hex,
            hash_part.find(non_hex).unwrap_or(0)
        )));
    }

    // Check for remainder
    if rest.is_empty() {
        return Err(ParseError::TooShort(line.len()));
    }

    // Parse separator and extract filename
    let filename = if let Some(stripped) = rest.strip_prefix(config::HASH_SEPARATOR_DOUBLE) {
        stripped.trim_start()
    } else if let Some(stripped) = rest.strip_prefix(config::HASH_SEPARATOR_ASTERISK) {
        stripped.trim_start()
    } else if let Some(stripped) = rest.strip_prefix(' ') {
        stripped.trim_start()
    } else {
        return Err(ParseError::InvalidSeparator(rest.chars().take(2).collect()));
    };

    // Validate filename is not empty
    if filename.is_empty() {
        return Err(ParseError::TooShort(line.len()));
    }

    Ok((hash_part, filename))
}

/// Verify checksums from a checksum file
pub fn check_checksums(
    checksum_source: &str,
    config: &config::Config,
    status_only: bool,
    warn: bool,
    quiet: bool,
) -> io::Result<(i32, Vec<HashResult>)> {
    let file_counter = AtomicUsize::new(0);
    let checksum_path = Path::new(checksum_source);

    // Open checksum file or use stdin
    let reader: Box<dyn BufRead> = if checksum_source == "-" {
        Box::new(BufReader::with_capacity(config::BUFFER_SIZE, io::stdin()))
    } else {
        let canonical_checksum_path = util::safe_canonicalize(checksum_path)?;
        let checksum_file =
            util::secure_open_file(&canonical_checksum_path, config, &file_counter, None)?;
        Box::new(BufReader::with_capacity(config::BUFFER_SIZE, checksum_file))
    };

    // Counters for statistics
    let mut failed = 0;
    let mut total = 0;
    let mut invalid_lines = 0;
    let mut results = Vec::with_capacity(256);

    // Track if any failure occurred (for early exit in status-only mode)
    let has_failed = Arc::new(AtomicBool::new(false));

    // Process each line
    for (line_num, line_result) in reader.lines().enumerate() {
        let line_num = line_num + 1;

        // Early exit optimization for status-only mode
        if status_only && has_failed.load(Ordering::Relaxed) {
            return Ok((1, results));
        }

        // Read line from file
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                invalid_lines += 1;
                if !status_only && config.output_format == config::OutputFormat::Text {
                    eprintln!(
                        "whirlpoolsum: {}: line {}: read error: {}",
                        checksum_source, line_num, e
                    );
                }
                continue;
            }
        };

        // Parse checksum line
        match parse_checksum_line(&line) {
            Ok((expected_hash, filename)) => {
                total += 1;

                // Resolve and validate target file path
                let target_path = Path::new(filename);
                // Note: We don't canonicalize target path immediately because it might be relative to CWD
                // But secure_open_file expects a path.
                // In original code: util::safe_canonicalize(target_path)?
                // We should probably keep that behavior.
                
                let canonical_target_result = util::safe_canonicalize(target_path);

                match canonical_target_result {
                    Ok(canonical_target) => {
                        // Attempt to open file and compute hash
                        let result = File::open(&canonical_target)
                            .and_then(|file| {
                                let metadata = file.metadata()?;
                                util::secure_open_file(
                                    &canonical_target,
                                    config,
                                    &file_counter,
                                    Some(metadata),
                                )
                            })
                            .map_err(|e| format!("{}", e))
                            .and_then(|file| {
                                let mut reader = BufReader::with_capacity(config::BUFFER_SIZE, file);
                                processor::compute_whirlpool(&mut reader)
                                    .map(|hash| util::hash_to_hex(&hash))
                                    .map_err(|e| format!("hash computation failed: {}", e))
                            });

                        // Compare computed hash with expected hash
                        match result {
                            Ok(actual_hash) => {
                                let status = if actual_hash.eq_ignore_ascii_case(expected_hash) {
                                    // Hash matches - file verified successfully
                                    if !status_only
                                        && !quiet
                                        && config.output_format == config::OutputFormat::Text
                                    {
                                        println!("{}: OK", filename);
                                    }
                                    VerificationStatus::Ok
                                } else {
                                    // Hash mismatch - verification failed
                                    failed += 1;
                                    has_failed.store(true, Ordering::Relaxed);
                                    if !status_only && config.output_format == config::OutputFormat::Text {
                                        eprintln!("{}: FAILED", filename);
                                        eprintln!(
                                            "whirlpoolsum: {}: line {}: computed hash: {}",
                                            checksum_source, line_num, actual_hash
                                        );
                                        eprintln!(
                                            "whirlpoolsum: {}: line {}: expected hash: {}",
                                            checksum_source, line_num, expected_hash
                                        );
                                    }
                                    VerificationStatus::Failed
                                };
                                results.push(HashResult {
                                    filename: PathBuf::from(filename),
                                    hash: actual_hash,
                                    status: Some(status),
                                    benchmark_info: None,
                                });
                            }
                            Err(err) => {
                                // Could not open or read file
                                failed += 1;
                                has_failed.store(true, Ordering::Relaxed);
                                if !status_only && config.output_format == config::OutputFormat::Text {
                                    eprintln!("{}: FAILED open or read - {}", filename, err);
                                }
                                results.push(HashResult {
                                    filename: PathBuf::from(filename),
                                    hash: expected_hash.to_string(),
                                    status: Some(VerificationStatus::FailedOpenRead),
                                    benchmark_info: None,
                                });
                            }
                        }
                    },
                    Err(e) => {
                         // Could not canonicalize (e.g. file not found)
                        failed += 1;
                        has_failed.store(true, Ordering::Relaxed);
                        if !status_only && config.output_format == config::OutputFormat::Text {
                             eprintln!("{}: FAILED open or read - {}", filename, e);
                        }
                        results.push(HashResult {
                            filename: PathBuf::from(filename),
                            hash: expected_hash.to_string(),
                            status: Some(VerificationStatus::FailedOpenRead),
                            benchmark_info: None,
                        });
                    }
                }
            }
            Err(err) => {
                // Line parsing failed - malformed checksum line
                invalid_lines += 1;
                if !status_only && config.output_format == config::OutputFormat::Text {
                    let source_name = if checksum_source == "-" {
                        "standard input"
                    } else {
                        checksum_source
                    };

                    // Provide detailed error messages based on parse error type
                    match err {
                        ParseError::EmptyOrComment => {
                            // Silently ignore empty lines and comments
                        }
                        ParseError::TooShort(len) => {
                            eprintln!(
                                "whirlpoolsum: {}: line {}: line too short ({} characters). \
                                 Expected format: <128-character hash> <space(s)> <filename>",
                                source_name, line_num, len
                            );
                        }
                        ParseError::InvalidSeparator(sep) => {
                            eprintln!(
                                "whirlpoolsum: {}: line {}: invalid separator '{:#?}'. \
                                 Expected one or two spaces, or space+asterisk",
                                source_name, line_num, sep
                            );
                        }
                        ParseError::InvalidHashLength(len) => {
                            eprintln!(
                                "whirlpoolsum: {}: line {}: invalid hash length. \
                                 Expected 128 hexadecimal characters for WHIRLPOOL-512, got {}",
                                source_name, line_num, len
                            );
                        }
                        ParseError::NonHexCharacters(pos) => {
                            eprintln!(
                                "whirlpoolsum: {}: line {}: invalid hash format. \
                                 WHIRLPOOL-512 hash must contain only hexadecimal characters (0-9, a-f, A-F). \
                                 Problem at: {}",
                                source_name, line_num, pos
                            );
                        }
                    }
                }
            }
        }
    }

    // Print summary statistics in text mode
    if !status_only && config.output_format == config::OutputFormat::Text {
        if failed > 0 {
            eprintln!(
                "whirlpoolsum: WARNING: {} of {} computed checksums did NOT match",
                failed, total
            );
        }
        if invalid_lines > 0 && warn {
            eprintln!(
                "whirlpoolsum: WARNING: {} of {} lines are improperly formatted",
                invalid_lines,
                total + invalid_lines
            );
        }
    }

    // Return exit code and results
    Ok((
        if failed > 0 || invalid_lines > 0 {
            1
        } else {
            0
        },
        results,
    ))
}
