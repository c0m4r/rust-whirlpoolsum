use rayon::prelude::*;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use whirlpool::{Digest, Whirlpool};

use crate::config;
use crate::util;

// ============================================================================
// Result Structures
// ============================================================================

/// Result of hashing or verifying a single file
#[derive(Debug, Clone)]
pub struct HashResult {
    /// Path to the file (or "-" for stdin)
    pub filename: PathBuf,
    /// Hexadecimal hash string
    pub hash: String,
    /// Verification status (only for check mode)
    pub status: Option<VerificationStatus>,
    /// Benchmark information (only when benchmarking)
    pub benchmark_info: Option<BenchmarkInfo>,
}

/// Performance metrics for benchmark mode
#[derive(Debug, Clone)]
pub struct BenchmarkInfo {
    /// Total bytes processed
    pub bytes_processed: u64,
    /// Time taken in milliseconds
    pub duration_ms: u64,
    /// Throughput in megabytes per second
    pub throughput_mbps: f64,
}

/// Status of checksum verification
#[derive(Debug, Clone)]
pub enum VerificationStatus {
    /// Hash matched expected value
    Ok,
    /// Hash did not match
    Failed,
    /// Could not open or read the file
    FailedOpenRead,
}

impl VerificationStatus {
    /// Convert status to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            VerificationStatus::Ok => "OK",
            VerificationStatus::Failed => "FAILED",
            VerificationStatus::FailedOpenRead => "FAILED_OPEN_READ",
        }
    }
}

// ============================================================================
// Cryptographic Hash Functions
// ============================================================================

/// Compute WHIRLPOOL-512 hash of data from a reader
pub fn compute_whirlpool<R: Read>(reader: &mut R) -> io::Result<[u8; config::HASH_SIZE]> {
    let mut hasher = Whirlpool::new();
    let mut buffer = [0u8; config::BUFFER_SIZE];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash_result = hasher.finalize();
    let mut hash_bytes = [0u8; config::HASH_SIZE];
    hash_bytes.copy_from_slice(&hash_result);
    Ok(hash_bytes)
}

/// Compute WHIRLPOOL-512 hash while tracking the number of bytes processed
pub fn compute_whirlpool_with_count<R: Read>(
    reader: &mut R,
    byte_count: &mut u64,
) -> io::Result<[u8; config::HASH_SIZE]> {
    let mut hasher = Whirlpool::new();
    let mut buffer = [0u8; config::BUFFER_SIZE];
    *byte_count = 0;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
        *byte_count += bytes_read as u64;
    }

    let hash_result = hasher.finalize();
    let mut hash_bytes = [0u8; config::HASH_SIZE];
    hash_bytes.copy_from_slice(&hash_result);
    Ok(hash_bytes)
}

// ============================================================================
// File Processing Functions
// ============================================================================

/// Process a single file and compute its WHIRLPOOL hash
pub fn process_file(
    filename: &Path,
    config: &config::Config,
    file_counter: &AtomicUsize,
) -> io::Result<HashResult> {
    // Start timing if benchmarking is enabled
    let start_time = if config.benchmark {
        Some(Instant::now())
    } else {
        None
    };

    // Process stdin or regular file
    let (hash, display_path, bytes_processed) = if filename == Path::new("-") {
        let stdin = io::stdin();
        let mut reader = BufReader::with_capacity(config::BUFFER_SIZE, stdin.lock());
        let mut bytes = 0u64;
        let hash = if config.benchmark {
            compute_whirlpool_with_count(&mut reader, &mut bytes)?
        } else {
            compute_whirlpool(&mut reader)?
        };
        (util::hash_to_hex(&hash), PathBuf::from("-"), bytes)
    } else {
        let canonical_path = util::safe_canonicalize(filename)?;

        // Get file metadata for security checks
        let metadata = canonical_path.metadata().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("Failed to access '{}': {}", canonical_path.display(), e),
            )
        })?;

        let file_size = metadata.len();
        let file = util::secure_open_file(&canonical_path, config, file_counter, Some(metadata))?;

        let mut reader = BufReader::with_capacity(config::BUFFER_SIZE, file);
        let mut bytes = 0u64;
        let hash = if config.benchmark {
            compute_whirlpool_with_count(&mut reader, &mut bytes)?
        } else {
            compute_whirlpool(&mut reader)?
        };
        (
            util::hash_to_hex(&hash),
            filename.to_path_buf(),
            if config.benchmark { bytes } else { file_size },
        )
    };

    // Calculate benchmark metrics if enabled
    let benchmark_info = if let Some(start) = start_time {
        let duration = start.elapsed();
        let duration_ms = duration.as_millis() as u64;
        let throughput_mbps = if duration_ms > 0 {
            (bytes_processed as f64 / 1_048_576.0) / (duration_ms as f64 / 1000.0)
        } else {
            0.0
        };
        Some(BenchmarkInfo {
            bytes_processed,
            duration_ms,
            throughput_mbps,
        })
    } else {
        None
    };

    let result = HashResult {
        filename: display_path,
        hash,
        status: None,
        benchmark_info,
    };

    Ok(result)
}

/// Print result in text format
pub fn print_text_result(result: &HashResult) {
    println!("{}  {}", result.hash, result.filename.display());
    if let Some(bench) = &result.benchmark_info {
        eprintln!(
            "  Benchmark: {} bytes in {} ms ({:.2} MB/s)",
            bench.bytes_processed, bench.duration_ms, bench.throughput_mbps
        );
    }
}

/// Type alias for the result sender to reduce complexity
pub type ProcessResultSender =
    std::sync::mpsc::Sender<(usize, Result<HashResult, (PathBuf, io::Error)>)>;

/// Process multiple files in parallel using rayon
pub fn process_files_parallel(
    files: &[PathBuf],
    config: &config::Config,
    file_counter: Arc<AtomicUsize>,
    tx: ProcessResultSender,
) {
    files.par_iter().enumerate().for_each(|(index, filename)| {
        // Check if file limit reached
        if file_counter.load(Ordering::Relaxed) >= config.max_files {
            // We can't easily break from par_iter, but we can skip processing
            // secure_open_file handles the check too, but let's be safe
        }

        let result = match process_file(filename, config, &file_counter) {
            Ok(r) => Ok(r),
            Err(e) => Err((filename.clone(), e)),
        };

        let _ = tx.send((index, result));
    });
}

// ============================================================================
// Output Formatting Functions
// ============================================================================

/// Escape special characters in strings for JSON output
fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + s.len() / 4);
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            '\x08' => result.push_str("\\b"),
            '\x0C' => result.push_str("\\f"),
            c if c.is_control() => {
                use std::fmt::Write;
                let _ = write!(result, "\\u{:04x}", c as u32);
            }
            c => result.push(c),
        }
    }
    result
}

/// Escape special characters in strings for YAML output
fn escape_yaml_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + s.len() / 4);
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c => result.push(c),
        }
    }
    result
}

/// Convert PathBuf to String, handling non-UTF8 paths gracefully
fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Output results in JSON or YAML format
pub fn output_results_json_yaml(
    results: &[HashResult],
    format: config::OutputFormat,
    check_mode: bool,
) {
    match format {
        config::OutputFormat::Json => {
            println!("{{");
            if check_mode {
                println!("  \"verification_results\": [");
            } else {
                println!("  \"hash_results\": [");
            }
            for (i, res) in results.iter().enumerate() {
                print!(
                    "    {{\"filename\": \"{}\", \"hash\": \"{}\"",
                    escape_json_string(&path_to_string(&res.filename)),
                    res.hash
                );
                if let Some(status) = &res.status {
                    print!(", \"status\": \"{}\"", status.as_str());
                }
                if let Some(bench) = &res.benchmark_info {
                    print!(
                        ", \"bytes_processed\": {}, \"duration_ms\": {}, \"throughput_mbps\": {:.2}",
                        bench.bytes_processed, bench.duration_ms, bench.throughput_mbps
                    );
                }
                if i == results.len() - 1 {
                    println!("}}");
                } else {
                    println!("}},");
                }
            }
            println!("  ]");
            println!("}}");
        }
        config::OutputFormat::Yaml => {
            if check_mode {
                println!("verification_results:");
            } else {
                println!("hash_results:");
            }
            for res in results {
                println!(
                    "  - filename: \"{}\"",
                    escape_yaml_string(&path_to_string(&res.filename))
                );
                println!("    hash: \"{}\"", res.hash);
                if let Some(status) = &res.status {
                    println!("    status: \"{}\"", status.as_str());
                }
                if let Some(bench) = &res.benchmark_info {
                    println!("    bytes_processed: {}", bench.bytes_processed);
                    println!("    duration_ms: {}", bench.duration_ms);
                    println!("    throughput_mbps: {:.2}", bench.throughput_mbps);
                }
            }
        }
        config::OutputFormat::Text => {}
    }
}
