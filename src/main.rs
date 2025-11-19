use colored::Colorize;
use std::ffi::OsString;
use std::fs::{canonicalize, File, Metadata};
use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use whirlpool::{Digest, Whirlpool};

// ============================================================================
// Error Types
// ============================================================================

/// Detailed errors for checksum line parsing
#[derive(Debug)]
enum ParseError {
    EmptyOrComment,
    TooShort(usize),
    InvalidSeparator(String),
    InvalidHashLength(usize),
    NonHexCharacters(String),
}

// ============================================================================
// Constants
// ============================================================================

/// Default maximum file size (1GB) - prevents DoS via large files
const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;
/// Default maximum number of files - prevents DoS via many files
const DEFAULT_MAX_FILES: usize = 100;
/// WHIRLPOOL-512 produces 64 bytes (512 bits)
const HASH_SIZE: usize = 64;
/// Hash in hexadecimal format is 128 characters
const HASH_HEX_SIZE: usize = HASH_SIZE * 2;
/// Size of data used for benchmark testing (100MB)
const BENCHMARK_FILE_SIZE: usize = 100 * 1024 * 1024;
/// Optimal buffer size for I/O operations (64KB)
const BUFFER_SIZE: usize = 65536;
/// Standard separator: two spaces
const HASH_SEPARATOR_DOUBLE: &str = "  ";
/// BSD-style separator: space followed by asterisk
const HASH_SEPARATOR_ASTERISK: &str = " *";

// ============================================================================
// Configuration Structures
// ============================================================================

/// Configuration settings for security and resource limits
#[derive(Clone)]
struct Config {
    /// Maximum allowed size for individual files
    max_file_size: u64,
    /// Maximum number of files to process
    max_files: usize,
    /// Output format (text, JSON, or YAML)
    output_format: OutputFormat,
    /// Whether to show performance benchmarks
    benchmark: bool,
}

/// Available output formats for results
#[derive(Debug, Clone, Copy, PartialEq)]
enum OutputFormat {
    Text,
    Json,
    Yaml,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            max_files: DEFAULT_MAX_FILES,
            output_format: OutputFormat::Text,
            benchmark: false,
        }
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Parse human-readable size strings (e.g., "512M", "2G")
/// 
/// Supports suffixes: B, KB, MB, GB, TB (case-insensitive)
/// Examples: "1024", "512M", "2.5G"
fn parse_size(size_str: &str) -> io::Result<u64> {
    let size_str = size_str.trim();
    if size_str.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Empty size specification",
        ));
    }

    // Split into numeric part and suffix
    let (num_str, suffix) =
        if let Some(pos) = size_str.find(|c: char| !c.is_ascii_digit() && c != '.') {
            (&size_str[..pos], &size_str[pos..])
        } else {
            (size_str, "")
        };

    // Parse the numeric value
    let num: f64 = num_str.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid number in size specification: {}", e),
        )
    })?;

    if num < 0.0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Size cannot be negative",
        ));
    }

    // Determine multiplier based on suffix
    let multiplier = match suffix.to_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1024.0,
        "m" | "mb" => 1024.0 * 1024.0,
        "g" | "gb" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unknown size suffix: {}", suffix),
            ))
        }
    };

    let size = num * multiplier;
    if size > u64::MAX as f64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Size value out of range",
        ));
    }

    Ok(size as u64)
}

/// Canonicalize paths, resolving symlinks and normalizing
/// 
/// Special handling for "-" (stdin) which is returned as-is
fn safe_canonicalize<P: AsRef<Path>>(path: P) -> io::Result<PathBuf> {
    let path = path.as_ref();

    // Skip canonicalization for standard input
    if path == Path::new("-") {
        return Ok(PathBuf::from("-"));
    }

    // Resolve symlinks and normalize path
    canonicalize(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Failed to access '{}': {}", path.display(), e),
        )
    })
}

// ============================================================================
// File Security and Validation
// ============================================================================

/// Secure file opening with size validation and resource limits
/// 
/// Enforces:
/// - Maximum file count to prevent DoS
/// - Maximum file size to prevent memory exhaustion
/// - Rejects directories
/// 
/// # Arguments
/// * `path` - Path to the file to open
/// * `config` - Configuration with security limits
/// * `file_counter` - Atomic counter to track number of opened files
/// * `metadata` - Optional pre-fetched metadata (avoids double stat)
fn secure_open_file<P: AsRef<Path>>(
    path: P,
    config: &Config,
    file_counter: &AtomicUsize,
    metadata: Option<Metadata>,
) -> io::Result<File> {
    let path = path.as_ref();

    // Check if we've exceeded the maximum file limit
    let current_count = file_counter.fetch_add(1, Ordering::Relaxed);
    if current_count >= config.max_files {
        return Err(io::Error::other(format!(
            "Maximum file limit reached ({}). Use --max-files to increase.",
            config.max_files
        )));
    }

    // Get or use provided metadata
    let metadata = match metadata {
        Some(meta) => meta,
        None => path.metadata().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("Failed to access '{}': {}", path.display(), e),
            )
        })?,
    };

    // Reject directories
    if metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("'{}' is a directory", path.display()),
        ));
    }

    // Validate file size against configured maximum
    let file_size = metadata.len();
    if file_size > config.max_file_size {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            format!(
                "File '{}' exceeds maximum size limit of {} bytes",
                path.display(),
                config.max_file_size
            ),
        ));
    }

    // Open the file
    File::open(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Failed to open '{}': {}", path.display(), e),
        )
    })
}

// ============================================================================
// Cryptographic Hash Functions
// ============================================================================

/// Compute WHIRLPOOL-512 hash of data from a reader
/// 
/// # Arguments
/// * `reader` - Any type implementing Read trait
/// 
/// # Returns
/// 64-byte (512-bit) hash as a fixed-size array
fn compute_whirlpool<R: Read>(reader: &mut R) -> io::Result<[u8; HASH_SIZE]> {
    let mut hasher = Whirlpool::new();
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash_result = hasher.finalize();
    let mut hash_bytes = [0u8; HASH_SIZE];
    hash_bytes.copy_from_slice(&hash_result);
    Ok(hash_bytes)
}

/// Compute WHIRLPOOL-512 hash while tracking the number of bytes processed
/// 
/// Used for benchmarking to measure throughput
/// 
/// # Arguments
/// * `reader` - Any type implementing Read trait
/// * `byte_count` - Mutable reference to store total bytes processed
fn compute_whirlpool_with_count<R: Read>(
    reader: &mut R,
    byte_count: &mut u64,
) -> io::Result<[u8; HASH_SIZE]> {
    let mut hasher = Whirlpool::new();
    let mut buffer = [0u8; BUFFER_SIZE];
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
    let mut hash_bytes = [0u8; HASH_SIZE];
    hash_bytes.copy_from_slice(&hash_result);
    Ok(hash_bytes)
}

/// Convert binary hash to hexadecimal string representation
/// 
/// Pre-allocates string with exact required capacity for efficiency
fn hash_to_hex(hash: &[u8]) -> String {
    hash.iter()
        .fold(String::with_capacity(HASH_HEX_SIZE), |mut acc, byte| {
            use std::fmt::Write;
            let _ = write!(acc, "{:02x}", byte);
            acc
        })
}

// ============================================================================
// Result Structures
// ============================================================================

/// Result of hashing or verifying a single file
#[derive(Debug, Clone)]
struct HashResult {
    /// Path to the file (or "-" for stdin)
    filename: PathBuf,
    /// Hexadecimal hash string
    hash: String,
    /// Verification status (only for check mode)
    status: Option<VerificationStatus>,
    /// Benchmark information (only when benchmarking)
    benchmark_info: Option<BenchmarkInfo>,
}

/// Performance metrics for benchmark mode
#[derive(Debug, Clone)]
struct BenchmarkInfo {
    /// Total bytes processed
    bytes_processed: u64,
    /// Time taken in milliseconds
    duration_ms: u64,
    /// Throughput in megabytes per second
    throughput_mbps: f64,
}

/// Status of checksum verification
#[derive(Debug, Clone)]
enum VerificationStatus {
    /// Hash matched expected value
    Ok,
    /// Hash did not match
    Failed,
    /// Could not open or read the file
    FailedOpenRead,
}

impl VerificationStatus {
    /// Convert status to string representation
    fn as_str(&self) -> &'static str {
        match self {
            VerificationStatus::Ok => "OK",
            VerificationStatus::Failed => "FAILED",
            VerificationStatus::FailedOpenRead => "FAILED_OPEN_READ",
        }
    }
}

// ============================================================================
// Output Formatting Functions
// ============================================================================

/// Escape special characters in strings for JSON output
/// 
/// Handles: quotes, backslashes, control characters, unicode escapes
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
/// 
/// Uses double-quoted string format with minimal escaping
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
/// 
/// # Arguments
/// * `results` - Collection of hash results to output
/// * `format` - Desired output format
/// * `check_mode` - Whether results are from verification (vs generation)
fn output_results_json_yaml(results: &[HashResult], format: OutputFormat, check_mode: bool) {
    match format {
        OutputFormat::Json => {
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
        OutputFormat::Yaml => {
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
        OutputFormat::Text => {}
    }
}

// ============================================================================
// Benchmark Test Function
// ============================================================================

/// Run a standardized benchmark test with 100MB of data
/// 
/// Tests hashing performance and provides a scored rating
/// Score calculation: (MB/s) * 10
/// Ratings: A++ (2000+), A+ (1000+), A (500+), B (250+), C (100+), D (<100)
fn run_benchmark_test() -> io::Result<()> {
    println!("{}", "=== WHIRLPOOL Benchmark Test ===".green().bold());
    println!("Generating 100 MB of random data...\n");

    // Generate test data (pattern 0xA5 for repeatability)
    let data = vec![0xA5u8; BENCHMARK_FILE_SIZE];
    let mut cursor = Cursor::new(&data);

    println!("Starting benchmark...\n");
    let start = Instant::now();

    // Perform hash computation
    let mut hasher = Whirlpool::new();
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut bytes_processed = 0u64;

    loop {
        let bytes_read = cursor.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
        bytes_processed += bytes_read as u64;
    }

    let hash_result = hasher.finalize();
    let duration = start.elapsed();

    // Calculate performance metrics
    let duration_secs = duration.as_secs_f64();
    let throughput_mbps = if duration_secs > 0.0 {
        (bytes_processed as f64 / 1_048_576.0) / duration_secs
    } else {
        0.0
    };

    // Calculate benchmark score (MB/s * 10)
    let score = (throughput_mbps * 10.0).round() as u64;

    // Determine performance rating
    let rating = if score >= 2000 {
        "A++".bright_magenta().bold()
    } else if score >= 1000 {
        "A+".bright_green().bold()
    } else if score >= 500 {
        "A".green()
    } else if score >= 250 {
        "B".yellow()
    } else if score >= 100 {
        "C".bright_red()
    } else {
        "D".red().bold()
    };

    // Display results
    println!("{}", "Benchmark Results:".green().bold());
    println!("═════════════════════════════════════════════════════");
    println!("Data size:        {} bytes (100 MB)", bytes_processed);
    println!(
        "Hash:             {}",
        hash_to_hex(hash_result.as_slice()).bright_black()
    );
    println!();
    println!("{}", "Timing:".yellow().bold());
    println!("  Seconds:        {:.9} s", duration.as_secs_f64());
    println!("  Milliseconds:   {} ms", duration.as_millis());
    println!("  Microseconds:   {} μs", duration.as_micros());
    println!("  Nanoseconds:    {} ns", duration.as_nanos());
    println!();
    println!("{}", "Performance:".cyan().bold());
    println!("  Throughput:     {:.2} MB/s", throughput_mbps);
    println!();
    println!("{}", "Benchmark Score:".bright_cyan().bold());
    println!(
        "  Score:          {} points",
        score.to_string().bright_white().bold()
    );
    println!("  Rating:         {}", rating);
    println!("═════════════════════════════════════════════════════");
    Ok(())
}

// ============================================================================
// File Processing Functions
// ============================================================================

/// Process a single file and compute its WHIRLPOOL hash
/// 
/// Handles both regular files and stdin (when filename is "-")
/// Optionally collects benchmark metrics if enabled
/// 
/// # Arguments
/// * `filename` - Path to file or "-" for stdin
/// * `config` - Configuration including benchmark flag
/// * `file_counter` - Atomic counter for resource tracking
fn process_file(
    filename: &OsString,
    config: &Config,
    file_counter: &AtomicUsize,
) -> io::Result<HashResult> {
    // Start timing if benchmarking is enabled
    let start_time = if config.benchmark {
        Some(Instant::now())
    } else {
        None
    };

    // Process stdin or regular file
    let (hash, display_path, bytes_processed) = if filename == "-" {
        let stdin = io::stdin();
        let mut reader = BufReader::with_capacity(BUFFER_SIZE, stdin.lock());
        let mut bytes = 0u64;
        let hash = if config.benchmark {
            compute_whirlpool_with_count(&mut reader, &mut bytes)?
        } else {
            compute_whirlpool(&mut reader)?
        };
        (hash_to_hex(&hash), PathBuf::from("-"), bytes)
    } else {
        let path = Path::new(filename);
        let canonical_path = safe_canonicalize(path)?;

        // Get file metadata for security checks
        let metadata = canonical_path.metadata().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("Failed to access '{}': {}", canonical_path.display(), e),
            )
        })?;

        let file_size = metadata.len();
        let file = secure_open_file(&canonical_path, config, file_counter, Some(metadata))?;

        let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
        let mut bytes = 0u64;
        let hash = if config.benchmark {
            compute_whirlpool_with_count(&mut reader, &mut bytes)?
        } else {
            compute_whirlpool(&mut reader)?
        };
        (
            hash_to_hex(&hash),
            PathBuf::from(filename),
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
        filename: display_path.clone(),
        hash: hash.clone(),
        status: None,
        benchmark_info: benchmark_info.clone(),
    };

    // Output result in text format
    if config.output_format == OutputFormat::Text {
        println!("{}  {}", hash, display_path.display());
        if let Some(bench) = &benchmark_info {
            eprintln!(
                "  Benchmark: {} bytes in {} ms ({:.2} MB/s)",
                bench.bytes_processed, bench.duration_ms, bench.throughput_mbps
            );
        }
    }

    Ok(result)
}

/// Process multiple files in parallel using thread pool
/// 
/// Distributes files across available CPU cores for better performance
/// Each thread processes its chunk independently, then results are merged
/// 
/// # Arguments
/// * `files` - Vector of file paths to process
/// * `config` - Configuration settings
/// * `file_counter` - Shared atomic counter for resource limits
fn process_files_parallel(
    files: &[OsString],
    config: &Config,
    file_counter: Arc<AtomicUsize>,
) -> Vec<Result<HashResult, (OsString, io::Error)>> {
    // Determine optimal thread count
    let num_threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(files.len())
        .max(1);

    let mut handles = vec![];
    let chunk_size = files.len().div_ceil(num_threads);

    // Spawn threads for each chunk of files
    for (chunk_idx, chunk) in files.chunks(chunk_size).enumerate() {
        let chunk = chunk.to_vec();
        let config = config.clone();
        let file_counter = Arc::clone(&file_counter);
        let base_idx = chunk_idx * chunk_size;

        let handle = thread::spawn(move || {
            // Process files in this thread, collecting results locally
            let mut local_results = Vec::with_capacity(chunk.len());
            for (idx, filename) in chunk.iter().enumerate() {
                // Check if file limit reached
                if file_counter.load(Ordering::Relaxed) >= config.max_files {
                    break;
                }

                let result = match process_file(filename, &config, &file_counter) {
                    Ok(r) => Ok(r),
                    Err(e) => Err((filename.clone(), e)),
                };

                local_results.push((base_idx + idx, result));
            }
            local_results
        });

        handles.push(handle);
    }

    // Collect results from all threads
    let mut all_results = Vec::with_capacity(files.len());
    for handle in handles {
        if let Ok(local_results) = handle.join() {
            all_results.extend(local_results);
        }
    }

    // Sort by original file order
    all_results.sort_by_key(|(idx, _)| *idx);
    all_results.into_iter().map(|(_, result)| result).collect()
}

// ============================================================================
// Checksum Verification Functions
// ============================================================================

/// Parse a line from a checksum file
/// 
/// Expected format: <128 hex chars><separator><filename>
/// Separators: "  " (two spaces), " *" (space+asterisk), or " " (single space)
/// 
/// # Arguments
/// * `line` - Line from checksum file
/// 
/// # Returns
/// Tuple of (hash_string, filename) on success
fn parse_checksum_line(line: &str) -> Result<(&str, &str), ParseError> {
    let line = line.trim();

    // Skip empty lines and comments
    if line.is_empty() || line.starts_with('#') {
        return Err(ParseError::EmptyOrComment);
    }

    // Check minimum length (hash + separator + at least 1 char filename)
    if line.len() < HASH_HEX_SIZE + 1 {
        return Err(ParseError::TooShort(line.len()));
    }

    // Extract hash and remainder
    let (hash_part, rest) = line.split_at(HASH_HEX_SIZE);

    // Validate hash length
    if hash_part.len() != HASH_HEX_SIZE {
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
    let filename = if let Some(stripped) = rest.strip_prefix(HASH_SEPARATOR_DOUBLE) {
        stripped.trim_start()
    } else if let Some(stripped) = rest.strip_prefix(HASH_SEPARATOR_ASTERISK) {
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
/// 
/// Reads a file containing hash + filename pairs and verifies each file's hash
/// Supports various output modes: normal, status-only, quiet, with warnings
/// 
/// # Arguments
/// * `checksum_source` - Path to checksum file or "-" for stdin
/// * `config` - Configuration settings
/// * `status_only` - Only return exit code, no output
/// * `warn` - Show warnings for malformed lines
/// * `quiet` - Don't print OK for successful verifications
/// 
/// # Returns
/// Exit code: 0 for success, 1 for failures
fn check_checksums(
    checksum_source: &str,
    config: &Config,
    status_only: bool,
    warn: bool,
    quiet: bool,
) -> io::Result<i32> {
    let file_counter = AtomicUsize::new(0);
    let checksum_path = Path::new(checksum_source);
    
    // Open checksum file or use stdin
    let reader: Box<dyn BufRead> = if checksum_source == "-" {
        Box::new(BufReader::with_capacity(BUFFER_SIZE, io::stdin()))
    } else {
        let canonical_checksum_path = safe_canonicalize(checksum_path)?;
        let checksum_file =
            secure_open_file(&canonical_checksum_path, config, &file_counter, None)?;
        Box::new(BufReader::with_capacity(BUFFER_SIZE, checksum_file))
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
            return Ok(1);
        }

        // Read line from file
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                invalid_lines += 1;
                if !status_only && config.output_format == OutputFormat::Text {
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
                let canonical_target = safe_canonicalize(target_path)?;

                // Attempt to open file and compute hash
                let result = File::open(&canonical_target)
                    .and_then(|file| {
                        let metadata = file.metadata()?;
                        secure_open_file(&canonical_target, config, &file_counter, Some(metadata))
                    })
                    .map_err(|e| format!("{}", e))
                    .and_then(|file| {
                        let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
                        compute_whirlpool(&mut reader)
                            .map(|hash| hash_to_hex(&hash))
                            .map_err(|e| format!("hash computation failed: {}", e))
                    });

                // Compare computed hash with expected hash
                match result {
                    Ok(actual_hash) => {
                        let status = if actual_hash.eq_ignore_ascii_case(expected_hash) {
                            // Hash matches - file verified successfully
                            if !status_only && !quiet && config.output_format == OutputFormat::Text
                            {
                                println!("{}: OK", filename);
                            }
                            VerificationStatus::Ok
                        } else {
                            // Hash mismatch - verification failed
                            failed += 1;
                            has_failed.store(true, Ordering::Relaxed);
                            if !status_only && config.output_format == OutputFormat::Text {
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
                        if !status_only && config.output_format == OutputFormat::Text {
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
            }
            Err(err) => {
                // Line parsing failed - malformed checksum line
                invalid_lines += 1;
                if !status_only && config.output_format == OutputFormat::Text {
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

    // Output structured results if JSON or YAML format requested
    if config.output_format == OutputFormat::Json || config.output_format == OutputFormat::Yaml {
        output_results_json_yaml(&results, config.output_format, true);
    }

    // Print summary statistics in text mode
    if !status_only && config.output_format == OutputFormat::Text {
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

    // Return exit code
    Ok(if failed > 0 || invalid_lines > 0 {
        1
    } else {
        0
    })
}

// ============================================================================
// Help and Documentation
// ============================================================================

/// Print comprehensive help message with usage information
fn print_help() {
    let version = env!("CARGO_PKG_VERSION");
    let license = env!("CARGO_PKG_LICENSE");
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    let _ = stdout.write_all(
        format!(
            "whirlpoolsum v{} by Qwen3-Max & c0m4r
https://github.com/c0m4r/rust-whirlpoolsum/  
  
LICENSE: {}

Usage: whirlpoolsum [OPTION]... [FILE]...
Print or check WHIRLPOOL (512-bit) checksums.

With no FILE, or when FILE is -, read standard input.

Options:
  -c, --check       read WHIRLPOOL sums from FILEs and check them
      --status      don't output anything, status code shows success
      --warn        warn about improperly formatted checksum lines
  -q, --quiet       don't print OK for each successfully verified file
      --benchmark   show performance metrics (time and throughput)
      --max-file-size SIZE     set maximum file size (default: 1G)
      --max-files COUNT        set maximum number of files (default: 100)
      --json        output results in JSON format
      --yaml        output results in YAML format
  -h, --help        display this help and exit

SIZE format examples: 512M, 1G, 2.5GB

Format of checksum file lines:
  <128 hex characters><space(s)><filename>
  Example: b867ae736a...  filename.txt
  Accepts one space, two spaces, or space+asterisk as separator

Exit status:
  0 = all checksums matched (or successfully generated)
  1 = some checksums failed or files not found
  2 = invalid command line arguments
  3 = resource limits exceeded

Current configuration:
  Maximum file size: {}
  Maximum files: {}
  Output format: {:?}\n",
            version.green(),
            license,
            DEFAULT_MAX_FILE_SIZE,
            DEFAULT_MAX_FILES,
            OutputFormat::Text
        )
        .as_bytes(),
    );
}

// ============================================================================
// Main Entry Point
// ============================================================================

/// Main function - parses arguments and dispatches to appropriate operations
fn main() -> io::Result<()> {
    // Parse command-line arguments using OsString for non-UTF8 path support
    let mut args = std::env::args_os().skip(1).peekable();
    let mut config = Config::default();
    let mut check_mode = false;
    let mut status_only = false;
    let mut warn = false;
    let mut quiet = false;
    let mut files = Vec::new();

    // Process command-line arguments
    while let Some(arg) = args.next() {
        let arg_str = arg.to_string_lossy();
        match arg_str.as_ref() {
            "-c" | "--check" => check_mode = true,
            "--status" => status_only = true,
            "--warn" => warn = true,
            "-q" | "--quiet" => quiet = true,
            "--benchmark" => config.benchmark = true,
            "--max-file-size" => {
                if let Some(size_arg) = args.next() {
                    config.max_file_size = parse_size(&size_arg.to_string_lossy())?;
                } else {
                    eprintln!("error: --max-file-size requires a size argument");
                    process::exit(2);
                }
            }
            "--max-files" => {
                if let Some(count_arg) = args.next() {
                    let count_str = count_arg.to_string_lossy();
                    config.max_files = count_str.parse().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("Invalid file count: {}", count_str),
                        )
                    })?;
                } else {
                    eprintln!("error: --max-files requires a count argument");
                    process::exit(2);
                }
            }
            "--json" => config.output_format = OutputFormat::Json,
            "--yaml" => config.output_format = OutputFormat::Yaml,
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            "--" => {
                // Everything after -- is treated as filenames
                files.extend(args);
                break;
            }
            _ if arg_str.starts_with('-') => {
                eprintln!("whirlpoolsum: unrecognized option '{}'", arg_str);
                eprintln!("Try 'whirlpoolsum --help' for more information.");
                process::exit(2);
            }
            _ => files.push(arg),
        }
    }

    // Validate configuration
    if config.max_file_size == 0 {
        eprintln!("error: maximum file size cannot be zero");
        process::exit(2);
    }
    if config.max_files == 0 {
        eprintln!("error: maximum file count cannot be zero");
        process::exit(2);
    }

    // Validate conflicting options
    if config.output_format != OutputFormat::Text && status_only {
        eprintln!("error: --json/--yaml cannot be used with --status");
        process::exit(2);
    }
    if config.output_format != OutputFormat::Text && quiet && !check_mode {
        eprintln!("error: --json/--yaml cannot be used with -q/--quiet in generation mode");
        process::exit(2);
    }
    if config.benchmark && check_mode {
        eprintln!("error: --benchmark cannot be used with --check");
        process::exit(2);
    }

    // Initialize shared file counter for resource tracking
    let file_counter = Arc::new(AtomicUsize::new(0));

    // Special case: benchmark mode with no files runs a benchmark test
    if config.benchmark && files.is_empty() && !check_mode {
        return run_benchmark_test();
    }

    // Execute appropriate operation based on mode
    let exit_code = if check_mode {
        // Checksum verification mode
        if files.is_empty() {
            // Read from stdin
            if !status_only && !quiet && config.output_format == OutputFormat::Text {
                println!("Verifying checksums from standard input...");
            }
            check_checksums("-", &config, status_only, warn, quiet)?
        } else if files.len() == 1 {
            // Read from single file
            let filename = files[0].to_string_lossy();
            if !status_only && !quiet && config.output_format == OutputFormat::Text {
                println!("Verifying checksums from file: {}", filename);
            }
            check_checksums(&filename, &config, status_only, warn, quiet)?
        } else {
            // Multiple checksum files not allowed
            eprintln!("whirlpoolsum: only one checksum file allowed in check mode");
            process::exit(2);
        }
    } else {
        // Hash generation mode
        let mut exit_code = 0;

        if files.is_empty() {
            // Hash from stdin
            let result = process_file(&OsString::from("-"), &config, &file_counter)?;
            if config.output_format != OutputFormat::Text {
                output_results_json_yaml(&[result], config.output_format, false);
            }
        } else if files.len() == 1 {
            // Hash single file
            match process_file(&files[0], &config, &file_counter) {
                Ok(result) => {
                    if config.output_format != OutputFormat::Text {
                        output_results_json_yaml(&[result], config.output_format, false);
                    }
                }
                Err(e) => {
                    eprintln!("whirlpoolsum: {}: {}", files[0].to_string_lossy(), e);
                    exit_code = 1;
                }
            }
        } else {
            // Hash multiple files in parallel
            let results = process_files_parallel(&files, &config, Arc::clone(&file_counter));

            let mut collected_results = Vec::new();
            for result in results {
                match result {
                    Ok(hash_result) => {
                        if config.output_format != OutputFormat::Text {
                            collected_results.push(hash_result);
                        }
                    }
                    Err((filename, e)) => {
                        eprintln!("whirlpoolsum: {}: {}", filename.to_string_lossy(), e);
                        exit_code = 1;
                    }
                }
            }

            // Check if file limit was reached
            if file_counter.load(Ordering::Relaxed) >= config.max_files {
                eprintln!(
                    "whirlpoolsum: maximum file limit reached ({}). Some files were skipped.",
                    config.max_files
                );
                exit_code = 3;
            }

            // Output structured results if needed
            if config.output_format == OutputFormat::Json
                || config.output_format == OutputFormat::Yaml
            {
                output_results_json_yaml(&collected_results, config.output_format, false);
            }
        }

        exit_code
    };

    // Exit with appropriate code
    if exit_code != 0 {
        process::exit(exit_code);
    }
    Ok(())
}
