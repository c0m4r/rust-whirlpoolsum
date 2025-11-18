use colored::Colorize;
use std::fs::{canonicalize, File, Metadata};
use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use whirlpool::{Digest, Whirlpool};

/// Detailed errors for checksum line parsing
#[derive(Debug)]
enum ParseError {
    EmptyOrComment,
    TooShort(usize),
    InvalidSeparator(String),
    InvalidHashLength(usize),
    NonHexCharacters(String),
}

const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const DEFAULT_MAX_FILES: usize = 100;
const HASH_SIZE: usize = 64; // 512 bits = 64 bytes
const HASH_HEX_SIZE: usize = HASH_SIZE * 2; // 128 hex characters
const BENCHMARK_FILE_SIZE: usize = 100 * 1024 * 1024; // 100MB

/// Configuration settings for security and resource limits
#[derive(Clone)]
struct Config {
    max_file_size: u64,
    max_files: usize,
    output_format: OutputFormat,
    benchmark: bool,
}

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

/// Parse human-readable size strings (e.g., "512M", "2G")
fn parse_size(size_str: &str) -> io::Result<u64> {
    let size_str = size_str.trim();
    if size_str.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Empty size specification",
        ));
    }

    let (num_str, suffix) =
        if let Some(pos) = size_str.find(|c: char| !c.is_ascii_digit() && c != '.') {
            (&size_str[..pos], &size_str[pos..])
        } else {
            (size_str, "")
        };

    let num: f64 = num_str.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid number in size specification: {}", e),
        )
    })?;

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
    if size > u64::MAX as f64 || size < 0.0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Size value out of range",
        ));
    }

    Ok(size as u64)
}

/// Canonicalize paths without security restrictions
fn safe_canonicalize<P: AsRef<Path>>(path: P) -> io::Result<PathBuf> {
    let path = path.as_ref();

    // Skip validation for standard input
    if path == Path::new("-") {
        return Ok(PathBuf::from("-"));
    }

    // Canonicalize the path (resolves symlinks and normalizes)
    canonicalize(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Failed to access '{}': {}", path.display(), e),
        )
    })
}

/// Secure file opening with size validation
fn secure_open_file<P: AsRef<Path>>(
    path: P,
    config: &Config,
    file_counter: &AtomicUsize,
    metadata: Option<Metadata>,
) -> io::Result<File> {
    let path = path.as_ref();

    // Check file count limit
    let current_count = file_counter.fetch_add(1, Ordering::SeqCst);
    if current_count >= config.max_files {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Maximum file limit reached ({}). Use --max-files to increase.",
                config.max_files
            ),
        ));
    }

    // Get metadata if not provided
    let metadata = match metadata {
        Some(meta) => meta,
        None => path.metadata().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("Failed to access '{}': {}", path.display(), e),
            )
        })?,
    };

    // Skip directories
    if metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("'{}' is a directory", path.display()),
        ));
    }

    // Validate file size
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

    // Open file securely
    File::open(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Failed to open '{}': {}", path.display(), e),
        )
    })
}

fn compute_whirlpool<R: Read>(reader: &mut R) -> io::Result<[u8; HASH_SIZE]> {
    let mut hasher = Whirlpool::new();
    let mut buffer = [0u8; 8192]; // Increased from 4096 for better performance

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

fn compute_whirlpool_with_count<R: Read>(
    reader: &mut R,
    byte_count: &mut u64,
) -> io::Result<[u8; HASH_SIZE]> {
    let mut hasher = Whirlpool::new();
    let mut buffer = [0u8; 8192];
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

fn hash_to_hex(hash: &[u8]) -> String {
    hash.iter().map(|byte| format!("{:02x}", byte)).collect()
}

// --- Structs and Functions for JSON/YAML ---

#[derive(Debug, Clone)]
struct HashResult {
    filename: String,
    hash: String,
    status: Option<VerificationStatus>,    // Only for check mode
    benchmark_info: Option<BenchmarkInfo>, // Only when benchmarking
}

#[derive(Debug, Clone)]
struct BenchmarkInfo {
    bytes_processed: u64,
    duration_ms: u64,
    throughput_mbps: f64,
}

#[derive(Debug, Clone)]
enum VerificationStatus {
    Ok,
    Failed,
    FailedOpenRead,
}

impl VerificationStatus {
    fn as_str(&self) -> &'static str {
        match self {
            VerificationStatus::Ok => "OK",
            VerificationStatus::Failed => "FAILED",
            VerificationStatus::FailedOpenRead => "FAILED_OPEN_READ",
        }
    }
}

fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
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
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

fn escape_yaml_string(s: &str) -> String {
    // For YAML, we'll use double-quoted strings with escaping
    let mut result = String::with_capacity(s.len());
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
                    escape_json_string(&res.filename),
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
                println!("  - filename: \"{}\"", escape_yaml_string(&res.filename));
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
        OutputFormat::Text => {
            // Should not be called for Text format
        }
    }
}

// --- End Structs and Functions ---

fn run_benchmark_test() -> io::Result<()> {
    println!("{}", "=== WHIRLPOOL Benchmark Test ===".green().bold());
    println!("Generating 100 MB of random data...\n");

    // Generate 100MB of data
    let data = vec![0xA5u8; BENCHMARK_FILE_SIZE]; // Use pattern 0xA5 for repeatability
    let mut cursor = Cursor::new(&data);

    println!("Starting benchmark...\n");
    let start = Instant::now();

    let mut hasher = Whirlpool::new();
    let mut buffer = [0u8; 8192];
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

    // Convert hash to hex
    let hash = hash_result
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();

    // Calculate throughput
    let duration_secs = duration.as_secs_f64();
    let throughput_mbps = if duration_secs > 0.0 {
        (bytes_processed as f64 / 1_048_576.0) / duration_secs
    } else {
        0.0
    };

    // Calculate benchmark score
    // Score = (MB/s) * 10, rounded to nearest integer
    // This gives a nice scale where:
    // - Score of 100 = 10 MB/s (slow)
    // - Score of 500 = 50 MB/s (average)
    // - Score of 1000 = 100 MB/s (fast)
    // - Score of 2000+ = 200+ MB/s (very fast)
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
    println!("Hash:             {}", hash.bright_black());
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

fn process_file(
    filename: &str,
    config: &Config,
    file_counter: &AtomicUsize,
) -> io::Result<HashResult> {
    let start_time = if config.benchmark {
        Some(Instant::now())
    } else {
        None
    };

    let (hash, display_filename, bytes_processed) = if filename == "-" {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        let mut bytes = 0u64;
        let hash = if config.benchmark {
            compute_whirlpool_with_count(&mut reader, &mut bytes)?
        } else {
            compute_whirlpool(&mut reader)?
        };
        (hash_to_hex(&hash), "-".to_string(), bytes)
    } else {
        let path = Path::new(filename);
        let canonical_path = safe_canonicalize(path)?;

        let metadata = canonical_path.metadata().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("Failed to access '{}': {}", canonical_path.display(), e),
            )
        })?;

        let file_size = metadata.len();
        let file = secure_open_file(&canonical_path, config, file_counter, Some(metadata))?;

        let mut reader = BufReader::new(file);
        let mut bytes = 0u64;
        let hash = if config.benchmark {
            compute_whirlpool_with_count(&mut reader, &mut bytes)?
        } else {
            compute_whirlpool(&mut reader)?
        };
        (
            hash_to_hex(&hash),
            filename.to_string(),
            if config.benchmark { bytes } else { file_size },
        )
    };

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
        filename: display_filename.clone(),
        hash: hash.clone(),
        status: None,
        benchmark_info: benchmark_info.clone(),
    };

    if config.output_format == OutputFormat::Text {
        println!("{}  {}", hash, display_filename);
        if let Some(bench) = &benchmark_info {
            eprintln!(
                "  Benchmark: {} bytes in {} ms ({:.2} MB/s)",
                bench.bytes_processed, bench.duration_ms, bench.throughput_mbps
            );
        }
    }

    Ok(result)
}

fn process_files_parallel(
    files: &[String],
    config: &Config,
    file_counter: Arc<AtomicUsize>,
) -> Vec<Result<HashResult, (String, io::Error)>> {
    let num_threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(files.len());

    let results = Arc::new(Mutex::new(Vec::with_capacity(files.len())));
    let mut handles = vec![];

    // Split files into chunks for each thread
    let chunk_size = (files.len() + num_threads - 1) / num_threads;

    for chunk in files.chunks(chunk_size) {
        let chunk = chunk.to_vec();
        let config = config.clone();
        let file_counter = Arc::clone(&file_counter);
        let results = Arc::clone(&results);

        let handle = thread::spawn(move || {
            for (idx, filename) in chunk.iter().enumerate() {
                // Check if we've exceeded the file limit
                if file_counter.load(Ordering::SeqCst) >= config.max_files {
                    break;
                }

                let result = match process_file(filename, &config, &file_counter) {
                    Ok(r) => Ok(r),
                    Err(e) => Err((filename.clone(), e)),
                };

                let mut results = results.lock().unwrap();
                results.push((idx, result));
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        let _ = handle.join();
    }

    // Sort results to maintain original file order
    let mut results = Arc::try_unwrap(results)
        .expect("Failed to unwrap results")
        .into_inner()
        .unwrap();

    results.sort_by_key(|(idx, _)| *idx);

    results.into_iter().map(|(_, result)| result).collect()
}

fn parse_checksum_line(line: &str) -> Result<(&str, &str), ParseError> {
    let line = line.trim();

    if line.is_empty() || line.starts_with('#') {
        return Err(ParseError::EmptyOrComment);
    }

    if line.len() < HASH_HEX_SIZE + 1 {
        return Err(ParseError::TooShort(line.len()));
    }

    let (hash_part, rest) = line.split_at(HASH_HEX_SIZE);

    // Validate the hash part
    if hash_part.len() != HASH_HEX_SIZE {
        return Err(ParseError::InvalidHashLength(hash_part.len()));
    }

    if let Some(non_hex) = hash_part.chars().find(|&c| !c.is_ascii_hexdigit()) {
        return Err(ParseError::NonHexCharacters(format!(
            "character '{}' at position {}",
            non_hex,
            hash_part.find(non_hex).unwrap_or(0)
        )));
    }

    // Check separator and filename
    if rest.is_empty() {
        return Err(ParseError::TooShort(line.len()));
    }

    // Allow single space, double space, or space+asterisk as separators
    let filename = if rest.starts_with("  ") {
        rest[2..].trim_start()
    } else if rest.starts_with(" *") {
        rest[2..].trim_start()
    } else if rest.starts_with(' ') {
        rest[1..].trim_start()
    } else {
        return Err(ParseError::InvalidSeparator(rest.chars().take(2).collect()));
    };

    if filename.is_empty() {
        return Err(ParseError::TooShort(line.len()));
    }

    Ok((hash_part, filename))
}

fn check_checksums(
    checksum_source: &str,
    config: &Config,
    status_only: bool,
    warn: bool,
    quiet: bool,
) -> io::Result<i32> {
    let file_counter = AtomicUsize::new(0);
    let checksum_path = Path::new(checksum_source);
    let reader: Box<dyn BufRead> = if checksum_source == "-" {
        Box::new(BufReader::new(io::stdin()))
    } else {
        let canonical_checksum_path = safe_canonicalize(checksum_path)?;
        let checksum_file =
            secure_open_file(&canonical_checksum_path, config, &file_counter, None)?;
        Box::new(BufReader::new(checksum_file))
    };

    let mut failed = 0;
    let mut total = 0;
    let mut invalid_lines = 0;
    let mut results = Vec::new(); // Collect results for structured output

    for (line_num, line_result) in reader.lines().enumerate() {
        let line_num = line_num + 1;
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

        match parse_checksum_line(&line) {
            Ok((expected_hash, filename)) => {
                total += 1;

                // Validate and open target file securely
                let target_path = Path::new(filename);
                let canonical_target = safe_canonicalize(target_path)?;

                let result = File::open(&canonical_target)
                    .and_then(|file| {
                        let metadata = file.metadata()?;
                        secure_open_file(&canonical_target, config, &file_counter, Some(metadata))
                    })
                    .map_err(|e| format!("{}", e))
                    .and_then(|file| {
                        let mut reader = BufReader::new(file);
                        compute_whirlpool(&mut reader)
                            .map(|hash| hash_to_hex(&hash))
                            .map_err(|e| format!("hash computation failed: {}", e))
                    });

                match result {
                    Ok(actual_hash) => {
                        let status = if actual_hash.to_lowercase() == expected_hash.to_lowercase() {
                            if !status_only && !quiet && config.output_format == OutputFormat::Text
                            {
                                println!("{}: OK", filename);
                            }
                            VerificationStatus::Ok
                        } else {
                            failed += 1;
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
                            filename: filename.to_string(),
                            hash: actual_hash,
                            status: Some(status),
                            benchmark_info: None,
                        });
                    }
                    Err(err) => {
                        failed += 1;
                        if !status_only && config.output_format == OutputFormat::Text {
                            eprintln!("{}: FAILED open or read - {}", filename, err);
                        }
                        results.push(HashResult {
                            filename: filename.to_string(),
                            hash: expected_hash.to_string(),
                            status: Some(VerificationStatus::FailedOpenRead),
                            benchmark_info: None,
                        });
                    }
                }
            }
            Err(err) => {
                invalid_lines += 1;
                if !status_only && config.output_format == OutputFormat::Text {
                    let source_name = if checksum_source == "-" {
                        "standard input"
                    } else {
                        checksum_source
                    };

                    match err {
                        ParseError::EmptyOrComment => {
                            // Quietly ignore empty lines and comments
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

    // Output structured results if needed
    if config.output_format == OutputFormat::Json || config.output_format == OutputFormat::Yaml {
        output_results_json_yaml(&results, config.output_format, true); // true for check mode
    }

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

    Ok(if failed > 0 || invalid_lines > 0 {
        1
    } else {
        0
    })
}

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

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1).peekable();
    let mut config = Config::default();
    let mut check_mode = false;
    let mut status_only = false;
    let mut warn = false;
    let mut quiet = false;
    let mut files = Vec::new();

    // Parse command line arguments
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--check" => check_mode = true,
            "--status" => status_only = true,
            "--warn" => warn = true,
            "-q" | "--quiet" => quiet = true,
            "--benchmark" => config.benchmark = true,
            "--max-file-size" => {
                if let Some(size_arg) = args.next() {
                    config.max_file_size = parse_size(&size_arg)?;
                } else {
                    eprintln!("error: --max-file-size requires a size argument");
                    process::exit(2);
                }
            }
            "--max-files" => {
                if let Some(count_arg) = args.next() {
                    config.max_files = count_arg.parse().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("Invalid file count: {}", count_arg),
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
                files.extend(args);
                break;
            }
            _ if arg.starts_with('-') => {
                eprintln!("whirlpoolsum: unrecognized option '{}'", arg);
                eprintln!("Try 'whirlpoolsum --help' for more information.");
                process::exit(2);
            }
            _ => files.push(arg),
        }
    }

    // Validate resource limits
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

    let file_counter = Arc::new(AtomicUsize::new(0));

    // Special case: benchmark mode with no files runs a benchmark test
    if config.benchmark && files.is_empty() && !check_mode {
        return run_benchmark_test();
    }

    let exit_code = if check_mode {
        if files.is_empty() {
            if !status_only && !quiet && config.output_format == OutputFormat::Text {
                println!("Verifying checksums from standard input...");
            }
            check_checksums("-", &config, status_only, warn, quiet)?
        } else if files.len() == 1 {
            if !status_only && !quiet && config.output_format == OutputFormat::Text {
                println!("Verifying checksums from file: {}", files[0]);
            }
            check_checksums(&files[0], &config, status_only, warn, quiet)?
        } else {
            eprintln!("whirlpoolsum: only one checksum file allowed in check mode");
            process::exit(2);
        }
    } else {
        // Generation mode
        let mut exit_code = 0;

        if files.is_empty() {
            let result = process_file("-", &config, &file_counter)?;
            if config.output_format != OutputFormat::Text {
                output_results_json_yaml(&[result], config.output_format, false);
            }
        } else if files.len() == 1 {
            // Single file - no need for multithreading
            match process_file(&files[0], &config, &file_counter) {
                Ok(result) => {
                    if config.output_format != OutputFormat::Text {
                        output_results_json_yaml(&[result], config.output_format, false);
                    }
                }
                Err(e) => {
                    eprintln!("whirlpoolsum: {}: {}", files[0], e);
                    exit_code = 1;
                }
            }
        } else {
            // Multiple files - use multithreading
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
                        eprintln!("whirlpoolsum: {}: {}", filename, e);
                        exit_code = 1;
                    }
                }
            }

            // Check if we hit the file limit
            if file_counter.load(Ordering::SeqCst) >= config.max_files {
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

    if exit_code != 0 {
        process::exit(exit_code);
    }
    Ok(())
}
