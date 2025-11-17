use std::fs::{canonicalize, File, Metadata};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};
use whirlpool::{Digest, Whirlpool};
use colored::Colorize;

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

/// Configuration settings for security and resource limits
struct Config {
    max_file_size: u64,
    max_files: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            max_files: DEFAULT_MAX_FILES,
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

    let (num_str, suffix) = if let Some(pos) = size_str.find(|c: char| !c.is_ascii_digit() && c != '.') {
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
fn safe_canonicalize<P: AsRef<Path>>(
    path: P,
) -> io::Result<PathBuf> {
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
    let mut buffer = [0u8; 4096];
    
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

fn hash_to_hex(hash: &[u8]) -> String {
    hash.iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

fn process_file(
    filename: &str,
    config: &Config,
    file_counter: &AtomicUsize,
) -> io::Result<()> {
    if filename == "-" {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        let hash = compute_whirlpool(&mut reader)?;
        println!("{}  -", hash_to_hex(&hash));
        return Ok(());
    }

    let path = Path::new(filename);
    let canonical_path = safe_canonicalize(path)?;
    
    let metadata = canonical_path.metadata().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Failed to access '{}': {}", canonical_path.display(), e),
        )
    })?;

    let file = secure_open_file(
        &canonical_path,
        config,
        file_counter,
        Some(metadata),
    )?;
    
    let mut reader = BufReader::new(file);
    let hash = compute_whirlpool(&mut reader)?;
    println!("{}  {}", hash_to_hex(&hash), canonical_path.display());
    Ok(())
}

fn parse_checksum_line(line: &str) -> Result<(&str, &str), ParseError> {
    let _original_line = line;
    let line = line.trim();
    
    if line.is_empty() || line.starts_with('#') {
        return Err(ParseError::EmptyOrComment);
    }

    if line.len() < HASH_HEX_SIZE + 1 { // At least one space after hash
        return Err(ParseError::TooShort(line.len()));
    }

    let (hash_part, rest) = line.split_at(HASH_HEX_SIZE);
    
    // First validate the hash part before checking separator
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

    // Now check separator and filename
    if rest.is_empty() {
        return Err(ParseError::TooShort(line.len()));
    }

    // Allow single space, double space, or space+asterisk as separators
    let (_separator, filename) = if rest.starts_with("  ") { // Two spaces
        ("  ", &rest[2..].trim_start())
    } else if rest.starts_with(" *") { // Space + asterisk
        (" *", &rest[2..].trim_start())
    } else if rest.starts_with(' ') { // Single space
        (" ", &rest[1..].trim_start())
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
        let checksum_file = secure_open_file(
            &canonical_checksum_path,
            config,
            &file_counter,
            None,
        )?;
        Box::new(BufReader::new(checksum_file))
    };

    let mut failed = 0;
    let mut total = 0;
    let mut invalid_lines = 0;

    for (line_num, line_result) in reader.lines().enumerate() {
        let line_num = line_num + 1;
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                invalid_lines += 1;
                if !status_only {
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
                        secure_open_file(
                            &canonical_target,
                            config,
                            &file_counter,
                            Some(metadata),
                        )
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
                        if actual_hash.to_lowercase() == expected_hash.to_lowercase() {
                            if !status_only && !quiet {
                                println!("{}: OK", filename);
                            }
                        } else {
                            failed += 1;
                            if !status_only {
                                eprintln!("{}: FAILED", filename);
                                eprintln!(
                                    "whirlpoolsum: {}: line {}: computed hash: {}",
                                    checksum_source,
                                    line_num,
                                    actual_hash
                                );
                                eprintln!(
                                    "whirlpoolsum: {}: line {}: expected hash: {}",
                                    checksum_source,
                                    line_num,
                                    expected_hash
                                );
                            }
                        }
                    }
                    Err(err) => {
                        failed += 1;
                        if !status_only {
                            eprintln!("{}: FAILED open or read - {}", filename, err);
                        }
                    }
                }
            }
            Err(err) => {
                invalid_lines += 1;
                if !status_only {
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

    if !status_only {
        if failed > 0 {
            eprintln!(
                "whirlpoolsum: WARNING: {} of {} computed checksums did NOT match",
                failed, total
            );
        }
        if invalid_lines > 0 && warn {
            eprintln!(
                "whirlpoolsum: WARNING: {} of {} lines are improperly formatted",
                invalid_lines, total + invalid_lines
            );
        }
    }

    Ok(if failed > 0 || invalid_lines > 0 { 1 } else { 0 })
}

fn print_help() {
    let version = env!("CARGO_PKG_VERSION");
    let license = env!("CARGO_PKG_LICENSE");
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    
    stdout.write_all(
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
      --max-file-size SIZE     set maximum file size (default: 1G)
      --max-files COUNT        set maximum number of files (default: 100)
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
  Maximum files: {}\n",
            version.green(),
            license,
            DEFAULT_MAX_FILE_SIZE,
            DEFAULT_MAX_FILES
        )
        .as_bytes(),
    )
    .expect("Failed to write help message");
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

    let file_counter = AtomicUsize::new(0);
    let exit_code = if check_mode {
        if files.is_empty() {
            if !status_only && !quiet {
                println!("Verifying checksums from standard input...");
            }
            // Read checksums from stdin
            check_checksums("-", &config, status_only, warn, quiet)?
        } else if files.len() == 1 {
            if !status_only && !quiet {
                println!("Verifying checksums from file: {}", files[0]);
            }    
        // Read checksums from specified file
            check_checksums(&files[0], &config, status_only, warn, quiet)?
        } else {
            eprintln!("whirlpoolsum: only one checksum file allowed in check mode");
            process::exit(2);
        }
    } else {
        // Generation mode
        if files.is_empty() {
            process_file("-", &config, &file_counter)?;
            0
        } else {
            let mut exit_code = 0;
            for filename in &files {
                if file_counter.load(Ordering::SeqCst) >= config.max_files {
                    eprintln!(
                        "whirlpoolsum: maximum file limit reached ({}). Skipping remaining files.",
                        config.max_files
                    );
                    exit_code = 3;
                    break;
                }
                
                if let Err(e) = process_file(filename, &config, &file_counter) {
                    eprintln!("whirlpoolsum: {}: {}", filename, e);
                    exit_code = 1;
                }
            }
            exit_code
        }
    };

    if exit_code != 0 {
        process::exit(exit_code);
    }
    Ok(())
}
