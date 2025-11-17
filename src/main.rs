use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process;
use whirlpool::{Digest, Whirlpool};

const HASH_SIZE: usize = 64; // 512 bits = 64 bytes
const HASH_HEX_SIZE: usize = HASH_SIZE * 2; // 128 hex characters

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

fn process_file(filename: &str) -> io::Result<()> {
    if filename == "-" {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        let hash = compute_whirlpool(&mut reader)?;
        println!("{}  -", hash_to_hex(&hash));
        return Ok(());
    }

    let path = Path::new(filename);
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("whirlpoolsum: {}: {}", filename, e);
            return Err(e);
        }
    };
    
    let mut reader = BufReader::new(file);
    let hash = compute_whirlpool(&mut reader)?;
    println!("{}  {}", hash_to_hex(&hash), filename);
    Ok(())
}

fn parse_checksum_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    // Check if line has the proper format: 128 hex chars + separator + filename
    if line.len() < HASH_HEX_SIZE + 2 {
        return None;
    }

    let (hash_part, rest) = line.split_at(HASH_HEX_SIZE);
    let separator = &rest[..2];
    let filename = rest[2..].trim_start();

    // Valid separators are "  " (two spaces) or " *" (space + asterisk)
    if separator != "  " && separator != " *" {
        return None;
    }

    // Verify hash part contains only hex characters
    if !hash_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    Some((hash_part, filename))
}

fn check_checksums(checksum_source: &str, status_only: bool, warn: bool) -> io::Result<i32> {
    let reader: Box<dyn BufRead> = if checksum_source == "-" {
        Box::new(BufReader::new(io::stdin()))
    } else {
        let file = File::open(checksum_source).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("whirlpoolsum: {}: {}", checksum_source, e),
            )
        })?;
        Box::new(BufReader::new(file))
    };

    let mut failed = 0;
    let mut _total = 0;
    let mut invalid_lines = 0;

    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        let line_num = line_num + 1;

        match parse_checksum_line(&line) {
            Some((expected_hash, filename)) => {
                _total += 1;
                let result = File::open(filename)
                    .map_err(|e| format!("open failed: {}", e))
                    .and_then(|file| {
                        let mut reader = BufReader::new(file);
                        compute_whirlpool(&mut reader)
                            .map(|hash| hash_to_hex(&hash))
                            .map_err(|e| format!("read failed: {}", e))
                    });

                match result {
                    Ok(actual_hash) => {
                        if actual_hash.to_lowercase() == expected_hash.to_lowercase() {
                            if !status_only {
                                println!("{}: OK", filename);
                            }
                        } else {
                            failed += 1;
                            if !status_only {
                                eprintln!("{}: FAILED", filename);
                            }
                        }
                    }
                    Err(err) => {
                        failed += 1;
                        if !status_only {
                            eprintln!("{}: FAILED ({})", filename, err);
                        }
                    }
                }
            }
            None => {
                invalid_lines += 1;
                if warn && !status_only {
                    eprintln!(
                        "whirlpoolsum: {}: {}: improperly formatted line",
                        checksum_source, line_num
                    );
                }
            }
        }
    }

    if !status_only {
        if failed > 0 {
            eprintln!(
                "whirlpoolsum: WARNING: {} computed checksum did NOT match",
                failed
            );
        }
        if invalid_lines > 0 && warn {
            eprintln!(
                "whirlpoolsum: WARNING: {} lines are improperly formatted",
                invalid_lines
            );
        }
    }

    // Exit codes:
    // 0 = all checksums matched
    // 1 = some checksums failed
    // 2 = invalid command line arguments or IO errors
    Ok(if failed > 0 || invalid_lines > 0 { 1 } else { 0 })
}

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1).peekable();
    let mut check_mode = false;
    let mut status_only = false;
    let mut warn = false;
    let mut _quiet = false;
    let mut files = Vec::new();

    // Parse command line arguments
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--check" => check_mode = true,
            "--status" => status_only = true,
            "--warn" => warn = true,
            "-q" | "--quiet" => _quiet = true,
            "--" => {
                // End of options, take all remaining as files
                files.extend(args);
                break;
            }
            _ if arg.starts_with('-') => {
                eprintln!("whirlpoolsum: unrecognized option '{}'", arg);
                eprintln!("Try 'whirlpoolsum --help' for more information.");
                process::exit(1);
            }
            _ => files.push(arg),
        }
    }

    // Handle help request
    if files.iter().any(|f| f == "--help") {
        print_help();
        return Ok(());
    }

    let exit_code = if check_mode {
        if files.is_empty() {
            // Read checksums from stdin
            check_checksums("-", status_only, warn)?
        } else if files.len() == 1 {
            // Read checksums from specified file
            check_checksums(&files[0], status_only, warn)?
        } else {
            eprintln!("whirlpoolsum: only one checksum file allowed in check mode");
            process::exit(1);
        }
    } else {
        // Generation mode
        if files.is_empty() {
            process_file("-")?;
            0
        } else {
            let mut exit_code = 0;
            for filename in &files {
                if let Err(_e) = process_file(filename) {
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

fn print_help() {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    
    stdout.write_all(
        b"Usage: whirlpoolsum [OPTION]... [FILE]...
Print or check WHIRLPOOL (512-bit) checksums.

With no FILE, or when FILE is -, read standard input.

Options:
  -c, --check       read WHIRLPOOL sums from the FILEs and check them
      --status      don't output anything, status code shows success
      --warn        warn about improperly formatted checksum lines
  -q, --quiet       don't print OK for each successfully verified file
      --help        display this help and exit

The following two options are useful only when verifying checksums:
      --status      don't output anything, status code shows success
      --warn        warn about improperly formatted checksum lines

Check mode output format:
  <hash>  <filename>  (text mode)
  <hash> *<filename>  (binary mode, same as text mode on Unix)

Exit status:
  0 = all checksums matched (or successfully generated)
  1 = some checksums failed or files not found
  2 = invalid command line arguments or IO errors
",
    )
    .expect("Failed to write help message");
}
