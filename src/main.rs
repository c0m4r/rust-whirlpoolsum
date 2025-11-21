use clap::Parser;
use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use whirlpoolsum::{benchmark, cli, config, processor, verifier};

mod security;

fn main() {
    // Enable security sandbox (Seccomp) to block network and execution
    if let Err(e) = security::enable_sandbox() {
        eprintln!("Failed to enable security sandbox: {}", e);
        process::exit(1);
    }

    // Check for execution test mode (hidden flag)
    if std::env::args().any(|a| a == "--test-exec") {
        println!("\n========================================");
        println!("Seccomp Execution Restriction Test");
        println!("========================================\n");
        println!("Attempting to execute 'ls'...\n");

        match process::Command::new("ls").status() {
            Ok(_) => {
                println!("✗ EXECUTION SUCCESSFUL");
                println!("⚠ WARNING: Execution is ALLOWED!");
                println!("========================================\n");
                process::exit(1);
            }
            Err(e) => {
                println!("✓ EXECUTION BLOCKED");
                println!("  Error: {}", e);
                println!("✓ SUCCESS: Execution restrictions are working!");
                println!("========================================\n");
                process::exit(0);
            }
        }
    }

    // Check for help flag before parsing to print custom header
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!(
            "whirlpoolsum v{}\n\nGithub: {}\nAuthors: {}\nLicense: {}",
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_REPOSITORY"),
            env!("CARGO_PKG_AUTHORS"),
            env!("CARGO_PKG_LICENSE")
        );
        process::exit(0);
    }

    let cli = cli::Cli::parse();

    // Check for network test mode (for AppArmor verification)
    if cli.test_network {
        use std::net::TcpStream;
        use std::time::Duration;

        println!("\n========================================");
        println!("AppArmor Network Restriction Test");
        println!("========================================\n");
        println!("Attempting to connect to example.com:80...\n");

        match TcpStream::connect_timeout(
            &"23.215.0.136:80".parse().unwrap(),
            Duration::from_secs(5),
        ) {
            Ok(_) => {
                println!("✗ CONNECTION SUCCESSFUL");
                println!("  Status: APPARMOR NOT ENFORCING\n");
                println!("⚠ WARNING: Network access is ALLOWED!");
                println!("\nTo enable AppArmor:");
                println!("  sudo install -m 644 addons/apparmor/whirlpoolsum.cli /etc/apparmor.d/");
                println!("  sudo apparmor_parser -r /etc/apparmor.d/whirlpoolsum.cli");
                println!("  sudo aa-enforce whirlpoolsum");
                println!("========================================\n");
                process::exit(1);
            }
            Err(e) => {
                println!("✓ CONNECTION BLOCKED");
                println!("  Error: {}", e);
                println!("  Status: APPARMOR IS ENFORCING\n");
                println!("✓ SUCCESS: Network restrictions are working!");
                println!("========================================\n");
                process::exit(0);
            }
        }
    }

    // Check for TUI mode
    if cli.tui {
        let config = match cli.to_config() {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("error: {}", e);
                process::exit(2);
            }
        };
        if let Err(e) = whirlpoolsum::tui::run_tui(config) {
            eprintln!("TUI error: {}", e);
            process::exit(1);
        }
        return;
    }

    // Convert CLI args to Config
    let config = match cli.to_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(2);
        }
    };

    // Enable Landlock file system restrictions
    // We only allow access to the specified input files.
    // Output is to stdout, which is already open, so no special rule needed.
    #[cfg(target_os = "linux")]
    {
        let mut input_paths = Vec::new();
        for path in &cli.files {
            // Canonicalize paths to ensure they are absolute and resolve symlinks.
            // Landlock requires absolute paths.
            // If a file doesn't exist, canonicalize will fail. We warn and continue,
            // letting the main processor handle the error naturally later.
            match std::fs::canonicalize(path) {
                Ok(p) => input_paths.push(p),
                Err(_) => {
                    // If we can't canonicalize (e.g. file not found), we don't add it to the whitelist.
                    // The processor will fail to open it later, which is fine.
                    // Or we could fail here. But let's be consistent with existing behavior.
                    // However, if we don't add it, and the file DOES exist but canonicalize failed for some other reason,
                    // Landlock will block it.
                }
            }
        }

        // If we are in check mode with a file, we need to allow reading that file.
        // (It's already in cli.files, so handled above)

        // If we are in check mode, the file contains paths to other files.
        // We need to read those files too!
        // This is tricky. If `whirlpoolsum -c sums.txt` is run, we read `sums.txt`.
        // `sums.txt` contains `hash  filename`. We then need to open `filename`.
        // If we locked down FS to only `sums.txt`, we can't read the files listed in it!

        // CRITICAL: In check mode, we cannot easily predict which files will be accessed
        // without parsing the checksum file first.
        // Parsing the checksum file happens in `verifier::check_checksums`.

        // Options:
        // 1. Don't enable Landlock in check mode.
        // 2. Parse the check file *before* enabling Landlock to get the list of files.
        // 3. Allow reading the current directory (recursive)? That defeats the purpose somewhat.

        // Let's check if we are in check mode.
        if cli.check {
            // For now, let's SKIP Landlock in check mode to avoid breaking it.
            // Or we can implement a pre-pass to read the file list.
            // Given the complexity, skipping for check mode is a safer first step.
            // But the user wants hardening.

            // Allow access to system temporary directory
            let temp_dir = std::env::temp_dir();
            if let Ok(canon_temp) = std::fs::canonicalize(&temp_dir) {
                input_paths.push(canon_temp);
            }

            // Allow access to the directory of the checksum file itself
            // because it might contain relative paths to files in that directory.
            if !cli.files.is_empty() {
                if let Ok(canon_path) = std::fs::canonicalize(&cli.files[0]) {
                    if let Some(parent) = canon_path.parent() {
                        input_paths.push(parent.to_path_buf());
                    }
                }
            }

            // Alternative: Allow read access to the current working directory (recursive).
            // This restricts access to /etc, /usr, etc. (unless CWD is root).
            // This is a good middle ground for check mode.

            if let Ok(cwd) = std::env::current_dir() {
                input_paths.push(cwd);
            }
        }

        if let Err(e) = security::enable_landlock(&input_paths, None) {
            eprintln!("Failed to enable Landlock: {}", e);
            // We don't exit, just warn? Or exit? Seccomp exits.
            // Let's exit to be safe.
            process::exit(1);
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

    // Initialize shared file counter for resource tracking
    let file_counter = Arc::new(AtomicUsize::new(0));

    // Special case: benchmark mode with no files runs a benchmark test
    if config.benchmark && cli.files.is_empty() && !cli.check {
        if let Err(e) = benchmark::run_benchmark_test() {
            eprintln!("Benchmark failed: {}", e);
            process::exit(1);
        }
        return;
    }

    let exit_code = if cli.check {
        // Checksum verification mode
        if cli.files.is_empty() {
            // Read from stdin
            if !cli.status && !cli.quiet && config.output_format == config::OutputFormat::Text {
                println!("Verifying checksums from standard input...");
            }
            match verifier::check_checksums("-", &config, cli.status, cli.warn, cli.quiet) {
                Ok((code, results)) => {
                    if config.output_format != config::OutputFormat::Text {
                        processor::output_results_json_yaml(&results, config.output_format, true);
                    }
                    code
                }
                Err(e) => {
                    eprintln!("whirlpoolsum: {}", e);
                    1
                }
            }
        } else if cli.files.len() == 1 {
            // Read from single file
            let filename = cli.files[0].to_string_lossy();
            if !cli.status && !cli.quiet && config.output_format == config::OutputFormat::Text {
                println!("Verifying checksums from file: {}", filename);
            }
            match verifier::check_checksums(&filename, &config, cli.status, cli.warn, cli.quiet) {
                Ok((code, results)) => {
                    if config.output_format != config::OutputFormat::Text {
                        processor::output_results_json_yaml(&results, config.output_format, true);
                    }
                    code
                }
                Err(e) => {
                    eprintln!("whirlpoolsum: {}", e);
                    1
                }
            }
        } else {
            // Multiple checksum files not allowed
            eprintln!("whirlpoolsum: only one checksum file allowed in check mode");
            process::exit(2);
        }
    } else {
        // Hash generation mode
        let mut exit_code = 0;

        if cli.files.is_empty() {
            // Hash from stdin
            match processor::process_file(std::path::Path::new("-"), &config, &file_counter) {
                Ok(result) => {
                    if config.output_format == config::OutputFormat::Text {
                        processor::print_text_result(&result);
                    } else {
                        processor::output_results_json_yaml(&[result], config.output_format, false);
                    }
                }
                Err(e) => {
                    eprintln!("whirlpoolsum: {}", e);
                    exit_code = 1;
                }
            }
        } else if cli.files.len() == 1 {
            // Hash single file
            match processor::process_file(&cli.files[0], &config, &file_counter) {
                Ok(result) => {
                    if config.output_format == config::OutputFormat::Text {
                        processor::print_text_result(&result);
                    } else {
                        processor::output_results_json_yaml(&[result], config.output_format, false);
                    }
                }
                Err(e) => {
                    eprintln!("whirlpoolsum: {}: {}", cli.files[0].display(), e);
                    exit_code = 1;
                }
            }
        } else {
            // Hash multiple files in parallel
            let (tx, rx) = std::sync::mpsc::channel();
            let files = cli.files.clone();
            let config_clone = config.clone();
            let file_counter_clone = Arc::clone(&file_counter);

            // Spawn thread for parallel processing
            std::thread::spawn(move || {
                processor::process_files_parallel(&files, &config_clone, file_counter_clone, tx);
            });

            let mut collected_results = Vec::new();
            let mut buffer = std::collections::HashMap::new();
            let mut next_idx = 0;
            let mut limit_reached_printed = false;

            // Process results as they arrive
            for (idx, result) in rx {
                buffer.insert(idx, result);

                // Print available results in order
                while let Some(res) = buffer.remove(&next_idx) {
                    match res {
                        Ok(hash_result) => {
                            if config.output_format == config::OutputFormat::Text {
                                processor::print_text_result(&hash_result);
                            } else {
                                collected_results.push(hash_result);
                            }
                        }
                        Err((filename, e)) => {
                            let msg = e.to_string();
                            if msg.contains("Maximum file limit reached") {
                                if !limit_reached_printed {
                                    eprintln!("whirlpoolsum: {}", msg);
                                    limit_reached_printed = true;
                                }
                            } else {
                                eprintln!("whirlpoolsum: {}: {}", filename.display(), e);
                            }
                            exit_code = 1;
                        }
                    }
                    next_idx += 1;
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
            if config.output_format != config::OutputFormat::Text {
                processor::output_results_json_yaml(
                    &collected_results,
                    config.output_format,
                    false,
                );
            }
        }

        exit_code
    };

    if exit_code != 0 {
        process::exit(exit_code);
    }
}
