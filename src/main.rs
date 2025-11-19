use clap::Parser;
use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

mod benchmark;
mod cli;
mod config;
mod processor;
mod util;
mod verifier;

fn main() {
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

    // Convert CLI args to Config
    let config = match cli.to_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(2);
        }
    };

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
