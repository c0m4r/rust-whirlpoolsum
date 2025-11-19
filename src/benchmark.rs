use colored::Colorize;
use std::io::{self, Cursor, Read};
use std::time::Instant;
use whirlpool::{Digest, Whirlpool};

use crate::config;
use crate::util;

// ============================================================================
// Benchmark Test Function
// ============================================================================

/// Run a standardized benchmark test with 100MB of data
/// 
/// Tests hashing performance and provides a scored rating
/// Score calculation: (MB/s) * 10
/// Ratings: A++ (2000+), A+ (1000+), A (500+), B (250+), C (100+), D (<100)
pub fn run_benchmark_test() -> io::Result<()> {
    println!("{}", "=== WHIRLPOOL Benchmark Test ===".green().bold());
    println!("Generating 100 MB of random data...\n");

    // Generate test data (pattern 0xA5 for repeatability)
    let data = vec![0xA5u8; config::BENCHMARK_FILE_SIZE];
    let mut cursor = Cursor::new(&data);

    println!("Starting benchmark...\n");
    let start = Instant::now();

    // Perform hash computation
    let mut hasher = Whirlpool::new();
    let mut buffer = [0u8; config::BUFFER_SIZE];
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
        util::hash_to_hex(hash_result.as_slice()).bright_black()
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
