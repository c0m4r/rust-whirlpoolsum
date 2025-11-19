use colored::Colorize;
use std::io::{self, Write};

use crate::config;

// ============================================================================
// Help and Documentation
// ============================================================================

/// Print comprehensive help message with usage information
pub fn print_help() {
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
            config::DEFAULT_MAX_FILE_SIZE,
            config::DEFAULT_MAX_FILES,
            config::OutputFormat::Text
        )
        .as_bytes(),
    );
}
