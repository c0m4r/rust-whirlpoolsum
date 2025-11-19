// ============================================================================
// Constants
// ============================================================================

/// Default maximum file size (1GB) - prevents DoS via large files
pub const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;
/// Default maximum number of files - prevents DoS via many files
pub const DEFAULT_MAX_FILES: usize = 100;
/// WHIRLPOOL-512 produces 64 bytes (512 bits)
pub const HASH_SIZE: usize = 64;
/// Hash in hexadecimal format is 128 characters
pub const HASH_HEX_SIZE: usize = HASH_SIZE * 2;
/// Size of data used for benchmark testing (100MB)
pub const BENCHMARK_FILE_SIZE: usize = 100 * 1024 * 1024;
/// Optimal buffer size for I/O operations (64KB)
pub const BUFFER_SIZE: usize = 65536;
/// Standard separator: two spaces
pub const HASH_SEPARATOR_DOUBLE: &str = "  ";
/// BSD-style separator: space followed by asterisk
pub const HASH_SEPARATOR_ASTERISK: &str = " *";

// ============================================================================
// Configuration Structures
// ============================================================================

/// Configuration settings for security and resource limits
#[derive(Clone)]
pub struct Config {
    /// Maximum allowed size for individual files
    pub max_file_size: u64,
    /// Maximum number of files to process
    pub max_files: usize,
    /// Output format (text, JSON, or YAML)
    pub output_format: OutputFormat,
    /// Whether to show performance benchmarks
    pub benchmark: bool,
}

/// Available output formats for results
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
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
