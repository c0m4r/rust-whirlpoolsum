use std::fs::{canonicalize, File, Metadata};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config;

// ============================================================================
// Utility Functions
// ============================================================================

/// Parse human-readable size strings (e.g., "512M", "2G")
/// 
/// Supports suffixes: B, KB, MB, GB, TB (case-insensitive)
/// Examples: "1024", "512M", "2.5G"
pub fn parse_size(size_str: &str) -> io::Result<u64> {
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
pub fn safe_canonicalize<P: AsRef<Path>>(path: P) -> io::Result<PathBuf> {
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

/// Convert binary hash to hexadecimal string representation
/// 
/// Pre-allocates string with exact required capacity for efficiency
pub fn hash_to_hex(hash: &[u8]) -> String {
    hash.iter()
        .fold(String::with_capacity(config::HASH_HEX_SIZE), |mut acc, byte| {
            use std::fmt::Write;
            let _ = write!(acc, "{:02x}", byte);
            acc
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
pub fn secure_open_file<P: AsRef<Path>>(
    path: P,
    config: &config::Config,
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
