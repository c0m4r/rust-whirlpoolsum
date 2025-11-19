use std::fs::{canonicalize, File, Metadata};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config;

// ============================================================================
// Utility Functions
// ============================================================================

/// Evaluate RPN expression from string at compile time
/// Supported: integers, +, -, *, /
/// Example: "10 20 +" -> 30
pub const fn evaluate_rpn_str(s: &str) -> u64 {
    let mut stack = [0u64; 16];
    let mut sp = 0;
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b' ' {
            i += 1;
            continue;
        }

        if b >= b'0' && b <= b'9' {
            let mut num = 0u64;
            while i < bytes.len() && bytes[i] >= b'0' && bytes[i] <= b'9' {
                num = num * 10 + (bytes[i] - b'0') as u64;
                i += 1;
            }
            stack[sp] = num;
            sp += 1;
        } else {
            // Operator
            let op = bytes[i];
            i += 1;

            let b_val = stack[sp - 1];
            sp -= 1;
            let a_val = stack[sp - 1];
            // sp remains same for result (sp-1)

            match op {
                b'+' => stack[sp - 1] = a_val + b_val,
                b'-' => stack[sp - 1] = a_val - b_val,
                b'*' => stack[sp - 1] = a_val * b_val,
                b'/' => stack[sp - 1] = a_val / b_val,
                _ => {} // Ignore unknown
            }
        }
    }
    stack[0]
}

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

    // Determine multiplier based on suffix
    let multiplier: u64 = match suffix.to_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        "t" | "tb" => 1024 * 1024 * 1024 * 1024,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unknown size suffix: {}", suffix),
            ))
        }
    };

    // If it contains a decimal point, parse as f64 to handle fractions like "2.5G"
    if num_str.contains('.') {
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

        let size = num * (multiplier as f64);
        if size > u64::MAX as f64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Size value out of range",
            ));
        }
        Ok(size as u64)
    } else {
        // Parse as u64 directly to avoid precision loss for large integers
        let num: u64 = num_str.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid number in size specification: {}", e),
            )
        })?;

        // Check for overflow
        num.checked_mul(multiplier).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Size value out of range (overflow)",
            )
        })
    }
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
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(hash.len() * 2);

    for &byte in hash {
        result.push(HEX_CHARS[(byte >> 4) as usize] as char);
        result.push(HEX_CHARS[(byte & 0x0F) as usize] as char);
    }
    result
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
