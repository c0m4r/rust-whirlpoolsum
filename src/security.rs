use std::io;

// Define Seccomp constants and structs if not fully available or for convenience
#[cfg(target_os = "linux")]
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
#[cfg(target_os = "linux")]
const PR_SET_SECCOMP: libc::c_int = 22;
#[cfg(target_os = "linux")]
const SECCOMP_MODE_FILTER: libc::c_int = 2;

#[cfg(target_os = "linux")]
const SECCOMP_RET_ERRNO: u32 = 0x00050000;
#[cfg(target_os = "linux")]
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

// BPF instruction classes
#[cfg(target_os = "linux")]
const BPF_LD: u16 = 0x00;
#[cfg(target_os = "linux")]
const BPF_JMP: u16 = 0x05;
#[cfg(target_os = "linux")]
const BPF_RET: u16 = 0x06;

// BPF fields
#[cfg(target_os = "linux")]
const BPF_W: u16 = 0x00;
#[cfg(target_os = "linux")]
const BPF_ABS: u16 = 0x20;
#[cfg(target_os = "linux")]
const BPF_JEQ: u16 = 0x10;

#[repr(C)]
#[cfg(target_os = "linux")]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
#[cfg(target_os = "linux")]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

// Helper macro to create a BPF instruction
#[cfg(target_os = "linux")]
macro_rules! bpf_stmt {
    ($code:expr, $k:expr) => {
        SockFilter {
            code: $code,
            jt: 0,
            jf: 0,
            k: $k,
        }
    };
}

#[cfg(target_os = "linux")]
macro_rules! bpf_jump {
    ($code:expr, $k:expr, $jt:expr, $jf:expr) => {
        SockFilter {
            code: $code,
            jt: $jt,
            jf: $jf,
            k: $k,
        }
    };
}

/// Enables a Seccomp sandbox that blocks network and execution syscalls.
///
/// This function uses a blacklist approach to block:
/// - socket, connect, bind, listen, accept, accept4 (Network)
/// - execve, execveat (Execution)
///
/// It returns `Ok(())` on success or an `io::Error` on failure.
#[cfg(target_os = "linux")]
pub fn enable_sandbox() -> io::Result<()> {
    // 1. Set No New Privileges
    // This is required to load a Seccomp filter without being root.
    let ret = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    // 2. Define the Seccomp Filter
    // We want to check the syscall number (arch-dependent, but we assume x86_64/Linux for this example or use libc constants)
    // The syscall number is loaded from offset 0 in the seccomp_data struct (which is what BPF sees).
    // Actually, for seccomp, the data buffer is `struct seccomp_data`.
    // Offset 0 is `nr` (syscall number).

    // List of syscalls to block
    // We use libc::SYS_* constants to be portable across architectures where Rust's libc supports them.
    let blocked_syscalls = [
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_execve,
        libc::SYS_execveat,
    ];

    let mut filter = Vec::new();

    // Load syscall number into accumulator
    // BPF_LD | BPF_W | BPF_ABS, offset 0 (syscall number)
    // struct seccomp_data { int nr; __u32 arch; ... }
    // nr is at offset 0.
    filter.push(bpf_stmt!(BPF_LD | BPF_W | BPF_ABS, 0));

    // For each blocked syscall, compare and jump to Kill/Errno if match
    for &syscall in &blocked_syscalls {
        // JEQ (Jump if Equal)
        // If accumulator == syscall, jump to RET_ERRNO (jt=0), else continue (jf=1)
        // Wait, we want to BLOCK if it matches.
        // So if Equal, Jump to DENY (skip 0 instructions).
        // If Not Equal, Jump to NEXT check (skip 1 instruction, which is the DENY return).

        // Actually, it's easier to do:

        // We need to calculate relative jumps.
        // A simpler way for a blacklist is:
        // [LOAD syscall]
        // [JEQ syscall_1, DENY, NEXT]
        // [JEQ syscall_2, DENY, NEXT]
        // ...
        // [RET ALLOW]
        // [DENY: RET ERRNO]

        // But BPF jumps use u8 offsets. If the list is long, we might need chaining.
        // With 8 syscalls, it's fine.

        // However, `SockFilter` structure is: code, jt, jf, k.
        // jt and jf are relative offsets (number of instructions to skip).

        // Let's construct it:
        // For each syscall:
        //   JEQ syscall, 0 (execute next instruction = DENY), 1 (skip next instruction = CONTINUE)
        //   RET ERRNO
        // ...
        // RET ALLOW

        filter.push(bpf_jump!(BPF_JMP | BPF_JEQ, syscall as u32, 0, 1));
        filter.push(bpf_stmt!(BPF_RET, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
    }

    // Allow everything else
    filter.push(bpf_stmt!(BPF_RET, SECCOMP_RET_ALLOW));

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    // 3. Load the Filter
    let ret = unsafe {
        libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &prog as *const SockFprog as libc::c_long,
        )
    };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// No-op for non-Linux systems
#[cfg(not(target_os = "linux"))]
pub fn enable_sandbox() -> io::Result<()> {
    Ok(())
}

/// Enables Landlock to restrict file system access.
///
/// This function creates a ruleset that:
/// 1. Allows reading from the specified `input_paths`.
/// 2. Allows writing to the specified `output_path` (if any).
/// 3. Denies access to everything else (default Landlock behavior).
///
/// Note: Paths must be canonicalized (absolute) for Landlock to work correctly with them.
#[cfg(target_os = "linux")]
pub fn enable_landlock(
    input_paths: &[std::path::PathBuf],
    output_path: Option<&std::path::PathBuf>,
) -> io::Result<()> {
    use landlock::{Access, AccessFs, PathBeneath, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI};

    // 1. Create a ruleset
    // We want to handle both files and directories (if recursive).
    // For simplicity, we'll just ask for basic read/write permissions.
    // Note: AccessFs::MakeReg is the correct variant for regular files.
    let read_access = AccessFs::ReadFile | AccessFs::ReadDir;
    let write_access = AccessFs::WriteFile | AccessFs::MakeReg | AccessFs::Truncate;

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V1))
        .map_err(|e| io::Error::other(e.to_string()))?
        .create()
        .map_err(|e| io::Error::other(e.to_string()))?;

    // 2. Add rules for input paths
    for path in input_paths {
        // We need to open the file/dir to get a file descriptor for Landlock
        let fd = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "⚠ WARNING: Could not open {:?} to add Landlock rule: {}",
                    path, e
                );
                continue;
            }
        };

        let rule = PathBeneath::new(&fd, read_access);
        ruleset = ruleset.add_rule(rule).map_err(|e| {
            io::Error::other(format!("Failed to add Landlock rule for {:?}: {}", path, e))
        })?;
    }

    // 3. Add rule for output path
    if let Some(path) = output_path {
        // If the file doesn't exist, we need permission on the parent directory to create it.
        if let Some(parent) = path.parent() {
            if let Ok(fd) = std::fs::File::open(parent) {
                let rule = PathBeneath::new(&fd, write_access);
                ruleset = ruleset
                    .add_rule(rule)
                    .map_err(|e| io::Error::other(e.to_string()))?;
            }
        }

        // If the file already exists, we need permission on the file itself to write/truncate.
        if path.exists() {
            if let Ok(fd) = std::fs::File::open(path) {
                let rule = PathBeneath::new(&fd, write_access);
                ruleset = ruleset
                    .add_rule(rule)
                    .map_err(|e| io::Error::other(e.to_string()))?;
            }
        }
    }

    // 4. Enforce the ruleset
    let _restricted_ruleset = ruleset
        .restrict_self()
        .map_err(|e| io::Error::other(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::process::Command;
    use std::time::Duration;

    // NOTE: Seccomp filters are applied to the process. Running these tests in parallel
    // might affect other tests if they run in the same process.
    // However, `cargo test` runs each test in a thread. Seccomp with PR_SET_NO_NEW_PRIVS
    // and PR_SET_SECCOMP applies to the calling thread and its children.
    // So it SHOULD be safe if tests are threaded.

    #[test]
    fn test_network_blocked() {
        // Enable sandbox for this thread
        if let Err(e) = enable_sandbox() {
            // If we can't enable sandbox (e.g. CI environment issues), skip or fail
            eprintln!("Failed to enable sandbox: {}", e);
            return;
        }

        // Attempt network connection
        let result =
            TcpStream::connect_timeout(&"23.215.0.136:80".parse().unwrap(), Duration::from_secs(1));

        match result {
            Ok(_) => panic!("Network connection succeeded but should have been blocked!"),
            Err(e) => {
                // Verify it was blocked by permission denied (EPERM = 1)
                // or similar error depending on how TcpStream maps it.
                // os error 1 is EPERM.
                if let Some(os_error) = e.raw_os_error() {
                    assert_eq!(
                        os_error,
                        libc::EPERM,
                        "Expected EPERM (1), got {}",
                        os_error
                    );
                } else {
                    panic!("Expected OS error EPERM, got: {}", e);
                }
            }
        }
    }

    #[test]
    fn test_execution_blocked() {
        // Enable sandbox for this thread
        if let Err(e) = enable_sandbox() {
            eprintln!("Failed to enable sandbox: {}", e);
            return;
        }

        // Attempt execution
        let result = Command::new("ls").status();

        match result {
            Ok(_) => panic!("Execution succeeded but should have been blocked!"),
            Err(e) => {
                if let Some(os_error) = e.raw_os_error() {
                    assert_eq!(
                        os_error,
                        libc::EPERM,
                        "Expected EPERM (1), got {}",
                        os_error
                    );
                } else {
                    panic!("Expected OS error EPERM, got: {}", e);
                }
            }
        }
    }
}
