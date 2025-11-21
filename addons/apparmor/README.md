# AppArmor Profiles for whirlpoolsum

This directory contains AppArmor security profiles for `whirlpoolsum` using **pattern-based attachment** to protect against any executable with "whirlpoolsum" in the name, including temporary build binaries.

## Pattern-Based Protection

These profiles use glob patterns to match **any executable** containing "whirlpoolsum" in its name, regardless of location:
- ✅ `/usr/bin/whirlpoolsum` (installed binary)
- ✅ `./target/debug/whirlpoolsum` (debug build)
- ✅ `./target/release/whirlpoolsum` (release build)
- ✅ `/tmp/whirlpoolsum-test` (temporary copies)
- ✅ `~/github/rust-whirlpoolsum/whirlpoolsum` (development builds)

This provides **defense-in-depth** by restricting any whirlpoolsum binary, not just the installed one.

## Profiles

### 1. `whirlpoolsum` - CLI profile
For standard command-line usage.

**Pattern:** `profile whirlpoolsum /**/*whirlpoolsum*`

**Permissions:**
- Read access to files for checksumming
- Write access to create checksum files (.wrl, .json, .yaml)
- Standard terminal I/O
- ❌ No network access
- ❌ No privilege escalation

## Installation

### Install profile
```bash
sudo install -m 644 whirlpoolsum /etc/apparmor.d/
```

### Choose Your Profile

**For CLI:**
```bash
sudo apparmor_parser -r /etc/apparmor.d/whirlpoolsum.cli
```

### Verify
```bash
sudo aa-status | grep whirlpoolsum
```

## Development Workflow

### Testing Debug Builds
The profile automatically applies to debug builds:
```bash
cargo build
./target/debug/whirlpoolsum --help  # Profile active!
```

### Monitoring AppArmor Actions
Watch for denials during development:
```bash
sudo journalctl -f | grep -i apparmor
```

## Complain vs Enforce Modes

### Start in Complain Mode (Recommended)
Test without blocking operations:
```bash
sudo aa-complain whirlpoolsum
# Test your workflows
# Check logs for any issues
```

### Switch to Enforce Mode
Once tested:
```bash
sudo aa-enforce whirlpoolsum
```

## Pattern Matching Details

The pattern `/**/*whirlpoolsum*` matches:
- Any directory depth (`/**/`)
- Any characters before whirlpoolsum (`*`)
- The literal text "whirlpoolsum"
- Any characters after whirlpoolsum (`*`)

**Examples:**
- ✅ `/usr/bin/whirlpoolsum`
- ✅ `/home/user/project/target/debug/whirlpoolsum`
- ✅ `/tmp/whirlpoolsum-v0.8.0`
- ✅ `./whirlpoolsum.test`
- ❌ `/usr/bin/sha256sum` (doesn't match)

## Security Benefits

### Protection Against:
1. **Uncontrolled Build Artifacts**: Debug/release builds in development directories
2. **Temporary Copies**: Executables copied to /tmp or other locations
3. **Renamed Binaries**: Files like `whirlpoolsum.old` or `whirlpoolsum-backup`
4. **Attack Scenarios**: 
   - Malicious code injected into development builds
   - Compromised binaries with similar names
   - Supply chain attacks during build

### Limitations:
- Profile won't apply to executables without "whirlpoolsum" in their name
- Requires AppArmor 2.9+ for pattern-based attachment
- Both profiles cannot be active simultaneously (name conflict)

## Troubleshooting

### Profile Not Applying
Check if pattern matching is supported:
```bash
apparmor_parser --version  # Should be 2.9+
```

### Multiple Profiles Conflict
Only install ONE profile. To switch:
```bash
# Remove old profile
sudo rm /etc/apparmor.d/whirlpoolsum.cli
sudo apparmor_parser -R /etc/apparmor.d/whirlpoolsum.cli

# Install new profile
sudo install -m 644 whirlpoolsum.tui /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/whirlpoolsum.tui
```

### View Denials
```bash
sudo dmesg | grep -i apparmor | grep whirlpool
```

## Advanced: Profile Selection

If you need different profiles for different scenarios, use conditional logic:

```bash
# In your shell script
if [ "$1" = "--tui" ]; then
    # TUI profile active
    exec aa-exec -p whirlpoolsum-tui -- ./whirlpoolsum "$@"
else
    # CLI profile active  
    exec aa-exec -p whirlpoolsum -- ./whirlpoolsum "$@"
fi
```

## References
- [AppArmor Documentation](https://gitlab.com/apparmor/apparmor/-/wikis/home)
- [Profile Pattern Matching](https://gitlab.com/apparmor/apparmor/-/wikis/AppArmor_Core_Policy_Reference#profile-names-and-attachment-specifications)
