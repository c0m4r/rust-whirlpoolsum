# AppArmor Testing Guide

## Testing with the Actual Binary

Since `cargo test` creates separate test binaries that don't match the `/**/*whirlpoolsum*` pattern, I've added a hidden `--test-network` flag to the actual whirlpoolsum binary for AppArmor verification.

## Quick Test

### Without AppArmor (baseline)
```bash
./target/release/whirlpoolsum --test-network
```

**Expected output:**
```
✗ CONNECTION SUCCESSFUL
  Status: APPARMOR NOT ENFORCING
⚠ WARNING: Network access is ALLOWED!
```

### With AppArmor Enforcing
```bash
# Install and enforce the profile
sudo install -m 644 addons/apparmor/whirlpoolsum.cli /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/whirlpoolsum.cli
sudo aa-enforce whirlpoolsum

# Run the test
./target/release/whirlpoolsum --test-network
```

**Expected output:**
```
✓ CONNECTION BLOCKED
  Error: Permission denied (os error 13)
  Status: APPARMOR IS ENFORCING
✓ SUCCESS: Network restrictions are working!
```

## Testing Different Builds

### Debug Build
```bash
cargo build
./target/debug/whirlpoolsum --test-network
```

### Release Build
```bash
cargo build --release
./target/release/whirlpoolsum --test-network
```

### From Any Location
Thanks to pattern-based matching, the test works from anywhere:
```bash
cp target/release/whirlpoolsum /tmp/whirlpoolsum-test
/tmp/whirlpoolsum-test --test-network  # Still protected!
```

## Automated Testing Script

Create `test_apparmor.sh`:
```bash
#!/bin/bash

echo "Building whirlpoolsum..."
cargo build --release

echo ""
echo "Testing WITHOUT AppArmor (should connect):"
./target/release/whirlpoolsum --test-network
WITHOUT_APPARMOR=$?

echo ""
echo "Installing AppArmor profile..."
sudo install -m 644 addons/apparmor/whirlpoolsum.cli /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/whirlpoolsum.cli
sudo aa-enforce whirlpoolsum

echo ""
echo "Testing WITH AppArmor (should block):"
./target/release/whirlpoolsum --test-network
WITH_APPARMOR=$?

if [ $WITHOUT_APPARMOR -eq 1 ] && [ $WITH_APPARMOR -eq 0 ]; then
    echo ""
    echo "✓ ALL TESTS PASSED - AppArmor working correctly!"
    exit 0
else
    echo ""
    echo "✗ TEST FAILED - Unexpected results"
    exit 1
fi
```

## Exit Codes

The `--test-network` flag uses specific exit codes:
- **Exit 0**: Connection blocked (AppArmor working) ✓
- **Exit 1**: Connection succeeded (AppArmor NOT working) ✗

This makes it easy to use in scripts and CI/CD pipelines.

## Monitoring AppArmor Actions

While running tests, monitor AppArmor in another terminal:
```bash
sudo journalctl -f | grep -i apparmor
```

You should see denial messages when AppArmor blocks the connection:
```
apparmor="DENIED" operation="connect" profile="whirlpoolsum"
```

## Troubleshooting

### Profile not loading
```bash
sudo aa-status | grep whirlpool
```

### Check which profile is active
```bash
sudo aa-status
```

### View recent denials
```bash
sudo dmesg | grep -i apparmor | grep whirlpool | tail -20
```

### Switch to complain mode for debugging
```bash
sudo aa-complain whirlpoolsum
./target/release/whirlpoolsum --test-network
sudo journalctl | grep apparmor | grep whirlpool
```
