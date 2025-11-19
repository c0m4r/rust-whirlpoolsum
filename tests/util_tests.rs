use whirlpoolsum::util::{hash_to_hex, parse_size};

#[test]
fn test_hash_to_hex() {
    let hash = [0xDE, 0xAD, 0xBE, 0xEF];
    assert_eq!(hash_to_hex(&hash), "deadbeef");

    let hash = [0x00, 0xFF, 0x12, 0x34];
    assert_eq!(hash_to_hex(&hash), "00ff1234");
}

#[test]
fn test_parse_size() {
    // Basic bytes
    assert_eq!(parse_size("1024").unwrap(), 1024);
    assert_eq!(parse_size("1024B").unwrap(), 1024);
    assert_eq!(parse_size("1024b").unwrap(), 1024);

    // KB
    assert_eq!(parse_size("1K").unwrap(), 1024);
    assert_eq!(parse_size("1KB").unwrap(), 1024);

    // MB
    assert_eq!(parse_size("1M").unwrap(), 1024 * 1024);

    // GB
    assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);

    // Fractional
    assert_eq!(parse_size("1.5K").unwrap(), 1536);
    assert_eq!(parse_size("0.5M").unwrap(), 512 * 1024);

    // Error cases
    assert!(parse_size("").is_err());
    assert!(parse_size("-1").is_err());
    assert!(parse_size("abc").is_err());
    assert!(parse_size("10X").is_err());
}
