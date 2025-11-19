use clap::Parser;
use whirlpoolsum::cli::Cli;
use whirlpoolsum::config::{OutputFormat, DEFAULT_MAX_FILES};

#[test]
fn test_cli_defaults() {
    let args = vec!["whirlpoolsum"];
    let cli = Cli::parse_from(args);

    assert!(!cli.check);
    assert!(!cli.status);
    assert!(!cli.warn);
    assert!(!cli.quiet);
    assert!(!cli.benchmark);
    assert!(!cli.json);
    assert!(!cli.yaml);
    assert_eq!(cli.max_files, DEFAULT_MAX_FILES);
    assert_eq!(cli.get_output_format(), OutputFormat::Text);
}

#[test]
fn test_cli_flags() {
    let args = vec![
        "whirlpoolsum",
        "--check",
        "--status",
        "--warn",
        "--quiet",
        "--benchmark",
    ];
    let cli = Cli::parse_from(args);

    assert!(cli.check);
    assert!(cli.status);
    assert!(cli.warn);
    assert!(cli.quiet);
    assert!(cli.benchmark);
}

#[test]
fn test_cli_max_files() {
    let args = vec!["whirlpoolsum", "--max-files", "500"];
    let cli = Cli::parse_from(args);

    assert_eq!(cli.max_files, 500);
}

#[test]
fn test_cli_max_file_size() {
    let args = vec!["whirlpoolsum", "--max-file-size", "500M"];
    let cli = Cli::parse_from(args);
    let config = cli.to_config().unwrap();

    assert_eq!(config.max_file_size, 500 * 1024 * 1024);
}

#[test]
fn test_cli_output_format() {
    let args = vec!["whirlpoolsum", "--json"];
    let cli = Cli::parse_from(args);
    assert_eq!(cli.get_output_format(), OutputFormat::Json);

    let args = vec!["whirlpoolsum", "--yaml"];
    let cli = Cli::parse_from(args);
    assert_eq!(cli.get_output_format(), OutputFormat::Yaml);
}
