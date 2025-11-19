use crate::config;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = None,
    next_line_help = false
)]
pub struct Cli {
    /// Check WHIRLPOOL sums
    #[arg(short = 'c', long = "check", next_line_help = false)]
    pub check: bool,

    /// Don't output anything, status code shows success
    #[arg(long = "status", next_line_help = false)]
    pub status: bool,

    /// Warn about improperly formatted checksum lines
    #[arg(long = "warn", next_line_help = false)]
    pub warn: bool,

    /// Quiet mode
    #[arg(short = 'q', long = "quiet", next_line_help = false)]
    pub quiet: bool,

    /// Benchmark mode
    #[arg(long = "benchmark", next_line_help = false)]
    pub benchmark: bool,

    /// Maximum file size (e.g., 1G, 512M) [default: 10G]
    #[arg(long = "max-file-size", default_value_t = String::from("10G"), next_line_help = false, hide_default_value = true)]
    pub max_file_size: String,

    /// Maximum number of files to process [default: 10000]
    #[arg(long = "max-files", default_value_t = config::DEFAULT_MAX_FILES, next_line_help = false, hide_default_value = true)]
    pub max_files: usize,

    /// Output results in JSON format
    #[arg(long = "json", conflicts_with = "yaml", next_line_help = false)]
    pub json: bool,

    /// Output results in YAML format
    #[arg(long = "yaml", conflicts_with = "json", next_line_help = false)]
    pub yaml: bool,

    /// Files to process
    #[arg(name = "FILE", next_line_help = false)]
    pub files: Vec<PathBuf>,
}

impl Cli {
    pub fn get_output_format(&self) -> config::OutputFormat {
        if self.json {
            config::OutputFormat::Json
        } else if self.yaml {
            config::OutputFormat::Yaml
        } else {
            config::OutputFormat::Text
        }
    }

    pub fn to_config(&self) -> io::Result<config::Config> {
        let max_file_size = crate::util::parse_size(&self.max_file_size)?;

        Ok(config::Config {
            max_file_size,
            max_files: self.max_files,
            output_format: self.get_output_format(),
            benchmark: self.benchmark,
        })
    }
}

use std::io;
