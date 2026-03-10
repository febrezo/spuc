use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "spuc")]
#[command(
    about = "SPUC is a Rust CLI that parses STIX 2.1 patterns, normalizes them to IR, and emits detection content for EQL, KQL, Sigma, Snort, Suricata, and YARA.",
    arg_required_else_help = true
)]
pub struct Cli {
    /// Print version and exit
    #[arg(short = 'V', long = "version", global = true)]
    pub version: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Convert STIX patterns to selected targets
    Convert {
        #[arg(
            short = 't',
            long = "to",
            value_enum,
            num_args = 0..,
            default_values_t = Vec::<OutputTarget>::new()
        )]
        to: Vec<OutputTarget>,
        /// Optional Sigma backend targets (e.g. splunk, kusto) delegated to sigma-cli
        #[arg(short = 's', long = "sigma-target", num_args = 1..)]
        sigma_targets: Vec<String>,

        /// STIX pattern(s) provided directly. Repeatable.
        #[arg(short = 'r', long = "rule", conflicts_with = "file", num_args = 1..)]
        rule: Vec<String>,

        /// File containing one STIX pattern per line
        #[arg(short = 'f', long = "file")]
        file: Option<PathBuf>,

        /// Directory to write CSV results
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,

        /// Optional human readable description to embed in supported outputs
        #[arg(short = 'd', long = "description")]
        description: Option<String>,

        /// Optional analyst/indicator confidence (0..100), preserved as emitter metadata when possible
        #[arg(
            short = 'c',
            long = "rule-confidence",
            value_parser = clap::value_parser!(u8).range(0..=100)
        )]
        rule_confidence: Option<u8>,

        /// Conversion mode: strict (all predicates must map) or partial (emit supported subset)
        #[arg(short = 'm', long = "mode", value_enum, default_value_t = ConversionMode::Strict)]
        mode: ConversionMode,
    },

    /// Verify that STIX pattern(s) parse/normalize successfully
    Verify {
        #[arg(short = 'r', long = "rule", conflicts_with = "file", num_args = 1..)]
        rule: Vec<String>,
        #[arg(short = 'f', long = "file")]
        file: Option<PathBuf>,
    },

    /// Show converter documentation and coverage details
    #[command(name = "doc", visible_alias = "coverage", visible_alias = "cover")]
    Doc {
        #[arg(short = 't', long = "target", value_enum)]
        target: Option<OutputTarget>,
    },

    /// Guided CTF-like learning mode for writing STIX patterns
    #[command(name = "learn")]
    Learn {
        /// List available learning challenges and exit
        #[arg(short = 'l', long = "list")]
        list: bool,
        /// Optional challenge id (e.g. core001, core002, time001)
        challenge: Option<String>,
    },

    /// Run a simple JSON-RPC-like service
    #[command(
        name = "serve",
        visible_alias = "service",
        long_about = "Run a simple JSON-RPC-like service on HTTP.\n\nExamples:\n  spuc serve --port 8080\n  curl -H 'Authorization: Bearer <token>' -X POST -d '{\"rule\":\"[ipv4-addr:value = \\'1.1.1.1\\']\",\"to\":[\"snort\"]}' http://localhost:8080/rpc"
    )]
    Serve {
        #[arg(short = 'p', long = "port", default_value_t = 8080)]
        port: u16,
        /// Authentication token; if not provided, a random UUID is generated
        #[arg(short = 'k', long = "token")]
        token: Option<String>,
    },

    /// Interactive TUI (REPL-style)
    #[command(name = "interact", visible_alias = "interactive")]
    Interact {},
}

#[derive(Debug, Clone, ValueEnum, PartialEq, Eq)]
pub enum ConversionMode {
    Strict,
    Partial,
}

#[derive(Debug, Clone, ValueEnum, PartialEq, Eq, Hash)]
pub enum OutputTarget {
    Sigma,
    Eql,
    Kql,
    Snort,
    Suricata,
    Yara,
}
