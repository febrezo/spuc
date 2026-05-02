use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "spuc")]
#[command(
    about = "SPUC is a Rust CLI that parses STIX 2.1 patterns, normalizes them to IR, and emits detection content for EQL, KQL, Sigma, Snort, Suricata, and YARA."
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
    /// Emulate observable behaviour defined in the STIX Pattern.
    #[command(name = "emulate", display_order = 1)]
    Emulate {
        #[arg(
            short = 't',
            long = "to",
            value_enum,
            num_args = 0..,
            default_values_t = Vec::<AbilityTarget>::new()
        )]
        to: Vec<AbilityTarget>,

        /// STIX pattern(s) provided directly. Repeatable.
        #[arg(short = 'r', long = "rule", conflicts_with = "file", num_args = 1..)]
        rule: Vec<String>,

        /// File containing one STIX pattern per line
        #[arg(short = 'f', long = "file")]
        file: Option<PathBuf>,

        /// Directory to write exported artifacts
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,

        /// Optional human readable description to embed in supported artifacts
        #[arg(short = 'd', long = "description")]
        description: Option<String>,

        /// Optional ATT&CK technique id to attach to generated emulation artifacts
        #[arg(long = "ttp")]
        ttp: Option<String>,

        /// Optional analyst/indicator confidence (0..100), mapped to ability confidence
        #[arg(
            short = 'c',
            long = "rule-confidence",
            value_parser = clap::value_parser!(u8).range(0..=100)
        )]
        rule_confidence: Option<u8>,

        /// Emulation mode: strict (fail on unsupported observable scope) or partial (skip unsupported rules)
        #[arg(short = 'm', long = "mode", value_enum, default_value_t = ConversionMode::Strict)]
        mode: ConversionMode,

        /// Export formats to write to --output (e.g. csv)
        #[arg(short = 'x', long = "export", value_enum, value_delimiter = ',', num_args = 1..)]
        export: Vec<ExportFormat>,

        /// Force recalculation of cached internal dual-flow evaluations
        #[arg(long = "refresh")]
        refresh: bool,
    },

    /// Run a JSON-RPC service exposing SPUC functionality.
    #[command(
        name = "jsonrpc",
        alias = "serve",
        display_order = 2,
        long_about = "Run a JSON-RPC service exposing SPUC functionality.\n\nExamples:\n  spuc jsonrpc --port 8080\n  curl -X POST 'http://127.0.0.1:8080/rpc' -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' --data-raw \"{\\\"rule\\\":\\\"[ipv4-addr:value = '1.1.1.1']\\\",\\\"to\\\":[\\\"snort\\\"]}\""
    )]
    Jsonrpc {
        #[arg(short = 'p', long = "port", default_value_t = 8080)]
        port: u16,
        /// Authentication token; if not provided, a random UUID is generated
        #[arg(short = 'k', long = "token")]
        token: Option<String>,
    },

    /// Translate STIX patterns to selected targets
    #[command(display_order = 3)]
    Translate {
        #[arg(short = 't', long = "to", value_delimiter = ',', num_args = 0..)]
        to: Vec<String>,
        /// Optional backend ids delegated from Sigma output through sigma (e.g. splunk, elasticsearch, secops)
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

        /// Optional ATT&CK technique id to attach to generated emulation artifacts
        #[arg(long = "ttp")]
        ttp: Option<String>,

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

        /// Export formats to write to --output (e.g. csv)
        #[arg(short = 'x', long = "export", value_enum, value_delimiter = ',', num_args = 1..)]
        export: Vec<ExportFormat>,

        /// Force recalculation of cached internal dual-flow evaluations
        #[arg(long = "refresh")]
        refresh: bool,
    },

    /// Verify that STIX pattern(s) parse/normalize successfully
    #[command(display_order = 4)]
    Verify {
        #[arg(short = 'r', long = "rule", conflicts_with = "file", num_args = 1..)]
        rule: Vec<String>,
        #[arg(short = 'f', long = "file")]
        file: Option<PathBuf>,
    },

    /// Print version and exit
    #[command(name = "version", display_order = 5)]
    Version {},

    /// Inspect sigma availability and dynamic sigma targets.
    #[command(name = "sigma", display_order = 6)]
    Sigma {
        #[command(subcommand)]
        command: SigmaCommands,
    },

    /// Localized web interface for catalog browsing, tutorials and adversary planning
    #[command(name = "web", display_order = 7)]
    Web {
        #[arg(short = 'p', long = "port", default_value_t = 8090)]
        port: u16,
        /// Administrator username used for local login bootstrap
        #[arg(long = "admin-user", default_value = "admin")]
        admin_user: String,
        /// Administrator password; if omitted, SPUC generates one and prints it at startup
        #[arg(long = "admin-password")]
        admin_password: Option<String>,
        /// Disable login screen and enter directly as local administrator
        #[arg(long = "no-login", default_value_t = false)]
        no_login: bool,
        /// Do not open the system browser after starting the local web server
        #[arg(long = "no-open", default_value_t = false)]
        no_open: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum SigmaCommands {
    /// Print sigma detection status and compatible backends.
    #[command(name = "status", display_order = 1)]
    Status,
    /// List only dynamic sigma targets exposed by SPUC.
    #[command(name = "list-targets", display_order = 2)]
    ListTargets,
    /// Re-detect sigma runtime and overwrite cached sigma configuration.
    #[command(name = "update-config", display_order = 3)]
    UpdateConfig,
}

#[derive(Debug, Subcommand)]
pub enum RuleCommands {
    /// Delete one rule after manual confirmation
    #[command(display_order = 1)]
    Delete {
        /// Rule index or rule id
        id: String,
    },
    /// Edit mutable rule fields
    #[command(display_order = 2)]
    Edit {
        /// Rule index or rule id
        id: String,
        /// Editable display name
        #[arg(long = "name")]
        name: Option<String>,
        /// Editable description
        #[arg(long = "description")]
        description: Option<String>,
        /// Editable confidence (0..100)
        #[arg(long = "confidence", value_parser = clap::value_parser!(u8).range(0..=100))]
        confidence: Option<u8>,
    },
    /// Export one rule as emulation artifacts
    #[command(display_order = 3)]
    Export {
        /// Rule index or rule id
        id: String,
        /// Export target(s)
        #[arg(short = 't', long = "to", value_enum, num_args = 1..)]
        to: Vec<AbilityTarget>,
        /// Directory to write exported artifacts
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
    },
    /// List rules and print a table
    #[command(display_order = 4)]
    List {
        /// Maximum rows to print
        #[arg(long = "limit", default_value_t = 200)]
        limit: usize,
    },
    /// Search rules and print a table
    #[command(display_order = 5)]
    Search {
        /// Optional search text across visible columns
        query: Option<String>,
        /// Maximum rows to print
        #[arg(long = "limit", default_value_t = 200)]
        limit: usize,
    },
    /// Show one rule by index or id
    #[command(display_order = 6)]
    Show {
        /// Rule index or rule id
        id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum AdversaryCommands {
    /// Delete one adversary after manual confirmation
    #[command(display_order = 1)]
    Delete {
        /// Adversary index or id
        id: String,
    },
    /// Edit mutable adversary fields
    #[command(display_order = 2)]
    Edit {
        /// Adversary index or id
        id: String,
        /// Editable name
        #[arg(long = "name")]
        name: Option<String>,
        /// Editable description
        #[arg(long = "description")]
        description: Option<String>,
        /// Editable confidence (0..100)
        #[arg(long = "confidence", value_parser = clap::value_parser!(u8).range(0..=100))]
        confidence: Option<u8>,
    },
    /// Export one adversary for an executor
    #[command(display_order = 3)]
    Export {
        /// Adversary index or id
        id: String,
        /// Executor used to compile outputs
        #[arg(long = "to", value_enum)]
        to: AbilityTarget,
        /// Directory to write exported artifacts
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
        /// Output blocks to render
        #[arg(
            long = "show",
            value_enum,
            value_delimiter = ',',
            num_args = 1..,
            default_values_t = vec![BuildOutput::Summary, BuildOutput::Manifest]
        )]
        show: Vec<BuildOutput>,
    },
    /// List adversaries and print a table
    #[command(display_order = 4)]
    List {
        /// Maximum rows to print
        #[arg(long = "limit", default_value_t = 200)]
        limit: usize,
    },
    /// Search adversaries and print a table
    #[command(display_order = 5)]
    Search {
        /// Optional search text across visible columns
        query: Option<String>,
        /// Maximum rows to print
        #[arg(long = "limit", default_value_t = 200)]
        limit: usize,
    },
    /// Show one adversary by index or id
    #[command(display_order = 6)]
    Show {
        /// Adversary index or id
        id: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ConversionMode {
    Strict,
    Partial,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, Hash)]
pub enum OutputTarget {
    Sigma,
    Eql,
    Kql,
    Snort,
    Suricata,
    Yara,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum AbilityTarget {
    SpucAgent,
    Bash,
    Powershell,
    AtomicRedTeam,
    MitreCaldera,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum BuildOutput {
    Summary,
    Canonical,
    Artifact,
    Manifest,
    All,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ExportFormat {
    Csv,
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands};
    use clap::Parser;

    #[test]
    fn parse_allows_no_subcommand_for_standalone_mode() {
        let cli = Cli::try_parse_from(["spuc"]).expect("parse root invocation");
        assert!(cli.command.is_none());
        assert!(!cli.version);
    }

    #[test]
    fn translate_accepts_freeform_targets() {
        let cli = Cli::try_parse_from([
            "spuc",
            "translate",
            "--to",
            "sigma",
            "--to",
            "sigma-to-splunk",
            "--to",
            "kql",
            "--rule",
            "[process:name = 'cmd.exe']",
        ])
        .expect("parse translate targets");

        match cli.command {
            Some(Commands::Translate { to, .. }) => {
                assert_eq!(
                    to,
                    vec![
                        "sigma".to_string(),
                        "sigma-to-splunk".to_string(),
                        "kql".to_string(),
                    ]
                );
            }
            _ => panic!("expected translate command"),
        }
    }

    #[test]
    fn sigma_subcommands_parse() {
        let cli = Cli::try_parse_from(["spuc", "sigma", "status"]).expect("parse sigma status");
        match cli.command {
            Some(Commands::Sigma { .. }) => {}
            _ => panic!("expected sigma command"),
        }

        let cli = Cli::try_parse_from(["spuc", "sigma", "update-config"])
            .expect("parse sigma update-config");
        match cli.command {
            Some(Commands::Sigma { .. }) => {}
            _ => panic!("expected sigma command"),
        }
    }
}
