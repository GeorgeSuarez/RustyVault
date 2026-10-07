//! Command-line argument and environment parsing.
//!
//! Kept dependency-free and split from process state so it can be unit
//! tested: [`parse`] receives the arguments and the relevant environment
//! values explicitly.

use std::path::PathBuf;
use std::time::Duration;

use color_eyre::eyre;

pub const ENV_DB_PATH: &str = "RUSTY_VAULT_DB";
pub const ENV_IDLE_LOCK_SECS: &str = "RUSTY_VAULT_IDLE_LOCK_SECS";

pub const DEFAULT_DB_FILE: &str = "rusty-vault.db";
/// Auto-lock after five minutes of inactivity.
pub const DEFAULT_IDLE_LOCK_SECS: u64 = 300;

pub const USAGE: &str = "\
Rusty Vault - terminal password manager

USAGE:
    rusty-vault [OPTIONS]

OPTIONS:
    -d, --db <PATH>              Vault database file [default: rusty-vault.db]
        --idle-lock-secs <SECS>  Auto-lock after inactivity; 0 disables [default: 300]
    -h, --help                   Print this help
    -V, --version                Print the version

ENVIRONMENT:
    RUSTY_VAULT_DB               Default database path
    RUSTY_VAULT_IDLE_LOCK_SECS   Default idle-lock timeout in seconds
";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Run,
    Help,
    Version,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cli {
    pub db_path: PathBuf,
    /// `None` disables the idle auto-lock.
    pub idle_lock: Option<Duration>,
    pub action: Action,
}

/// Environment values relevant to the CLI, injected so tests never need to
/// mutate the process environment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Env {
    pub db_path: Option<String>,
    pub idle_lock_secs: Option<String>,
}

impl Env {
    pub fn from_process() -> Self {
        Self {
            db_path: std::env::var(ENV_DB_PATH).ok(),
            idle_lock_secs: std::env::var(ENV_IDLE_LOCK_SECS).ok(),
        }
    }
}

pub fn parse<I>(args: I, env: Env) -> eyre::Result<Cli>
where
    I: IntoIterator<Item = String>,
{
    let mut db_path = env
        .db_path
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DB_FILE));

    let mut idle_lock_secs = match &env.idle_lock_secs {
        Some(raw) => parse_secs(raw).map_err(|e| eyre::eyre!("{ENV_IDLE_LOCK_SECS}: {e}"))?,
        None => DEFAULT_IDLE_LOCK_SECS,
    };

    let mut action = Action::Run;

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let (flag, inline_value) = match arg.split_once('=') {
            Some((flag, value)) => (flag.to_string(), Some(value.to_string())),
            None => (arg, None),
        };
        match flag.as_str() {
            "-h" | "--help" => action = Action::Help,
            "-V" | "--version" => action = Action::Version,
            "-d" | "--db" => {
                let value = option_value(&flag, inline_value, &mut args)?;
                if value.is_empty() {
                    eyre::bail!("{flag} requires a non-empty path");
                }
                db_path = PathBuf::from(value);
            }
            "--idle-lock-secs" => {
                let value = option_value(&flag, inline_value, &mut args)?;
                idle_lock_secs =
                    parse_secs(&value).map_err(|e| eyre::eyre!("--idle-lock-secs: {e}"))?;
            }
            other => eyre::bail!("unknown argument: {other} (try --help)"),
        }
    }

    let idle_lock = match idle_lock_secs {
        0 => None,
        secs => Some(Duration::from_secs(secs)),
    };

    Ok(Cli {
        db_path,
        idle_lock,
        action,
    })
}

fn option_value<I>(flag: &str, inline: Option<String>, args: &mut I) -> eyre::Result<String>
where
    I: Iterator<Item = String>,
{
    inline
        .or_else(|| args.next())
        .ok_or_else(|| eyre::eyre!("{flag} requires a value"))
}

fn parse_secs(raw: &str) -> eyre::Result<u64> {
    raw.trim()
        .parse::<u64>()
        .map_err(|_| eyre::eyre!("\"{raw}\" is not a valid number of seconds"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str]) -> eyre::Result<Cli> {
        parse(args.iter().map(|s| s.to_string()), Env::default())
    }

    fn args(cli: &Cli) -> (&PathBuf, Option<Duration>, Action) {
        (&cli.db_path, cli.idle_lock, cli.action)
    }

    #[test]
    fn defaults_to_cwd_database_and_five_minute_lock() {
        let cli = parse_args(&[]).unwrap();
        assert_eq!(cli.db_path, PathBuf::from(DEFAULT_DB_FILE));
        assert_eq!(cli.idle_lock, Some(Duration::from_secs(300)));
        assert_eq!(cli.action, Action::Run);
    }

    #[test]
    fn parses_db_flag_in_both_forms() {
        let cli = parse_args(&["--db", "/tmp/a.db"]).unwrap();
        assert_eq!(cli.db_path, PathBuf::from("/tmp/a.db"));

        let cli = parse_args(&["--db=/tmp/b.db"]).unwrap();
        assert_eq!(cli.db_path, PathBuf::from("/tmp/b.db"));

        let cli = parse_args(&["-d", "/tmp/c.db"]).unwrap();
        assert_eq!(cli.db_path, PathBuf::from("/tmp/c.db"));
    }

    #[test]
    fn flag_overrides_environment() {
        let env = Env {
            db_path: Some("/env/vault.db".to_string()),
            idle_lock_secs: Some("60".to_string()),
        };
        let cli = parse(["--db=/flag/vault.db".to_string()], env).unwrap();
        assert_eq!(cli.db_path, PathBuf::from("/flag/vault.db"));
        assert_eq!(cli.idle_lock, Some(Duration::from_secs(60)));
    }

    #[test]
    fn environment_is_used_when_flags_are_absent() {
        let env = Env {
            db_path: Some("/env/vault.db".to_string()),
            idle_lock_secs: None,
        };
        let cli = parse(Vec::<String>::new(), env).unwrap();
        assert_eq!(cli.db_path, PathBuf::from("/env/vault.db"));
    }

    #[test]
    fn zero_seconds_disables_idle_lock() {
        let cli = parse_args(&["--idle-lock-secs", "0"]).unwrap();
        assert_eq!(cli.idle_lock, None);
        let cli = parse_args(&["--idle-lock-secs=0"]).unwrap();
        assert_eq!(cli.idle_lock, None);
    }

    #[test]
    fn help_and_version_are_actions() {
        assert_eq!(parse_args(&["--help"]).unwrap().action, Action::Help);
        assert_eq!(parse_args(&["-h"]).unwrap().action, Action::Help);
        assert_eq!(parse_args(&["--version"]).unwrap().action, Action::Version);
        assert_eq!(parse_args(&["-V"]).unwrap().action, Action::Version);
    }

    #[test]
    fn rejects_unknown_arguments_and_bad_values() {
        assert!(parse_args(&["--nope"]).is_err());
        assert!(parse_args(&["--db"]).is_err());
        assert!(parse_args(&["--db="]).is_err());
        assert!(parse_args(&["--idle-lock-secs", "soon"]).is_err());
        assert!(
            parse(
                Vec::<String>::new(),
                Env {
                    db_path: None,
                    idle_lock_secs: Some("soon".to_string()),
                }
            )
            .is_err()
        );
    }

    #[test]
    fn parses_through_action_helper() {
        let cli = parse_args(&["-V"]).unwrap();
        assert_eq!(
            args(&cli),
            (
                &PathBuf::from(DEFAULT_DB_FILE),
                Some(Duration::from_secs(300)),
                Action::Version
            )
        );
    }
}
