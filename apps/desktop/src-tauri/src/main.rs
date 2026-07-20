#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

enum StartupCommand {
    Application,
    Watchdog {
        journal: PathBuf,
    },
    #[cfg(target_os = "macos")]
    MacOsProxyHelperDaemon {
        journal: PathBuf,
        status: PathBuf,
        socket: PathBuf,
        endpoint: String,
        owner_pid: u32,
        owner_uid: u32,
    },
    #[cfg(target_os = "macos")]
    MacOsProxyHelperRecover {
        journal: PathBuf,
        owner_uid: u32,
    },
}

fn main() {
    let command = match parse_startup_command(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("CodeIsCheap startup arguments are invalid: {error}");
            std::process::exit(2);
        }
    };
    match command {
        StartupCommand::Application => codeischeap_desktop_lib::run(),
        StartupCommand::Watchdog { journal } => {
            if let Err(error) = codeischeap_proxy_recovery::run_watchdog(&journal) {
                eprintln!("CodeIsCheap proxy recovery failed: {error}");
                std::process::exit(1);
            }
        }
        #[cfg(target_os = "macos")]
        StartupCommand::MacOsProxyHelperDaemon {
            journal,
            status,
            socket,
            endpoint,
            owner_pid,
            owner_uid,
        } => {
            if let Err(error) = codeischeap_proxy_recovery::run_macos_privileged_proxy_helper(
                journal, status, socket, &endpoint, owner_pid, owner_uid,
            ) {
                eprintln!("CodeIsCheap macOS proxy helper failed: {error}");
                std::process::exit(1);
            }
        }
        #[cfg(target_os = "macos")]
        StartupCommand::MacOsProxyHelperRecover { journal, owner_uid } => {
            match codeischeap_proxy_recovery::run_macos_privileged_proxy_recovery(
                journal, owner_uid,
            ) {
                Ok(true) => println!("recovered"),
                Ok(false) => println!("clean"),
                Err(error) => {
                    eprintln!("CodeIsCheap macOS proxy recovery failed: {error}");
                    std::process::exit(1);
                }
            }
        }
    }
}

fn parse_startup_command(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<StartupCommand, String> {
    let mut arguments = arguments.into_iter();
    let Some(first) = arguments.next() else {
        return Ok(StartupCommand::Application);
    };
    match first.as_os_str() {
        value if value == OsStr::new("--journal") => {
            let journal = required_value(&mut arguments, "--journal")?.into();
            ensure_finished(&mut arguments)?;
            Ok(StartupCommand::Watchdog { journal })
        }
        #[cfg(target_os = "macos")]
        value if value == OsStr::new("--macos-proxy-helper-daemon") => {
            let journal = named_value(&mut arguments, "--journal")?.into();
            let status = named_value(&mut arguments, "--status")?.into();
            let socket = named_value(&mut arguments, "--socket")?.into();
            let endpoint = unicode_value(named_value(&mut arguments, "--endpoint")?, "endpoint")?;
            let owner_pid =
                numeric_value(named_value(&mut arguments, "--owner-pid")?, "owner PID")?;
            let owner_uid =
                numeric_value(named_value(&mut arguments, "--owner-uid")?, "owner UID")?;
            ensure_finished(&mut arguments)?;
            Ok(StartupCommand::MacOsProxyHelperDaemon {
                journal,
                status,
                socket,
                endpoint,
                owner_pid,
                owner_uid,
            })
        }
        #[cfg(target_os = "macos")]
        value if value == OsStr::new("--macos-proxy-helper-recover") => {
            let journal = named_value(&mut arguments, "--journal")?.into();
            let owner_uid =
                numeric_value(named_value(&mut arguments, "--owner-uid")?, "owner UID")?;
            ensure_finished(&mut arguments)?;
            Ok(StartupCommand::MacOsProxyHelperRecover { journal, owner_uid })
        }
        _ => Ok(StartupCommand::Application),
    }
}

fn named_value(
    arguments: &mut impl Iterator<Item = OsString>,
    expected_name: &str,
) -> Result<OsString, String> {
    let name = arguments
        .next()
        .ok_or_else(|| format!("missing {expected_name}"))?;
    if name != OsStr::new(expected_name) {
        return Err(format!("expected {expected_name}"));
    }
    required_value(arguments, expected_name)
}

fn required_value(
    arguments: &mut impl Iterator<Item = OsString>,
    name: &str,
) -> Result<OsString, String> {
    arguments
        .next()
        .ok_or_else(|| format!("missing value for {name}"))
}

fn unicode_value(value: OsString, name: &str) -> Result<String, String> {
    value
        .into_string()
        .map_err(|_| format!("{name} must be valid Unicode"))
}

fn numeric_value(value: OsString, name: &str) -> Result<u32, String> {
    unicode_value(value, name)?
        .parse()
        .map_err(|_| format!("{name} must be an unsigned 32-bit integer"))
}

fn ensure_finished(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), String> {
    if arguments.next().is_some() {
        return Err("unexpected trailing arguments".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(|value| OsString::from(*value)).collect()
    }

    #[test]
    fn watchdog_arguments_are_strict() {
        assert!(matches!(
            parse_startup_command(arguments(&["--journal", "recovery.json"])).unwrap(),
            StartupCommand::Watchdog { .. }
        ));
        assert!(parse_startup_command(arguments(&["--journal"])).is_err());
        assert!(
            parse_startup_command(arguments(&["--journal", "recovery.json", "extra"])).is_err()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_helper_arguments_are_strict() {
        let daemon = [
            "--macos-proxy-helper-daemon",
            "--journal",
            "/private/recovery/proxy-recovery.v0.1.json",
            "--status",
            "/private/recovery/helper.status",
            "--socket",
            "/private/tmp/helper.sock",
            "--endpoint",
            "http://127.0.0.1:43125",
            "--owner-pid",
            "123",
            "--owner-uid",
            "501",
        ];
        assert!(matches!(
            parse_startup_command(arguments(&daemon)).unwrap(),
            StartupCommand::MacOsProxyHelperDaemon { .. }
        ));
        assert!(parse_startup_command(arguments(&daemon[..daemon.len() - 1])).is_err());
        assert!(
            parse_startup_command(arguments(&[
                "--macos-proxy-helper-recover",
                "--journal",
                "/private/recovery/proxy-recovery.v0.1.json",
                "--owner-uid",
                "501",
            ]))
            .is_ok()
        );
    }
}
