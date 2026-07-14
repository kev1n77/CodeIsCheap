use std::env;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use codeischeap_proxy_recovery::{FileProxyBackend, ProxyBackend, ProxySession, ProxySettings};

#[cfg(windows)]
use codeischeap_proxy_recovery::WindowsProxyBackend;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    match arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .as_deref()
    {
        Some("hold") => {
            let state = next_path(&mut arguments, "state")?;
            let journal = next_path(&mut arguments, "journal")?;
            let ready = next_path(&mut arguments, "ready")?;
            let watchdog = next_path(&mut arguments, "watchdog")?;
            ensure_finished(&mut arguments)?;
            hold(
                FileProxyBackend::new(state),
                desired_settings(3210),
                journal,
                ready,
                watchdog,
            )
        }
        #[cfg(windows)]
        Some("hold-windows") => {
            let journal = next_path(&mut arguments, "journal")?;
            let ready = next_path(&mut arguments, "ready")?;
            let watchdog = next_path(&mut arguments, "watchdog")?;
            let port: u16 = arguments
                .next()
                .ok_or("missing proxy port")?
                .into_string()
                .map_err(|_| "proxy port must be UTF-8")?
                .parse()?;
            ensure_finished(&mut arguments)?;
            hold(
                WindowsProxyBackend::system(),
                desired_settings(port),
                journal,
                ready,
                watchdog,
            )
        }
        _ => Err("usage: proxy-recovery-spike hold <state> <journal> <ready> <watchdog>".into()),
    }
}

fn hold<B: ProxyBackend>(
    backend: B,
    desired: ProxySettings,
    journal: PathBuf,
    ready: PathBuf,
    watchdog: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let _session = ProxySession::begin(backend, desired, journal, watchdog)?;
    fs::write(ready, b"ready\n")?;
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn desired_settings(port: u16) -> ProxySettings {
    ProxySettings::Manual {
        http_proxy: format!("http://127.0.0.1:{port}"),
        https_proxy: format!("http://127.0.0.1:{port}"),
        bypass: vec!["localhost".to_owned(), "127.0.0.1".to_owned()],
    }
}

fn ensure_finished(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.next().is_some() {
        return Err("unexpected proxy-recovery-spike argument".into());
    }
    Ok(())
}

fn next_path(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name} path").into())
}
