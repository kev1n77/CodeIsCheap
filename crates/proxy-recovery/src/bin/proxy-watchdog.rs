use std::env;
use std::path::PathBuf;

use codeischeap_proxy_recovery::run_watchdog;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some("--journal".as_ref()) {
        return Err("usage: proxy-watchdog --journal <path>".into());
    }
    let journal = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("missing journal path")?;
    if arguments.next().is_some() {
        return Err("unexpected proxy-watchdog argument".into());
    }
    run_watchdog(&journal)?;
    Ok(())
}
