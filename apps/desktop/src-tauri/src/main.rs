#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() == Some(std::ffi::OsStr::new("--journal")) {
        let Some(journal) = arguments.next() else {
            std::process::exit(2);
        };
        if arguments.next().is_some() {
            std::process::exit(2);
        }
        if let Err(error) = codeischeap_proxy_recovery::run_watchdog(std::path::Path::new(&journal))
        {
            eprintln!("CodeIsCheap proxy recovery failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    codeischeap_desktop_lib::run();
}
