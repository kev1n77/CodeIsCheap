use std::net::SocketAddr;
use std::process::Command;

use crate::ProcessAttributionError;

const LSOF: &str = "/usr/sbin/lsof";

pub(super) fn resolve(
    client: SocketAddr,
    server: SocketAddr,
) -> Result<Option<u32>, ProcessAttributionError> {
    let output = Command::new(LSOF)
        .args(["-nP", "-a", "-iTCP", "-sTCP:ESTABLISHED", "-Fpfn"])
        .output()?;
    if !output.status.success() {
        if output.status.code() == Some(1) && output.stdout.is_empty() {
            return Ok(None);
        }
        return Err(ProcessAttributionError::CommandFailed(output.status.code()));
    }
    Ok(parse_lsof_pid(
        &String::from_utf8_lossy(&output.stdout),
        client,
        server,
    ))
}

fn parse_lsof_pid(output: &str, client: SocketAddr, server: SocketAddr) -> Option<u32> {
    let expected = format!("{client}->{server}");
    let mut process_id = None;
    for line in output.lines() {
        if let Some(value) = line.strip_prefix('p') {
            process_id = value.parse().ok();
        } else if let Some(name) = line.strip_prefix('n')
            && name.trim_end_matches(" (ESTABLISHED)") == expected
        {
            return process_id.filter(|process_id| *process_id != 0);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_the_exact_client_to_server_socket() {
        let output = "p11\nf8\nn127.0.0.1:8787->127.0.0.1:53110\np42\nf9\nn127.0.0.1:53110->127.0.0.1:8787\n";
        assert_eq!(
            parse_lsof_pid(
                output,
                "127.0.0.1:53110".parse().unwrap(),
                "127.0.0.1:8787".parse().unwrap(),
            ),
            Some(42)
        );
    }
}
