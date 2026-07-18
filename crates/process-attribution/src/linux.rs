use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::Path;

use crate::ProcessAttributionError;

const PROC_ROOT: &str = "/proc";
const TCP_ESTABLISHED: &str = "01";

pub(super) fn resolve(
    client: SocketAddr,
    server: SocketAddr,
) -> Result<Option<u32>, ProcessAttributionError> {
    let (table_path, client, server) = match (client, server) {
        (SocketAddr::V4(client), SocketAddr::V4(server)) => {
            ("/proc/net/tcp", format_ipv4(client), format_ipv4(server))
        }
        (SocketAddr::V6(client), SocketAddr::V6(server)) => {
            ("/proc/net/tcp6", format_ipv6(client), format_ipv6(server))
        }
        _ => return Err(ProcessAttributionError::AddressFamilyMismatch),
    };
    let table = fs::read_to_string(table_path)?;
    let Some(inode) = find_socket_inode(&table, &client, &server)? else {
        return Ok(None);
    };
    find_unique_owner(Path::new(PROC_ROOT), inode)
}

fn find_socket_inode(
    table: &str,
    client: &str,
    server: &str,
) -> Result<Option<u64>, ProcessAttributionError> {
    let mut matching_inode = None;
    for line in table.lines().skip(1) {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        if columns.len() < 10 {
            return Err(ProcessAttributionError::InvalidSystemTable);
        }
        if columns[1] != client || columns[2] != server || columns[3] != TCP_ESTABLISHED {
            continue;
        }
        let inode = columns[9]
            .parse::<u64>()
            .map_err(|_| ProcessAttributionError::InvalidSystemTable)?;
        if inode == 0 {
            return Ok(None);
        }
        if matching_inode.is_some_and(|existing| existing != inode) {
            return Ok(None);
        }
        matching_inode = Some(inode);
    }
    Ok(matching_inode)
}

fn find_unique_owner(proc_root: &Path, inode: u64) -> Result<Option<u32>, ProcessAttributionError> {
    let expected = format!("socket:[{inode}]");
    let mut owners = BTreeSet::new();
    for process in fs::read_dir(proc_root)? {
        let process = match process {
            Ok(process) => process,
            Err(error) if transient_proc_error(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        let Some(process_id) = process
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let descriptors = match fs::read_dir(process.path().join("fd")) {
            Ok(descriptors) => descriptors,
            Err(error) if transient_proc_error(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        for descriptor in descriptors {
            let descriptor = match descriptor {
                Ok(descriptor) => descriptor,
                Err(error) if transient_proc_error(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            let target = match fs::read_link(descriptor.path()) {
                Ok(target) => target,
                Err(error) if transient_proc_error(&error) => continue,
                Err(error) => return Err(error.into()),
            };
            if target == Path::new(&expected) {
                owners.insert(process_id);
                if owners.len() > 1 {
                    return Ok(None);
                }
                break;
            }
        }
    }
    Ok(owners.into_iter().next())
}

fn transient_proc_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    )
}

fn format_ipv4(address: SocketAddrV4) -> String {
    format!(
        "{:08X}:{:04X}",
        u32::from_le_bytes(address.ip().octets()),
        address.port()
    )
}

fn format_ipv6(address: SocketAddrV6) -> String {
    let octets = address.ip().octets();
    let mut encoded = String::with_capacity(37);
    for chunk in octets.chunks_exact(4) {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        encoded.push_str(&format!("{word:08X}"));
    }
    encoded.push(':');
    encoded.push_str(&format!("{:04X}", address.port()));
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_proc_tcp_endpoints() {
        assert_eq!(
            format_ipv4("127.0.0.1:3210".parse().unwrap()),
            "0100007F:0C8A"
        );
        assert_eq!(
            format_ipv6("[::1]:8787".parse().unwrap()),
            "00000000000000000000000001000000:2253"
        );
    }

    #[test]
    fn finds_only_an_exact_established_client_socket() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                     0: 0100007F:C350 0100007F:2253 01 00000000:00000000 00:00000000 00000000 1000 0 111\n\
                     1: 0100007F:2253 0100007F:C350 01 00000000:00000000 00:00000000 00000000 1000 0 222\n\
                     2: 0100007F:C350 0100007F:2253 06 00000000:00000000 00:00000000 00000000 1000 0 333\n";
        assert_eq!(
            find_socket_inode(table, "0100007F:C350", "0100007F:2253").unwrap(),
            Some(111)
        );
    }

    #[test]
    fn rejects_ambiguous_or_malformed_socket_tables() {
        let ambiguous = "header\n\
                         0: A B 01 x x x x x 11\n\
                         1: A B 01 x x x x x 12\n";
        assert_eq!(find_socket_inode(ambiguous, "A", "B").unwrap(), None);
        assert!(matches!(
            find_socket_inode("header\n0: too short", "A", "B"),
            Err(ProcessAttributionError::InvalidSystemTable)
        ));
    }
}
