//! Conservative process attribution for active loopback TCP connections.

use std::fmt;
use std::io;
use std::net::SocketAddr;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[derive(Debug)]
pub enum ProcessAttributionError {
    NonLoopbackConnection,
    AddressFamilyMismatch,
    InvalidSystemTable,
    SystemStatus(u32),
    CommandFailed(Option<i32>),
    Io(io::Error),
}

impl fmt::Display for ProcessAttributionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonLoopbackConnection => {
                write!(
                    formatter,
                    "process attribution requires a loopback connection"
                )
            }
            Self::AddressFamilyMismatch => {
                write!(
                    formatter,
                    "process attribution address families do not match"
                )
            }
            Self::InvalidSystemTable => {
                write!(formatter, "the operating system TCP table is malformed")
            }
            Self::SystemStatus(status) => {
                write!(
                    formatter,
                    "the operating system TCP query failed with status {status}"
                )
            }
            Self::CommandFailed(status) => {
                write!(
                    formatter,
                    "the process socket query failed with status {status:?}"
                )
            }
            Self::Io(error) => write!(formatter, "the process socket query failed: {error}"),
        }
    }
}

impl std::error::Error for ProcessAttributionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ProcessAttributionError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn resolve_loopback_client_pid(
    client: SocketAddr,
    server: SocketAddr,
) -> Result<Option<u32>, ProcessAttributionError> {
    if !client.ip().is_loopback() || !server.ip().is_loopback() {
        return Err(ProcessAttributionError::NonLoopbackConnection);
    }
    if client.is_ipv4() != server.is_ipv4() {
        return Err(ProcessAttributionError::AddressFamilyMismatch);
    }

    #[cfg(windows)]
    {
        windows::resolve(client, server)
    }
    #[cfg(target_os = "macos")]
    {
        macos::resolve(client, server)
    }
    #[cfg(target_os = "linux")]
    {
        linux::resolve(client, server)
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = (client, server);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_loopback_and_mixed_family_connections() {
        assert!(matches!(
            resolve_loopback_client_pid(
                "192.0.2.10:1234".parse().unwrap(),
                "127.0.0.1:8787".parse().unwrap()
            ),
            Err(ProcessAttributionError::NonLoopbackConnection)
        ));
        assert!(matches!(
            resolve_loopback_client_pid(
                "127.0.0.1:1234".parse().unwrap(),
                "[::1]:8787".parse().unwrap()
            ),
            Err(ProcessAttributionError::AddressFamilyMismatch)
        ));
    }
}
