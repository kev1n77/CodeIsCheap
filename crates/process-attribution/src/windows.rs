use std::ffi::c_void;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    TCP_TABLE_OWNER_PID_CONNECTIONS,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use crate::ProcessAttributionError;

pub(super) fn resolve(
    client: SocketAddr,
    server: SocketAddr,
) -> Result<Option<u32>, ProcessAttributionError> {
    match (client, server) {
        (SocketAddr::V4(client), SocketAddr::V4(server)) => resolve_ipv4(client, server),
        (SocketAddr::V6(client), SocketAddr::V6(server)) => resolve_ipv6(client, server),
        _ => Err(ProcessAttributionError::AddressFamilyMismatch),
    }
}

fn resolve_ipv4(
    client: SocketAddrV4,
    server: SocketAddrV4,
) -> Result<Option<u32>, ProcessAttributionError> {
    let table = tcp_table(u32::from(AF_INET))?;
    for row in table_rows::<MIB_TCPROW_OWNER_PID>(&table)? {
        let local = SocketAddrV4::new(
            Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()),
            network_port(row.dwLocalPort),
        );
        let remote = SocketAddrV4::new(
            Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes()),
            network_port(row.dwRemotePort),
        );
        if local == client && remote == server {
            return Ok((row.dwOwningPid != 0).then_some(row.dwOwningPid));
        }
    }
    Ok(None)
}

fn resolve_ipv6(
    client: SocketAddrV6,
    server: SocketAddrV6,
) -> Result<Option<u32>, ProcessAttributionError> {
    let table = tcp_table(u32::from(AF_INET6))?;
    for row in table_rows::<MIB_TCP6ROW_OWNER_PID>(&table)? {
        let local = SocketAddrV6::new(
            Ipv6Addr::from(row.ucLocalAddr),
            network_port(row.dwLocalPort),
            0,
            row.dwLocalScopeId,
        );
        let remote = SocketAddrV6::new(
            Ipv6Addr::from(row.ucRemoteAddr),
            network_port(row.dwRemotePort),
            0,
            row.dwRemoteScopeId,
        );
        if local == client && remote == server {
            return Ok((row.dwOwningPid != 0).then_some(row.dwOwningPid));
        }
    }
    Ok(None)
}

fn tcp_table(address_family: u32) -> Result<Vec<u8>, ProcessAttributionError> {
    let mut size = 0_u32;
    let first = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut size,
            0,
            address_family,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        )
    };
    if first != ERROR_INSUFFICIENT_BUFFER && first != NO_ERROR {
        return Err(ProcessAttributionError::SystemStatus(first));
    }
    if size < size_of::<u32>() as u32 {
        return Err(ProcessAttributionError::InvalidSystemTable);
    }
    let mut table = vec![0_u8; size as usize];
    let status = unsafe {
        GetExtendedTcpTable(
            table.as_mut_ptr().cast::<c_void>(),
            &mut size,
            0,
            address_family,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        )
    };
    if status != NO_ERROR {
        return Err(ProcessAttributionError::SystemStatus(status));
    }
    table.truncate(size as usize);
    Ok(table)
}

fn table_rows<T: Copy>(table: &[u8]) -> Result<Vec<T>, ProcessAttributionError> {
    if table.len() < size_of::<u32>() {
        return Err(ProcessAttributionError::InvalidSystemTable);
    }
    let count = unsafe { ptr::read_unaligned(table.as_ptr().cast::<u32>()) } as usize;
    let rows_size = count
        .checked_mul(size_of::<T>())
        .and_then(|size| size.checked_add(size_of::<u32>()))
        .ok_or(ProcessAttributionError::InvalidSystemTable)?;
    if rows_size > table.len() {
        return Err(ProcessAttributionError::InvalidSystemTable);
    }
    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        let offset = size_of::<u32>() + index * size_of::<T>();
        rows.push(unsafe { ptr::read_unaligned(table.as_ptr().add(offset).cast::<T>()) });
    }
    Ok(rows)
}

fn network_port(value: u32) -> u16 {
    u16::from_be(value as u16)
}
