//! The IPv4 default gateway of one interface, from the kernel's routing
//! table (`sysctl` with `NET_RT_FLAGS`): on iOS no API names the router of
//! a network the app joined, and a direct link's joiner connects to it
//! (PROTOCOL §10.2: the hotspot's or group's own address).
//!
//! The table is read once into a buffer the kernel sized; every message
//! and address is bounds-checked against its own length before it is
//! read. Nothing is written.

#![allow(
    unsafe_code,
    reason = "one sysctl call; the block states why it is sound"
)]

use std::ffi::{c_int, c_void};
use std::net::Ipv4Addr;

const CTL_NET: c_int = 4;
const PF_ROUTE: c_int = 17;
const AF_INET: c_int = 2;
const NET_RT_FLAGS: c_int = 2;
const RTF_GATEWAY: c_int = 0x2;
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
/// `sizeof(struct rt_msghdr)` on Darwin: the header, then `rt_metrics`
/// (14 four-byte fields).
const HEADER: usize = 92;
/// Routing messages read at most (a phone has a few dozen routes).
const MAX_TABLE: usize = 1 << 20;

unsafe extern "C" {
    fn sysctl(
        name: *const c_int,
        namelen: u32,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *const c_void,
        newlen: usize,
    ) -> c_int;
}

/// The IPv4 default gateway on the interface with index `interface`, if
/// the table has one.
#[must_use]
pub fn gateway(interface: u32) -> Option<Ipv4Addr> {
    default_gateway(&table()?, interface)
}

/// The IPv4 routing table's gateway routes, as the kernel's messages.
fn table() -> Option<Vec<u8>> {
    let name = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_GATEWAY];
    for _ in 0..3 {
        let mut size = 0_usize;
        // SAFETY: a size query (no output buffer); `name` and `size` outlive
        // the call.
        let status = unsafe {
            sysctl(
                name.as_ptr(),
                6,
                core::ptr::null_mut(),
                &raw mut size,
                core::ptr::null(),
                0,
            )
        };
        if status != 0 || size > MAX_TABLE {
            return None;
        }
        // Room for routes added meanwhile.
        let mut buffer = vec![0_u8; size + 512];
        let mut written = buffer.len();
        // SAFETY: the buffer holds `written` bytes; the kernel writes at
        // most that many and reports how many it wrote.
        let status = unsafe {
            sysctl(
                name.as_ptr(),
                6,
                buffer.as_mut_ptr().cast(),
                &raw mut written,
                core::ptr::null(),
                0,
            )
        };
        if status == 0 {
            buffer.truncate(written);
            return Some(buffer);
        }
    }
    None
}

/// The gateway of the first default route (destination 0.0.0.0) on
/// `interface` in `table`, a run of `rt_msghdr` messages.
fn default_gateway(table: &[u8], interface: u32) -> Option<Ipv4Addr> {
    let mut rest = table;
    while rest.len() >= HEADER {
        let length = usize::from(u16::from_ne_bytes([rest[0], rest[1]]));
        if length < HEADER || length > rest.len() {
            return None;
        }
        let (message, next) = rest.split_at(length);
        rest = next;
        let index = u32::from(u16::from_ne_bytes([message[4], message[5]]));
        let flags = i32::from_ne_bytes([message[8], message[9], message[10], message[11]]);
        let addresses = i32::from_ne_bytes([message[12], message[13], message[14], message[15]]);
        if index != interface || flags & RTF_GATEWAY == 0 {
            continue;
        }
        let (mut destination, mut gateway) = (None, None);
        let mut at = HEADER;
        // The addresses present, in bit order, each rounded up to 4 bytes.
        for bit in 0..8 {
            if addresses & (1 << bit) == 0 {
                continue;
            }
            let Some(&length) = message.get(at) else {
                break;
            };
            let length = usize::from(length);
            let address = message.get(at..at + length.max(1));
            match 1 << bit {
                RTA_DST => destination = address.and_then(ipv4),
                RTA_GATEWAY => gateway = address.and_then(ipv4),
                _ => {}
            }
            at += if length == 0 {
                4
            } else {
                length.next_multiple_of(4)
            };
        }
        if destination == Some(Ipv4Addr::UNSPECIFIED)
            && let Some(gateway) = gateway.filter(|gateway| !gateway.is_unspecified())
        {
            return Some(gateway);
        }
    }
    None
}

/// The address of a `sockaddr_in` (its family checked), or of a default
/// route's empty destination (a zero-length sockaddr: 0.0.0.0).
fn ipv4(address: &[u8]) -> Option<Ipv4Addr> {
    match address {
        [0, ..] => Some(Ipv4Addr::UNSPECIFIED),
        [length, family, _, _, a, b, c, d, ..]
            if usize::from(*length) >= 8 && i32::from(*family) == AF_INET =>
        {
            Some(Ipv4Addr::new(*a, *b, *c, *d))
        }
        // A short destination: the kernel trims trailing zero bytes.
        [length, family, ..] if i32::from(*family) == AF_INET => {
            let mut octets = [0_u8; 4];
            for (slot, byte) in octets
                .iter_mut()
                .zip(address.iter().take(usize::from(*length)).skip(4))
            {
                *slot = *byte;
            }
            Some(Ipv4Addr::from(octets))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One routing message: header, then the given addresses.
    fn message(index: u16, flags: i32, addresses: i32, sockaddrs: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        for sockaddr in sockaddrs {
            body.extend_from_slice(sockaddr);
            body.resize(body.len().next_multiple_of(4), 0);
        }
        let mut out = vec![0_u8; HEADER];
        let length = u16::try_from(HEADER + body.len()).unwrap_or(u16::MAX);
        out[..2].copy_from_slice(&length.to_ne_bytes());
        out[4..6].copy_from_slice(&index.to_ne_bytes());
        out[8..12].copy_from_slice(&flags.to_ne_bytes());
        out[12..16].copy_from_slice(&addresses.to_ne_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn sockaddr_in(octets: [u8; 4]) -> Vec<u8> {
        let mut out = vec![16, 2, 0, 0];
        out.extend_from_slice(&octets);
        out.resize(16, 0);
        out
    }

    #[test]
    fn the_default_route_of_the_interface_names_its_gateway() {
        let default = [0_u8, 0, 0, 0];
        let mut table = message(
            1,
            RTF_GATEWAY,
            RTA_DST | RTA_GATEWAY,
            &[&sockaddr_in(default), &sockaddr_in([10, 0, 0, 1])],
        );
        // A route to another network on the interface: not the default.
        table.extend(message(
            7,
            RTF_GATEWAY,
            RTA_DST | RTA_GATEWAY,
            &[
                &sockaddr_in([172, 16, 0, 0]),
                &sockaddr_in([192, 168, 49, 254]),
            ],
        ));
        // The default route on interface 7, with the kernel's empty
        // destination.
        table.extend(message(
            7,
            RTF_GATEWAY,
            RTA_DST | RTA_GATEWAY | 0x4,
            &[
                &[0, 0, 0, 0],
                &sockaddr_in([192, 168, 49, 1]),
                &[0, 0, 0, 0],
            ],
        ));
        assert_eq!(
            default_gateway(&table, 7),
            Some(Ipv4Addr::new(192, 168, 49, 1))
        );
        assert_eq!(default_gateway(&table, 1), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(default_gateway(&table, 9), None);
        // Truncated or nonsense tables give nothing, never a panic.
        assert_eq!(default_gateway(&table[..HEADER + 3], 1), None);
        let mut short = table.clone();
        short[0] = 4;
        short[1] = 0;
        assert_eq!(default_gateway(&short, 1), None);
        assert_eq!(default_gateway(&[], 1), None);
    }

    /// The real table reads, and any default gateway found is an address.
    #[test]
    fn the_real_table_reads() {
        let table = table();
        assert!(table.is_some());
        for index in 1..32 {
            if let Some(gateway) = gateway(index) {
                assert!(!gateway.is_unspecified());
            }
        }
    }
}
