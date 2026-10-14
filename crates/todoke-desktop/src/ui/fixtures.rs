//! The mock core's world: four contacts at every distance, finished
//! transfers, a nearby stranger, and pairing and sending that succeed. The
//! UI tests and the screenshots use it.

use std::sync::atomic::{AtomicU32, Ordering};

use todoke_core::api::{
    ContactInfo, EntryInfo, HistoryEntry, OfferInfo, ReceiptInfo, Request, Response, Route,
    StatusInfo, StrangerInfo, TransferState, Way,
};

/// A contact in a session on the LAN.
pub const LAN: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
/// A contact seen nearby, no session.
pub const NEAR: &str = "b7c8d9e0f1a2b3c4d5e6f708192a3b4cb7c8d9e0f1a2b3c4d5e6f708192a3b4c";
/// A contact neither nearby nor connected.
pub const AWAY: &str = "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2";
/// A contact in a session through a relay.
pub const RELAYED: &str = "d9e0f1a2b3c4d5e6f708192a3b4cb7c8d9e0f1a2b3c4d5e6f708192a3b4cb7c8";

fn contact(device: &str, nearby: bool, route: Option<Route>) -> ContactInfo {
    ContactInfo {
        device: device.into(),
        person: device.chars().rev().collect(),
        available: true,
        nearby,
        connected: route.is_some(),
        route,
    }
}

/// The mock core's answers: four contacts, a status, two finished
/// transfers, one stranger, and offers and pairings that work.
pub fn script() -> impl Fn(&Request) -> Response + Send + Sync + 'static {
    let sent = AtomicU32::new(0);
    move |request| match request {
        Request::Status => Response::Status(StatusInfo {
            device: "e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4".into(),
            sessions_enabled: true,
            port: Some(41_000),
            contacts: 4,
            sessions: 2,
            pairing: false,
            hidden: false,
            history_days: 30,
            key_protection: todoke_core::api::KeyProtection::Keychain,
        }),
        Request::Contacts => Response::Contacts(vec![
            contact(LAN, true, Some(Route::Lan)),
            contact(NEAR, true, None),
            contact(RELAYED, false, Some(Route::Relay)),
            contact(AWAY, false, None),
        ]),
        Request::Transfers | Request::Offers => match request {
            Request::Offers => Response::Offers(Vec::new()),
            _ => Response::Transfers(Vec::new()),
        },
        Request::History => Response::History(history()),
        Request::Strangers => Response::Strangers(vec![StrangerInfo {
            stranger: "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a".into(),
        }]),
        Request::Send { .. } => {
            let n = sent.fetch_add(1, Ordering::Relaxed);
            Response::Offered {
                transfer: format!("{n:032x}"),
                skipped: 0,
            }
        }
        Request::PairShowQr => Response::Qr {
            text: "TODOKE:EXAMPLEPAIRINGOFFER0123456789".into(),
            expires_at: u64::MAX / 2,
        },
        Request::PairShowCode => Response::Code {
            code: "0123456789".into(),
            expires_at: u64::MAX / 2,
        },
        Request::PairEnterCode { .. } | Request::PairScanQr { .. } => Response::Paired {
            contact: NEAR.into(),
        },
        _ => Response::Done,
    }
}

/// Two finished transfers, one each way, with receipts.
#[must_use]
pub fn history() -> Vec<HistoryEntry> {
    vec![
        HistoryEntry {
            transfer: "11".repeat(16),
            peer: LAN.into(),
            way: Way::Incoming,
            state: TransferState::Received,
            detail: None,
            finished_at: 1_791_970_200,
            files: 12,
            bytes: 48 << 20,
            names: vec!["Holiday photos".into()],
            manifest_hash: Some("ab".repeat(32)),
            receipt: Some(ReceiptInfo {
                id: "cd".repeat(16),
                completed_at: 1_791_970_200,
            }),
        },
        HistoryEntry {
            transfer: "22".repeat(16),
            peer: RELAYED.into(),
            way: Way::Outgoing,
            state: TransferState::Delivered,
            detail: None,
            finished_at: 1_791_960_000,
            files: 1,
            bytes: 2 << 20,
            names: vec!["Quarterly report.pdf".into()],
            manifest_hash: Some("ef".repeat(32)),
            receipt: Some(ReceiptInfo {
                id: "01".repeat(16),
                completed_at: 1_791_960_000,
            }),
        },
    ]
}

/// An offer from [`LAN`] of `names` (name, MIME type, size; no MIME type
/// for a folder).
#[must_use]
pub fn offer(transfer: &str, names: &[(&str, &str, u64)]) -> OfferInfo {
    let entries: Vec<EntryInfo> = names
        .iter()
        .enumerate()
        .map(|(index, (name, mime, size))| EntryInfo {
            id: u32::try_from(index + 1).unwrap_or(u32::MAX),
            parent: 0,
            directory: mime.is_empty(),
            name: (*name).into(),
            mime: (*mime).into(),
            size: *size,
        })
        .collect();
    OfferInfo {
        transfer: transfer.into(),
        from: LAN.into(),
        total_bytes: entries.iter().map(|e| e.size).sum(),
        entries,
        resume: None,
    }
}
