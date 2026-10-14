//! Requests to the core, its responses, and its events: the one API every
//! user interface uses (the CLI through the daemon's local IPC, later the
//! desktop and mobile apps).
//!
//! Requests are untrusted input: the core checks every one against its own
//! state and policy. No request carries key material; the only secrets that
//! leave the core are a pairing offer's QR text and code, which exist to be
//! shown to the user (§3) and are redacted from `Debug` output.
//!
//! Devices are named by the lowercase hex of their device public key; a
//! unique prefix of at least [`MIN_PREFIX`] characters is enough in
//! requests. Transfers are named by the hex of their transfer ID.

use core::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The shortest device or transfer prefix a request may use.
pub const MIN_PREFIX: usize = 8;

/// A request to the core.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "request",
    content = "args",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Request {
    /// What the core is doing.
    Status,
    /// The paired devices.
    Contacts,
    /// Transfers in progress or awaiting a decision.
    Transfers,
    /// Show a QR pairing offer (this device responds) and advertise in
    /// stranger mode for its lifetime.
    PairShowQr,
    /// Pair with the device whose QR offer text was scanned or pasted.
    PairScanQr {
        /// The QR text (`TODOKE:` and Base45).
        text: String,
    },
    /// Show a human-code pairing offer and advertise in stranger mode.
    PairShowCode,
    /// Pair with a nearby device in stranger mode, using its code.
    PairEnterCode {
        /// The ten-digit code shown on the other device.
        code: String,
        /// The stranger advertisement to send the request to
        /// ([`Response::Strangers`]).
        stranger: String,
    },
    /// Nearby devices in stranger mode (for code pairing).
    Strangers,
    /// Stop showing a pairing offer and advertising in stranger mode.
    StopPairing,
    /// Offer files and folders to a contact.
    Send {
        /// The contact.
        contact: String,
        /// Files and folders to offer; folders are sent with their contents.
        paths: Vec<PathBuf>,
    },
    /// Accept an offer (the user's decision, §7.2).
    Accept {
        /// The transfer.
        transfer: String,
        /// The files to receive; all files when absent.
        files: Option<Vec<u32>>,
    },
    /// Decline an offer.
    Decline {
        /// The transfer.
        transfer: String,
    },
    /// Cancel a transfer in either direction.
    Cancel {
        /// The transfer.
        transfer: String,
    },
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PairScanQr { .. } => f.write_str("PairScanQr { <redacted> }"),
            Self::PairEnterCode { .. } => f.write_str("PairEnterCode { <redacted> }"),
            Self::Send { paths, .. } => write!(f, "Send {{ paths: {} }}", paths.len()),
            other => {
                let text = serde_json::to_string(other).unwrap_or_default();
                f.write_str(&text)
            }
        }
    }
}

/// Why a request failed; stable codes for scripts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The request is malformed or names nothing known.
    Invalid,
    /// A device or transfer prefix matches more than one.
    Ambiguous,
    /// The contact is not reachable now.
    Unreachable,
    /// The operation is not allowed in the current state.
    State,
    /// Pairing failed (wrong code, expired offer, or the peer refused).
    Pairing,
    /// Reading the files to send failed.
    Source,
    /// Sessions are disabled in this build (PROTOCOL §16 gates).
    Disabled,
    /// An internal failure.
    Internal,
}

/// A paired device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactInfo {
    /// The device public key, hex.
    pub device: String,
    /// The person root public key, hex.
    pub person: String,
    /// Whether a session may start (not revoked, blocked, or uncertain).
    pub available: bool,
    /// Whether it was seen on the local network recently.
    pub nearby: bool,
    /// Whether a session with it is open.
    pub connected: bool,
}

/// One entry of an offer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryInfo {
    /// The entry ID (selections name file IDs).
    pub id: u32,
    /// The parent directory's ID, 0 for the top level.
    pub parent: u32,
    /// Whether it is a directory.
    pub directory: bool,
    /// The name as the peer sent it: untrusted display text. Interfaces
    /// must escape control and bidirectional characters before showing it.
    pub name: String,
    /// The size in bytes, 0 for directories.
    pub size: u64,
}

/// Which way a transfer goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Way {
    /// This device sends.
    Outgoing,
    /// This device receives.
    Incoming,
}

/// A transfer the core knows about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferInfo {
    /// The transfer ID, hex.
    pub transfer: String,
    /// The peer device, hex.
    pub peer: String,
    /// Which way.
    pub way: Way,
    /// Where it stands: `offered`, `awaiting_decision`, `accepted`,
    /// `transferring`, `interrupted`.
    pub state: String,
    /// Bytes done of the selected files.
    pub bytes_done: u64,
    /// Bytes selected.
    pub bytes_total: u64,
}

/// A nearby device in stranger mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrangerInfo {
    /// Its current stranger token, hex: identifies nobody (§9).
    pub stranger: String,
}

/// What the core is doing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusInfo {
    /// This device's public key, hex.
    pub device: String,
    /// Whether sessions are enabled in this build.
    pub sessions_enabled: bool,
    /// The LAN listener's port, if listening.
    pub port: Option<u16>,
    /// Paired devices.
    pub contacts: usize,
    /// Open sessions.
    pub sessions: usize,
    /// Whether a pairing offer is shown.
    pub pairing: bool,
}

/// The core's answer to a request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum Response {
    /// Done.
    Done,
    /// The status.
    Status(StatusInfo),
    /// The contacts.
    Contacts(Vec<ContactInfo>),
    /// The transfers.
    Transfers(Vec<TransferInfo>),
    /// A QR offer to show: secret until it is used or expires (§3.1).
    Qr {
        /// The QR text.
        text: String,
        /// When it expires, Unix seconds.
        expires_at: u64,
    },
    /// A code offer to show: secret until used or expired (§3.2).
    Code {
        /// The ten digits.
        code: String,
        /// When it expires, Unix seconds.
        expires_at: u64,
    },
    /// Pairing succeeded.
    Paired {
        /// The new contact, hex.
        contact: String,
    },
    /// Nearby strangers.
    Strangers(Vec<StrangerInfo>),
    /// An offer was queued.
    Offered {
        /// The transfer, hex.
        transfer: String,
    },
    /// The request failed.
    Error {
        /// Why.
        code: ErrorCode,
        /// For people; never contains secrets, paths, or peer names.
        message: String,
    },
}

impl Response {
    /// An error response.
    #[must_use]
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Qr { expires_at, .. } => {
                write!(f, "Qr {{ text: <redacted>, expires_at: {expires_at} }}")
            }
            Self::Code { expires_at, .. } => {
                write!(f, "Code {{ code: <redacted>, expires_at: {expires_at} }}")
            }
            other => f.write_str(&serde_json::to_string(other).unwrap_or_default()),
        }
    }
}

/// Something the user should know about, as it happens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// A new contact was paired.
    Paired {
        /// The contact, hex.
        contact: String,
    },
    /// An offer awaits the user's decision (§7.2); it expires after 300
    /// seconds.
    OfferReceived {
        /// The transfer, hex.
        transfer: String,
        /// The sender, hex.
        from: String,
        /// The entries; names are untrusted.
        entries: Vec<EntryInfo>,
        /// Bytes in all files.
        total_bytes: u64,
        /// Files a previous Accept selected, when this resumes a transfer.
        resume: Option<Vec<u32>>,
    },
    /// Bytes moved.
    Progress {
        /// The transfer, hex.
        transfer: String,
        /// Which way.
        way: Way,
        /// Bytes done.
        done: u64,
        /// Bytes selected.
        total: u64,
        /// Recent throughput.
        bytes_per_second: u64,
    },
    /// The receiver published every selected file.
    Completed {
        /// The transfer, hex.
        transfer: String,
    },
    /// The sender verified the receiver's signed delivery receipt.
    Delivered {
        /// The transfer, hex.
        transfer: String,
    },
    /// The transfer ended without completing.
    Ended {
        /// The transfer, hex.
        transfer: String,
        /// `rejected`, `cancelled`, `failed`, or `interrupted` (resumable).
        reason: String,
        /// For people.
        message: String,
    },
}

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: impl AsRef<[u8]>) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn requests_and_responses_round_trip() -> TestResult {
        for request in [
            Request::Status,
            Request::PairScanQr {
                text: "TODOKE:SECRET".into(),
            },
            Request::Send {
                contact: "abcdef0123".into(),
                paths: vec!["/tmp/x".into()],
            },
            Request::Accept {
                transfer: "00ff".into(),
                files: Some(vec![2, 3]),
            },
        ] {
            let text = serde_json::to_string(&request)?;
            assert_eq!(serde_json::from_str::<Request>(&text)?, request);
        }
        assert!(serde_json::from_str::<Request>(r#"{"request":"status","x":1}"#).is_err());
        assert!(
            serde_json::from_str::<Request>(
                r#"{"request":"decline","args":{"transfer":"00","extra":1}}"#
            )
            .is_err()
        );
        assert_eq!(
            serde_json::from_str::<Request>(r#"{"request":"decline","args":{"transfer":"00"}}"#)?,
            Request::Decline {
                transfer: "00".into()
            }
        );
        assert!(serde_json::from_str::<Request>(r#"{"request":"format_disk"}"#).is_err());
        Ok(())
    }

    #[test]
    fn secrets_never_reach_debug_output() {
        let qr = Response::Qr {
            text: "TODOKE:SECRET-QR".into(),
            expires_at: 9,
        };
        let code = Response::Code {
            code: "0123456789".into(),
            expires_at: 9,
        };
        let scan = Request::PairScanQr {
            text: "TODOKE:SECRET-QR".into(),
        };
        let enter = Request::PairEnterCode {
            code: "0123456789".into(),
            stranger: "aa".into(),
        };
        let shown = format!("{qr:?} {code:?} {scan:?} {enter:?}");
        assert!(!shown.contains("SECRET-QR"), "{shown}");
        assert!(!shown.contains("0123456789"), "{shown}");
        let send = Request::Send {
            contact: "c".into(),
            paths: vec!["/home/me/private".into()],
        };
        assert!(!format!("{send:?}").contains("private"));
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex([0x00, 0xab, 0xff]), "00abff");
    }
}
