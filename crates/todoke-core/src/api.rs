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
    /// Received offers awaiting a decision, with their entries: what an
    /// interface that starts late has not seen as events. At most 40000
    /// entries in all; the rest are listed once those are decided.
    Offers,
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
    /// Stop (or resume) being visible to contacts: no LAN advertisement and
    /// no relay presence while hidden. Contacts this device sends to are
    /// still reached, and pairing still advertises in stranger mode while
    /// an offer is shown.
    SetHidden {
        /// Whether to hide.
        hidden: bool,
    },
    /// Finished transfers kept under the history policy
    /// (`history_days`), newest first.
    History,
    /// Forget every finished transfer in the history.
    ClearHistory,
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
    /// How the open session reaches it; `None` without one.
    pub route: Option<Route>,
}

/// How a session reaches a contact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    /// Directly, on the local network.
    Lan,
    /// Through a relay (§10): end-to-end encrypted, forwarded by it.
    Relay,
}

/// An offer this device received.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferInfo {
    /// The transfer, hex.
    pub transfer: String,
    /// The sender, hex.
    pub from: String,
    /// The entries; names are untrusted.
    pub entries: Vec<EntryInfo>,
    /// Bytes in all files.
    pub total_bytes: u64,
    /// Files a previous Accept selected, when this resumes a transfer.
    pub resume: Option<Vec<u32>>,
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
    /// The MIME type the peer claims (§7.1), `application/octet-stream`
    /// when unknown: a display hint only, which grants nothing (no preview,
    /// no execution).
    pub mime: String,
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
    /// Where it stands.
    pub state: TransferState,
    /// Why it ended, when it failed: the protocol error code.
    pub detail: Option<String>,
    /// Bytes done of the selected files.
    pub bytes_done: u64,
    /// Bytes selected.
    pub bytes_total: u64,
}

/// Where a transfer stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    /// Sent to the peer, or waiting for a session to send it in.
    Offered,
    /// Received; waiting for this user to accept or decline.
    AwaitingDecision,
    /// Accepted; no file data yet.
    Accepted,
    /// File data is moving.
    Transferring,
    /// The connection ended; it resumes in the next session (§7.5).
    Interrupted,
    /// Every selected file arrived and was published.
    Received,
    /// The receiver's signed receipt arrived (§7.7).
    Delivered,
    /// Sent, but no signed receipt arrived.
    Unconfirmed,
    /// The receiver declined.
    Rejected,
    /// Either side cancelled.
    Cancelled,
    /// It failed; see the detail.
    Failed,
}

impl TransferState {
    /// Whether nothing more happens to the transfer.
    #[must_use]
    pub const fn is_finished(self) -> bool {
        !matches!(
            self,
            Self::Offered
                | Self::AwaitingDecision
                | Self::Accepted
                | Self::Transferring
                | Self::Interrupted
        )
    }

    /// Its name, as in JSON.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::AwaitingDecision => "awaiting_decision",
            Self::Accepted => "accepted",
            Self::Transferring => "transferring",
            Self::Interrupted => "interrupted",
            Self::Received => "received",
            Self::Delivered => "delivered",
            Self::Unconfirmed => "unconfirmed",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
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
    /// Whether this device is hidden from its contacts ([`Request::SetHidden`]).
    pub hidden: bool,
    /// How many days finished transfers stay in the history; 0 keeps none.
    pub history_days: u32,
}

/// A finished transfer in the history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// The transfer, hex.
    pub transfer: String,
    /// The peer device, hex.
    pub peer: String,
    /// Which way.
    pub way: Way,
    /// How it ended: `received`, `delivered`, `unconfirmed`, `rejected`,
    /// `cancelled`, or `failed`.
    pub state: TransferState,
    /// Why it ended, for people, when it did not complete.
    pub detail: Option<String>,
    /// When it ended, Unix seconds (this device's clock).
    pub finished_at: u64,
    /// Files offered, or selected once accepted.
    pub files: u32,
    /// Bytes offered, or selected once accepted.
    pub bytes: u64,
    /// The top-level names, at most [`HISTORY_NAMES`]; untrusted display
    /// text for received transfers (escape before showing).
    pub names: Vec<String>,
    /// The manifest's hash, hex (§7.1), once the offer was sent or
    /// received.
    pub manifest_hash: Option<String>,
    /// The signed delivery receipt (§7.7): the one this device signed as
    /// receiver, or verified as sender.
    pub receipt: Option<ReceiptInfo>,
}

/// The top-level names a history entry keeps.
pub const HISTORY_NAMES: usize = 8;

/// A signed delivery receipt (§7.7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptInfo {
    /// Its ID, hex.
    pub id: String,
    /// When the receiver finished, Unix seconds on its clock.
    pub completed_at: u64,
}

/// The core's answer to a request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "response", content = "body", rename_all = "snake_case")]
pub enum Response {
    /// Done.
    Done,
    /// The status.
    Status(StatusInfo),
    /// The contacts.
    Contacts(Vec<ContactInfo>),
    /// The transfers.
    Transfers(Vec<TransferInfo>),
    /// Received offers awaiting a decision.
    Offers(Vec<OfferInfo>),
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
    /// The history, newest first.
    History(Vec<HistoryEntry>),
    /// An offer was queued.
    Offered {
        /// The transfer, hex.
        transfer: String,
        /// Entries left out: links, special files, unreadable entries,
        /// names other systems cannot use, duplicate names, and paths too
        /// long (§7.1).
        skipped: usize,
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
    OfferReceived(OfferInfo),
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
        /// `unconfirmed`, `rejected`, `cancelled`, `failed`, or
        /// `interrupted` (it resumes in the next session).
        reason: TransferState,
        /// For people.
        message: String,
    },
    /// This subscriber fell behind and `events` events were dropped: re-read
    /// `Offers` and `Transfers` (sent by the daemon, never by the core).
    Missed {
        /// How many.
        events: u64,
    },
}

/// Escapes untrusted text for display: every control character and every
/// character that hides or reorders text ([`todoke_fs::is_invisible`]:
/// bidi controls, tags, fillers, joiners, variation selectors, and the
/// rest of the default-ignorable code points) becomes `\u{…}`; a backslash
/// becomes `\\`. Every interface shows peer-chosen names through it, so
/// `invoice\u{202e}fdp.exe` cannot pass for a PDF.
#[must_use]
pub fn escape(text: &str) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if c.is_control() || todoke_fs::is_invisible(c) {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
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
            Request::SetHidden { hidden: true },
            Request::History,
            Request::ClearHistory,
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

    /// Every response shape survives JSON (internally tagged enums cannot
    /// hold sequences, hence the adjacent tagging).
    #[test]
    fn every_response_round_trips() -> TestResult {
        let responses = [
            Response::Done,
            Response::Contacts(vec![ContactInfo {
                device: "aa".into(),
                person: "bb".into(),
                available: true,
                nearby: false,
                connected: true,
                route: Some(Route::Relay),
            }]),
            Response::Transfers(vec![TransferInfo {
                transfer: "ab".into(),
                peer: "cd".into(),
                way: Way::Incoming,
                state: TransferState::Failed,
                detail: Some("hash_mismatch".into()),
                bytes_done: 1,
                bytes_total: 2,
            }]),
            Response::Offers(Vec::new()),
            Response::History(vec![HistoryEntry {
                transfer: "ab".into(),
                peer: "cd".into(),
                way: Way::Outgoing,
                state: TransferState::Delivered,
                detail: None,
                finished_at: 9,
                files: 2,
                bytes: 3,
                names: vec!["n".into()],
                manifest_hash: Some("ef".into()),
                receipt: Some(ReceiptInfo {
                    id: "01".into(),
                    completed_at: 8,
                }),
            }]),
            Response::Strangers(vec![StrangerInfo {
                stranger: "cc".into(),
            }]),
            Response::Code {
                code: "0123456789".into(),
                expires_at: 1,
            },
            Response::error(ErrorCode::State, "no"),
        ];
        for response in responses {
            let text = serde_json::to_string(&response)?;
            assert_eq!(serde_json::from_str::<Response>(&text)?, response, "{text}");
        }
        let event = Event::OfferReceived(OfferInfo {
            transfer: "dd".into(),
            from: "ee".into(),
            entries: vec![EntryInfo {
                id: 1,
                parent: 0,
                directory: false,
                name: "n".into(),
                mime: "text/plain".into(),
                size: 1,
            }],
            total_bytes: 1,
            resume: Some(vec![1]),
        });
        let ended = Event::Ended {
            transfer: "dd".into(),
            reason: TransferState::Interrupted,
            message: "m".into(),
        };
        for event in [event, ended] {
            let text = serde_json::to_string(&event)?;
            assert_eq!(serde_json::from_str::<Event>(&text)?, event, "{text}");
        }
        assert!(
            serde_json::to_string(&TransferState::AwaitingDecision)?
                .contains(TransferState::AwaitingDecision.as_str())
        );
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
    fn names_are_escaped_for_display() {
        assert_eq!(escape("invoice\u{202e}fdp.exe"), "invoice\\u{202e}fdp.exe");
        assert_eq!(escape("a\\b\u{1b}[2J"), "a\\\\b\\u{1b}[2J");
        assert_eq!(escape("caf\u{e9} \u{1f600}"), "caf\u{e9} \u{1f600}");
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex([0x00, 0xab, 0xff]), "00abff");
    }
}
