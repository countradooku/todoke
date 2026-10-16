//! What crosses the boundary as plain values: the core's answers and
//! events, without secrets. Peer-chosen names are escaped
//! ([`todoke_core::api::escape`]) before they cross, so no interface can
//! show a name that hides or reorders text.

use boltffi::data;
use todoke_core::api;

/// Which way a transfer goes.
#[data]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Way {
    /// This device sends.
    Outgoing,
    /// This device receives.
    Incoming,
}

impl From<api::Way> for Way {
    fn from(way: api::Way) -> Self {
        match way {
            api::Way::Outgoing => Self::Outgoing,
            api::Way::Incoming => Self::Incoming,
        }
    }
}

/// Where a transfer is.
#[data]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferState {
    /// Offered, waiting for the receiver.
    Offered,
    /// Received, waiting for this user's decision.
    AwaitingDecision,
    /// Accepted, not yet moving.
    Accepted,
    /// Moving.
    Transferring,
    /// Paused; it resumes in the next session.
    Interrupted,
    /// Every selected file arrived and was published.
    Received,
    /// The receiver's signed receipt was verified.
    Delivered,
    /// Sent, but no receipt came.
    Unconfirmed,
    /// Declined.
    Rejected,
    /// Cancelled.
    Cancelled,
    /// Failed.
    Failed,
}

impl From<api::TransferState> for TransferState {
    fn from(state: api::TransferState) -> Self {
        use api::TransferState as S;
        match state {
            S::Offered => Self::Offered,
            S::AwaitingDecision => Self::AwaitingDecision,
            S::Accepted => Self::Accepted,
            S::Transferring => Self::Transferring,
            S::Interrupted => Self::Interrupted,
            S::Received => Self::Received,
            S::Delivered => Self::Delivered,
            S::Unconfirmed => Self::Unconfirmed,
            S::Rejected => Self::Rejected,
            S::Cancelled => Self::Cancelled,
            S::Failed => Self::Failed,
        }
    }
}

/// How a contact is reached now.
#[data]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// Not connected.
    None,
    /// Directly, on the local network.
    Lan,
    /// Through a relay.
    Relay,
    /// Over a direct Wi-Fi link the two devices set up.
    Direct,
}

/// What protects the key that seals this device's state.
#[data]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyProtection {
    /// A file only this app can read.
    File,
    /// The Keychain.
    Keychain,
    /// The Keychain, wrapped by the Secure Enclave.
    SecureEnclave,
    /// Windows Data Protection.
    Dpapi,
    /// Windows Data Protection, wrapped by the TPM.
    Tpm,
    /// The Secret Service.
    SecretService,
    /// The desktop's secret portal.
    Portal,
    /// The Android Keystore, in `StrongBox`.
    StrongBox,
    /// The Android Keystore, in the trusted execution environment.
    Tee,
}

impl From<api::KeyProtection> for KeyProtection {
    fn from(protection: api::KeyProtection) -> Self {
        use api::KeyProtection as P;
        match protection {
            P::File => Self::File,
            P::Keychain => Self::Keychain,
            P::SecureEnclave => Self::SecureEnclave,
            P::Dpapi => Self::Dpapi,
            P::Tpm => Self::Tpm,
            P::SecretService => Self::SecretService,
            P::Portal => Self::Portal,
            P::StrongBox => Self::StrongBox,
            P::Tee => Self::Tee,
        }
    }
}

impl From<KeyProtection> for api::KeyProtection {
    fn from(protection: KeyProtection) -> Self {
        use api::KeyProtection as P;
        match protection {
            KeyProtection::File => P::File,
            KeyProtection::Keychain => P::Keychain,
            KeyProtection::SecureEnclave => P::SecureEnclave,
            KeyProtection::Dpapi => P::Dpapi,
            KeyProtection::Tpm => P::Tpm,
            KeyProtection::SecretService => P::SecretService,
            KeyProtection::Portal => P::Portal,
            KeyProtection::StrongBox => P::StrongBox,
            KeyProtection::Tee => P::Tee,
        }
    }
}

/// Where the storage key may live.
#[data]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStoragePolicy {
    /// The platform's store where there is one, else a private file.
    Auto,
    /// The platform's store only.
    Platform,
    /// A private file.
    File,
}

/// How to start the core.
#[data]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The app's private directory: the state goes in `state` inside it.
    pub home: String,
    /// Where received files are published.
    pub downloads: String,
    /// Use the local network.
    pub lan: bool,
    /// Reach devices on this machine too: two profiles in one test, never
    /// an app. Refused unless the library was built for tests (the
    /// `test-support` feature).
    pub allow_loopback: bool,
    /// Start hidden from contacts.
    pub hidden: bool,
    /// Days of history to keep (0: none).
    pub history_days: u32,
    /// Where the storage key may live.
    pub key_storage: KeyStoragePolicy,
}

/// What the core is doing.
#[data]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// This device's fingerprint (hex).
    pub device: String,
    /// Whether sessions are enabled in this build.
    pub sessions_enabled: bool,
    /// Paired contacts.
    pub contacts: u32,
    /// Live sessions.
    pub sessions: u32,
    /// Whether a pairing offer is shown.
    pub pairing: bool,
    /// Whether this device is hidden.
    pub hidden: bool,
    /// Days of history kept.
    pub history_days: u32,
    /// What protects the storage key.
    pub key_protection: KeyProtection,
}

impl From<api::StatusInfo> for Status {
    fn from(status: api::StatusInfo) -> Self {
        Self {
            device: status.device,
            sessions_enabled: status.sessions_enabled,
            contacts: count(status.contacts),
            sessions: count(status.sessions),
            pairing: status.pairing,
            hidden: status.hidden,
            history_days: status.history_days,
            key_protection: status.key_protection.into(),
        }
    }
}

/// A count as the boundary carries it.
pub(crate) fn count(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// A paired device.
#[data]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    /// Its device fingerprint (hex): pass it to `Core::contact`.
    pub device: String,
    /// What to call it (devices carry no names).
    pub name: String,
    /// Reachable now.
    pub available: bool,
    /// Seen on the local network.
    pub nearby: bool,
    /// A session is open.
    pub connected: bool,
    /// How it is reached.
    pub route: Route,
}

impl From<api::ContactInfo> for Contact {
    fn from(contact: api::ContactInfo) -> Self {
        Self {
            name: name_of(&contact.device),
            route: match contact.route {
                None => Route::None,
                Some(api::Route::Lan) => Route::Lan,
                Some(api::Route::Relay) => Route::Relay,
                Some(api::Route::Direct) => Route::Direct,
            },
            device: contact.device,
            available: contact.available,
            nearby: contact.nearby,
            connected: contact.connected,
        }
    }
}

/// What to call a device: the start of its fingerprint, as the desktop
/// app shows it.
#[must_use]
pub fn name_of(device: &str) -> String {
    let digits: Vec<char> = device
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let groups: Vec<String> = digits
        .chunks(4)
        .map(|group| group.iter().collect())
        .collect();
    format!("Device {}", groups.join(" "))
}

/// A transfer.
#[data]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    /// Its ID (hex): pass it to `Core::transfer`.
    pub id: String,
    /// The other device's fingerprint.
    pub peer: String,
    /// Which way.
    pub way: Way,
    /// Where it is.
    pub state: TransferState,
    /// Why it ended, for people (escaped), or empty.
    pub detail: String,
    /// Bytes moved.
    pub bytes_done: u64,
    /// Bytes selected.
    pub bytes_total: u64,
}

impl From<api::TransferInfo> for Transfer {
    fn from(transfer: api::TransferInfo) -> Self {
        Self {
            id: transfer.transfer,
            peer: transfer.peer,
            way: transfer.way.into(),
            state: transfer.state.into(),
            detail: transfer
                .detail
                .map(|detail| api::escape(&detail))
                .unwrap_or_default(),
            bytes_done: transfer.bytes_done,
            bytes_total: transfer.bytes_total,
        }
    }
}

/// One file or folder of an offer.
#[data]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its ID in the offer (choose by it).
    pub id: u32,
    /// Its folder's ID (0: the top).
    pub parent: u32,
    /// A folder.
    pub directory: bool,
    /// Its name, as the sender gave it (escaped).
    pub name: String,
    /// Its claimed type.
    pub mime: String,
    /// Its claimed size.
    pub size: u64,
}

/// An offer waiting for this user's decision.
#[data]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    /// The transfer's ID.
    pub transfer: String,
    /// The sender's fingerprint (a verified contact).
    pub from: String,
    /// What the sender calls itself here: its fingerprint's start.
    pub from_name: String,
    /// The files and folders.
    pub entries: Vec<Entry>,
    /// Bytes in all.
    pub total_bytes: u64,
    /// For a resumed offer, the files still to receive; else empty.
    pub resume: Vec<u32>,
}

impl From<api::OfferInfo> for Offer {
    fn from(offer: api::OfferInfo) -> Self {
        Self {
            from_name: name_of(&offer.from),
            transfer: offer.transfer,
            from: offer.from,
            entries: offer
                .entries
                .into_iter()
                .map(|entry| Entry {
                    id: entry.id,
                    parent: entry.parent,
                    directory: entry.directory,
                    name: api::escape(&entry.name),
                    mime: api::escape(&entry.mime),
                    size: entry.size,
                })
                .collect(),
            total_bytes: offer.total_bytes,
            resume: offer.resume.unwrap_or_default(),
        }
    }
}

/// A finished transfer kept in the history.
#[data]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryItem {
    /// The transfer's ID.
    pub transfer: String,
    /// The other device's fingerprint.
    pub peer: String,
    /// Which way.
    pub way: Way,
    /// How it ended.
    pub state: TransferState,
    /// Why, for people (escaped), or empty.
    pub detail: String,
    /// When it finished (Unix seconds).
    pub finished_at: u64,
    /// Files.
    pub files: u32,
    /// Bytes.
    pub bytes: u64,
    /// The first names (escaped).
    pub names: Vec<String>,
    /// The manifest's hash (hex), or empty.
    pub manifest_hash: String,
    /// The delivery receipt's ID (hex), or empty.
    pub receipt: String,
}

impl From<api::HistoryEntry> for HistoryItem {
    fn from(entry: api::HistoryEntry) -> Self {
        Self {
            transfer: entry.transfer,
            peer: entry.peer,
            way: entry.way.into(),
            state: entry.state.into(),
            detail: entry
                .detail
                .map(|detail| api::escape(&detail))
                .unwrap_or_default(),
            finished_at: entry.finished_at,
            files: entry.files,
            bytes: entry.bytes,
            names: entry.names.iter().map(|name| api::escape(name)).collect(),
            manifest_hash: entry.manifest_hash.unwrap_or_default(),
            receipt: entry.receipt.map(|receipt| receipt.id).unwrap_or_default(),
        }
    }
}

/// A nearby device showing a pairing code (stranger mode).
#[data]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stranger {
    /// Its advertisement: pass it to `Core::pair_enter_code`.
    pub stranger: String,
}

/// Something the core reports.
#[data]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreEvent {
    /// A contact was paired.
    Paired {
        /// Its fingerprint.
        contact: String,
    },
    /// An offer awaits this user's decision.
    OfferReceived {
        /// The offer.
        offer: Offer,
    },
    /// Bytes moved.
    Progress {
        /// The transfer.
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
    /// Every selected file arrived and was published.
    Completed {
        /// The transfer.
        transfer: String,
    },
    /// The receiver's signed receipt was verified.
    Delivered {
        /// The transfer.
        transfer: String,
    },
    /// The transfer ended without completing.
    Ended {
        /// The transfer.
        transfer: String,
        /// How.
        reason: TransferState,
        /// Why, for people (escaped).
        message: String,
    },
    /// Events were lost: read the offers and transfers again.
    Missed {
        /// How many.
        events: u64,
    },
    /// This device points at a contact (`Core::point_start`): range with it
    /// as the controller.
    PointTarget {
        /// The ranging.
        ranging: RangingInfo,
    },
    /// A contact points at this device: answer with `Core::accept_ranging`
    /// (then range with it as the controlee) or `Core::refuse_ranging`.
    RangingRequested {
        /// The ranging.
        ranging: RangingInfo,
    },
    /// This device points at a contact with Apple Nearby Interaction
    /// (`Core::point_start_peer`): run the session whose token is
    /// `local_token` with `peer_token`.
    PeerPointTarget {
        /// The ranging.
        ranging: PeerRangingInfo,
    },
    /// A contact points at this device with Apple Nearby Interaction:
    /// accept with `Core::accept_peer_ranging` (then range with
    /// `peer_token`) or `Core::refuse_ranging`.
    PeerRangingRequested {
        /// The ranging.
        ranging: PeerRangingInfo,
    },
    /// A ranging ended (stopped, its time up, or its session gone): stop
    /// ranging with that session ID.
    RangingStopped {
        /// The contact.
        contact: String,
        /// The ranging session ID.
        session_id: u32,
    },
}

/// One Apple Nearby Interaction ranging between this device and a contact
/// (PROTOCOL §10.4): archived discovery tokens, never logged or kept once
/// it ends.
#[data]
#[derive(Clone, PartialEq, Eq)]
pub struct PeerRangingInfo {
    /// The contact.
    pub contact: String,
    /// The ranging session ID.
    pub session_id: u32,
    /// The contact's token for this ranging.
    pub peer_token: Vec<u8>,
    /// This device's token for it; none in a request.
    pub local_token: Option<Vec<u8>>,
}

impl core::fmt::Debug for PeerRangingInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PeerRangingInfo")
            .field("contact", &self.contact)
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

impl From<api::PeerRangingInfo> for PeerRangingInfo {
    fn from(ranging: api::PeerRangingInfo) -> Self {
        Self {
            contact: ranging.contact,
            session_id: ranging.session_id,
            peer_token: unhex(&ranging.peer_token).unwrap_or_default(),
            local_token: ranging.local_token.as_deref().and_then(unhex),
        }
    }
}

/// A controller session the platform prepared for pointing (PROTOCOL
/// §10.4): its address serves one ranging.
#[data]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UwbController {
    /// Its UWB short address.
    pub address: u16,
    /// The channel: 5 or 9.
    pub channel: u8,
    /// The preamble index: 9 to 12 or 25 to 32.
    pub preamble: u8,
}

/// One ultra-wideband ranging between this device and a contact
/// (PROTOCOL §10.4): `FiRa` provisioned-STS unicast DS-TWR. It only hints at
/// which contact the user points at: it authenticates nothing.
#[data]
#[derive(Clone, PartialEq, Eq)]
pub struct RangingInfo {
    /// The contact.
    pub contact: String,
    /// The ranging session ID.
    pub session_id: u32,
    /// The controller's UWB short address.
    pub controller: u16,
    /// The controlee's UWB short address; none in a request (answer with
    /// a fresh one: `Core::accept_ranging`).
    pub controlee: Option<u16>,
    /// The channel: 5 or 9.
    pub channel: u8,
    /// The preamble index.
    pub preamble: u8,
    /// The configuration (1: provisioned-STS unicast DS-TWR).
    pub config: u8,
    /// The 16-byte STS key: hand it to the UWB stack only, never log or
    /// keep it.
    pub sts_key: Vec<u8>,
}

impl core::fmt::Debug for RangingInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RangingInfo")
            .field("contact", &self.contact)
            .field("session_id", &self.session_id)
            .field("controller", &self.controller)
            .field("controlee", &self.controlee)
            .field("channel", &self.channel)
            .field("preamble", &self.preamble)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl From<api::Ranging> for RangingInfo {
    fn from(ranging: api::Ranging) -> Self {
        let key = zeroize::Zeroizing::new(ranging.sts_key);
        Self {
            contact: ranging.contact,
            session_id: ranging.session_id,
            controller: ranging.controller,
            controlee: ranging.controlee,
            channel: ranging.channel,
            preamble: ranging.preamble,
            config: ranging.config,
            sts_key: unhex(&key).unwrap_or_default(),
        }
    }
}

/// Lowercase hexadecimal text as bytes.
fn unhex(text: &str) -> Option<Vec<u8>> {
    let digit = |byte: u8| {
        char::from(byte)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    let text = text.as_bytes();
    let (pairs, []) = text.as_chunks::<2>() else {
        return None;
    };
    pairs
        .iter()
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

impl From<api::Event> for CoreEvent {
    fn from(event: api::Event) -> Self {
        use api::Event as E;
        match event {
            E::Paired { contact } => Self::Paired { contact },
            E::OfferReceived(offer) => Self::OfferReceived {
                offer: offer.into(),
            },
            E::Progress {
                transfer,
                way,
                done,
                total,
                bytes_per_second,
            } => Self::Progress {
                transfer,
                way: way.into(),
                done,
                total,
                bytes_per_second,
            },
            E::Completed { transfer } => Self::Completed { transfer },
            E::Delivered { transfer } => Self::Delivered { transfer },
            E::Ended {
                transfer,
                reason,
                message,
            } => Self::Ended {
                transfer,
                reason: reason.into(),
                message: api::escape(&message),
            },
            E::Missed { events } => Self::Missed { events },
            E::PointTarget(ranging) => Self::PointTarget {
                ranging: ranging.into(),
            },
            E::RangingRequested(ranging) => Self::RangingRequested {
                ranging: ranging.into(),
            },
            E::PeerPointTarget(ranging) => Self::PeerPointTarget {
                ranging: ranging.into(),
            },
            E::PeerRangingRequested(ranging) => Self::PeerRangingRequested {
                ranging: ranging.into(),
            },
            E::RangingStopped {
                contact,
                session_id,
            } => Self::RangingStopped {
                contact,
                session_id,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name that would pass for a PDF if its bidi override were shown.
    const TRICK: &str = "invoice\u{202e}fdp.exe\n";
    const ESCAPED: &str = "invoice\\u{202e}fdp.exe\\u{a}";

    fn entry(name: &str) -> api::EntryInfo {
        api::EntryInfo {
            id: 1,
            parent: 0,
            directory: false,
            name: name.to_owned(),
            mime: format!("text/{name}"),
            size: 3,
        }
    }

    /// Every peer-chosen text in an offer crosses escaped; the sender's
    /// name is made from its fingerprint, never sent by the peer.
    #[test]
    fn offers_cross_escaped() -> Result<(), &'static str> {
        let offer = Offer::from(api::OfferInfo {
            transfer: "aa".into(),
            from: "0123456789abcdef".repeat(4),
            entries: vec![entry(TRICK)],
            total_bytes: 3,
            resume: None,
        });
        assert_eq!(offer.from_name, "Device 0123 4567");
        assert_eq!(offer.entries[0].name, ESCAPED);
        assert_eq!(offer.entries[0].mime, format!("text/{ESCAPED}"));
        assert_eq!(offer.resume, Vec::<u32>::new());
        let event = CoreEvent::from(api::Event::OfferReceived(api::OfferInfo {
            transfer: "aa".into(),
            from: String::new(),
            entries: vec![entry(TRICK)],
            total_bytes: 3,
            resume: Some(vec![1]),
        }));
        let CoreEvent::OfferReceived { offer } = event else {
            return Err("an offer became something else");
        };
        assert_eq!(offer.entries[0].name, ESCAPED);
        assert_eq!(offer.resume, [1]);
        Ok(())
    }

    /// Why a transfer ended crosses escaped: in events, the transfer
    /// list, and the history (with its names).
    #[test]
    fn endings_and_history_cross_escaped() {
        let event = CoreEvent::from(api::Event::Ended {
            transfer: "aa".into(),
            reason: api::TransferState::Cancelled,
            message: TRICK.into(),
        });
        assert_eq!(
            event,
            CoreEvent::Ended {
                transfer: "aa".into(),
                reason: TransferState::Cancelled,
                message: ESCAPED.into(),
            }
        );
        let transfer = Transfer::from(api::TransferInfo {
            transfer: "aa".into(),
            peer: "bb".into(),
            way: api::Way::Incoming,
            state: api::TransferState::Failed,
            detail: Some(TRICK.into()),
            bytes_done: 1,
            bytes_total: 2,
        });
        assert_eq!(transfer.detail, ESCAPED);
        assert_eq!(transfer.way, Way::Incoming);
        let item = HistoryItem::from(api::HistoryEntry {
            transfer: "aa".into(),
            peer: "bb".into(),
            way: api::Way::Outgoing,
            state: api::TransferState::Delivered,
            detail: Some(TRICK.into()),
            finished_at: 5,
            files: 1,
            bytes: 2,
            names: vec![TRICK.into(), "plain".into()],
            manifest_hash: Some("cc".into()),
            receipt: Some(api::ReceiptInfo {
                id: "dd".into(),
                completed_at: 4,
            }),
        });
        assert_eq!(item.detail, ESCAPED);
        assert_eq!(item.names, [ESCAPED, "plain"]);
        assert_eq!(
            (item.manifest_hash.as_str(), item.receipt.as_str()),
            ("cc", "dd")
        );
        // Nothing to say is an empty string, not a missing value.
        let quiet = Transfer::from(api::TransferInfo {
            transfer: "aa".into(),
            peer: "bb".into(),
            way: api::Way::Outgoing,
            state: api::TransferState::Offered,
            detail: None,
            bytes_done: 0,
            bytes_total: 0,
        });
        assert_eq!(quiet.detail, "");
    }

    /// A contact is named by its device fingerprint (not its person key)
    /// and keeps its route.
    #[test]
    fn contacts_keep_their_route() {
        for (route, expected) in [
            (None, Route::None),
            (Some(api::Route::Lan), Route::Lan),
            (Some(api::Route::Relay), Route::Relay),
        ] {
            let contact = Contact::from(api::ContactInfo {
                device: "fedcba98".repeat(8),
                person: "11".repeat(32),
                available: true,
                nearby: false,
                connected: true,
                route,
            });
            assert_eq!(contact.name, "Device FEDC BA98");
            assert_eq!(contact.route, expected);
            assert!(contact.available && !contact.nearby && contact.connected);
        }
    }

    /// A device is called by its fingerprint's first eight hex digits,
    /// whatever else the text holds.
    #[test]
    fn devices_are_named_by_fingerprint() {
        assert_eq!(name_of(&"abcdef0123".repeat(7)), "Device ABCD EF01");
        assert_eq!(name_of("ab\u{202e}cd-ef"), "Device ABCD EF");
        assert_eq!(name_of("abc"), "Device ABC");
        assert_eq!(name_of(""), "Device ");
    }

    /// Counts beyond what the boundary carries saturate.
    #[test]
    fn counts_saturate() {
        assert_eq!(count(7), 7);
        if let Ok(huge) = usize::try_from(u64::from(u32::MAX) + 1) {
            assert_eq!(count(huge), u32::MAX);
        }
    }

    /// Every key protection maps both ways unchanged.
    #[test]
    fn key_protections_round_trip() {
        for protection in [
            KeyProtection::File,
            KeyProtection::Keychain,
            KeyProtection::SecureEnclave,
            KeyProtection::Dpapi,
            KeyProtection::Tpm,
            KeyProtection::SecretService,
            KeyProtection::Portal,
            KeyProtection::StrongBox,
            KeyProtection::Tee,
        ] {
            let core: api::KeyProtection = protection.into();
            assert_eq!(KeyProtection::from(core), protection);
        }
    }

    /// The STS key crosses as bytes, never in a printout; a key that is
    /// not hexadecimal crosses as none (the UWB stack then refuses).
    #[test]
    fn rangings_cross_with_their_key_unprinted() -> Result<(), &'static str> {
        let ranging = |sts_key: &str| api::Ranging {
            contact: "ab".into(),
            session_id: 9,
            controller: 1,
            controlee: Some(2),
            channel: 9,
            preamble: 10,
            config: 1,
            sts_key: sts_key.to_owned(),
        };
        let key = "00112233445566778899aabbccddeeff";
        let CoreEvent::RangingRequested { ranging: info } =
            CoreEvent::from(api::Event::RangingRequested(ranging(key)))
        else {
            return Err("a ranging became something else");
        };
        assert_eq!(
            info.sts_key,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
        assert_eq!(
            (info.controller, info.controlee, info.session_id),
            (1, Some(2), 9)
        );
        let printed = format!("{info:?}");
        assert!(!printed.contains("sts_key") && !printed.contains("17"));
        for bad in ["0", "zz", "0g"] {
            assert_eq!(RangingInfo::from(ranging(bad)).sts_key, Vec::<u8>::new());
        }
        assert_eq!(unhex("0aFf"), Some(vec![0x0a, 0xff]));
        Ok(())
    }
}
