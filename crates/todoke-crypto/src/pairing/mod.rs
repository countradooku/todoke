//! QR and human-code pairing (PROTOCOL §3, §4.3, §4.4, §10, §13).
//!
//! Pairing is local intent to trust a device, never consent to receive a
//! file (§3.1, §7). It ends in a contact with pinned keys and a ratcheted
//! pair PSK, created only after a mutually authenticated session (§4.3)
//! commits its first ratchet (§4.4).
//!
//! # QR pairing (`IKpsk2`)
//!
//! The displayer is the responder; the scanner is the initiator.
//!
//! ```text
//! displayer                                   scanner
//! offers.create_qr(&local, now, mono)
//!   -> QrPayload::to_text()  ==== shown ====> QrPayload::from_text(text, now)
//!                                             store.begin_qr_pairing(&payload, now)
//!                                               -> (plan, authority)
//! IncomingSession::accept_any(..)  <--------  Session::initiate(.., plan, &mut authority)
//! incoming.reserve_offer(&offers, now)
//!   -> reservation.into_qr_responder(&mut store)
//!   -> (plan, authority)
//! incoming.respond(.., plan, &mut authority)
//! ```
//!
//! Both [`PairingAuthority`] values then do the same: verify the peer's
//! binding under the root it names (trust in that root originates in this
//! authenticated pairing, §2), check revocations and expiry, and — on the
//! scanner — pin the responder's three full keys from the QR against that
//! binding (§3.1). At the §4.4 journal they durably record the pending
//! pairing and burn the offer in one write; the commit creates the contact
//! through the same path as [`ContactStore::pair`](crate::identity::ContactStore::pair).
//!
//! # Human-code pairing (`CPace`, then `XXpsk3`)
//!
//! Disabled for production (O2): every entry point needs an
//! [`UnauditedCodePairing`] acknowledgement, and the `CPace` backend
//! (`pakery`, `docs/adr/0002-cpace.md`) exists only with the non-default
//! `unaudited-code-pairing` feature.
//!
//! ```text
//! displayer                                   entrant
//! offers.create_code(gate, ..) -> HumanCode == shown ==> HumanCode::parse(typed)
//! IncomingSession::accept_any(..)  <-- CodeOfferRequest --  Session::initiate_code_pairing(
//!   -> request.answer(gate, &offers, token, now)              .., token, &code, &mut store)
//!                                  --- CodeOffer --->
//!                                  <-- ClientHello ---
//! incoming.reserve_offer(&offers, now)
//!   -> reservation.into_code_responder(gate, &mut store)
//! incoming.respond(.., plan, &mut authority)
//!            ServerHello, CodeShareA/B (CPace), XX messages, Identity, ratchet
//! ```
//!
//! The PSK is `HKDF(B3(pre_noise), ISK, "todoke/v1/cpace-psk\0", 32)` over
//! the exact §3.2 transcript, which also forms the Noise prologue. A wrong
//! code fails the Noise authentication at the displayer, which closes
//! silently; each attempt that does not reach the journal costs the offer
//! one of its five failures.
//!
//! # Offers and budgets
//!
//! [`PairingOffers`] holds the displayer's offers in memory and enforces
//! one attempt per offer at a time, the code attempt budget, and the §13
//! unauthenticated-attempt budget. Only a stream that began with the code
//! offer exchange may attempt a code offer. A reservation that ends
//! without reaching the journal frees a QR offer and counts as a failed
//! attempt on a code offer.
//!
//! # Secrets
//!
//! The QR payload carries the displayer's one-time PSK and the code is a
//! password. Both are zeroized, redacted in `Debug`, and absent from every
//! error. The QR text is sensitive: anyone who sees it may race to pair
//! (§3.1), so it must not be logged, uploaded, placed in a URL, or passed
//! across FFI as raw bytes. How a platform UI renders or scans it without
//! that is open (O5).

mod authority;
mod base45;
mod code;
pub(crate) mod cpace;
#[cfg(fuzzing)]
pub mod fuzzing;
mod offers;
mod qr;
pub(crate) mod transcript;

use core::fmt;

pub use authority::PairingAuthority;
pub use code::{CODE_DIGITS, HumanCode, InvalidCode};
pub(crate) use offers::AttemptPermit;
pub use offers::{
    CODE_ATTEMPT_SPACING, MAX_ATTEMPT_STARTS_PER_MINUTE, MAX_CODE_FAILURES,
    MAX_CONCURRENT_ATTEMPTS, MAX_OFFERS, OfferKind, OfferReservation, PairingOffers,
};
pub use qr::{
    OFFER_LIFETIME_SECONDS, QR_MAGIC, QR_PAYLOAD_LEN, QR_TEXT_LEN, QR_TEXT_PREFIX, QrError,
    QrPayload, QrRendezvousError, RendezvousToken,
};

/// Why a pairing step was refused. Carries no secret, token, or pairing ID.
/// Errors about an incoming attempt are for local reporting only: the
/// stream is closed without telling the peer why (§3.2, §12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairingError {
    /// The QR payload is invalid or expired.
    Qr(QrError),
    /// No live offer has this pairing ID (unknown, withdrawn, burned, or
    /// exhausted), or the stranger token is not the advertised one.
    UnknownOffer,
    /// The offer expired.
    Expired,
    /// The Hello's mode does not match the offer's.
    Mode,
    /// Another attempt holds the offer.
    OfferBusy,
    /// A code-mode `ClientHello` on a stream that did not begin with the
    /// `CodeOfferRequest`/`CodeOffer` exchange (§3.2).
    NoOfferExchange,
    /// Less than 2 seconds since the previous attempt on this code offer.
    TooSoon,
    /// The §13 unauthenticated-attempt budget is exhausted for now.
    RateLimited,
    /// [`MAX_OFFERS`] offers are live.
    TooManyOffers,
    /// This pairing ID was already used, or its pairing was interrupted
    /// after its journal: scan or enter a new one (§3.1).
    Burned,
    /// Another new pairing is journaled in this store and not finished.
    PairingInProgress,
    /// The local binding is not valid now.
    LocalIdentity,
    /// OS randomness was unavailable.
    Random,
    /// The offer table is unusable after a panic elsewhere (fail closed).
    Unavailable,
    /// This build has no `CPace` backend: human-code pairing is disabled
    /// (PROTOCOL §16, O2).
    CodePairingUnavailable,
}

impl fmt::Display for PairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Qr(error) => write!(f, "QR payload rejected: {error}"),
            Self::UnknownOffer => f.write_str("no such pairing offer"),
            Self::Expired => f.write_str("pairing offer expired"),
            Self::Mode => f.write_str("pairing mode does not match the offer"),
            Self::OfferBusy => f.write_str("pairing offer is in use by another attempt"),
            Self::NoOfferExchange => {
                f.write_str("code pairing attempt without the code offer exchange")
            }
            Self::TooSoon => f.write_str("pairing attempt too soon after the previous one"),
            Self::RateLimited => f.write_str("too many pairing attempts; try again later"),
            Self::TooManyOffers => f.write_str("too many pairing offers"),
            Self::Burned => f.write_str("pairing offer already used; create a new one"),
            Self::PairingInProgress => f.write_str("another pairing is in progress"),
            Self::LocalIdentity => f.write_str("local identity is not valid now"),
            Self::Random => f.write_str("randomness unavailable"),
            Self::Unavailable => f.write_str("pairing offers unavailable"),
            Self::CodePairingUnavailable => {
                f.write_str("code pairing is not available in this build")
            }
        }
    }
}

impl std::error::Error for PairingError {}

/// Acknowledgement that human-code pairing is not production-ready
/// (PROTOCOL §16: gate O2 is open; `CPace` comes from an unreviewed library,
/// `docs/adr/0002-cpace.md`, and the §3.2 context needs conformance
/// vectors). Required by every code-pairing entry point.
///
/// It can be obtained only through
/// `UnauditedCodePairing::acknowledge_not_production_ready()`, which exists
/// only in this crate's unit tests and with the non-default
/// `unaudited-code-pairing` feature. Without that feature there is also no
/// `CPace` backend. CI (`scripts/ci/deny-exceptions-dev-only.sh`) fails if
/// any shipped graph enables the feature.
///
/// Without the feature, this does not compile:
///
#[cfg_attr(not(feature = "unaudited-code-pairing"), doc = "```compile_fail")]
#[cfg_attr(feature = "unaudited-code-pairing", doc = "```")]
/// let _gate = todoke_crypto::pairing::UnauditedCodePairing::acknowledge_not_production_ready();
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnauditedCodePairing(());

impl UnauditedCodePairing {
    /// Acknowledges that human-code pairing, its `CPace` library, and its
    /// transcript bindings are unaudited and disabled for production.
    ///
    /// Exists only with the `unaudited-code-pairing` feature or in this
    /// crate's unit tests.
    #[cfg(any(test, feature = "unaudited-code-pairing"))]
    #[must_use]
    pub const fn acknowledge_not_production_ready() -> Self {
        Self(())
    }
}

impl From<QrError> for PairingError {
    fn from(error: QrError) -> Self {
        Self::Qr(error)
    }
}

#[cfg(test)]
mod code_tests;
#[cfg(test)]
mod tests;
