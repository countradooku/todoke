//! The displayer's pairing offers and the unauthenticated-attempt budgets
//! (PROTOCOL §3.1, §3.2, §13).
//!
//! Offers live only in memory: a restart destroys every offer that was not
//! burned, which is equivalent to burning it (§3.1: "generate a new one").
//! Burning an offer that reached a journal is also durable, through the
//! contact store's ledger.
//!
//! | Rule | Where |
//! | --- | --- |
//! | One authenticated attempt per offer at a time; unauthenticated failures do not consume a QR offer | [`PairingOffers::reserve`], [`OfferReservation`] |
//! | A code offer: at most 5 failed attempts, at least 2 s between attempts, one `CPace` at a time | [`PairingOffers::reserve`] |
//! | Offers expire after 300 s, measured on both the wall and the monotonic clock | every operation |
//! | At most 4 unauthenticated attempts at once and 20 starts per minute | the shared budget of [`PairingOffers::reserve`] |
//!
//! The §13 budget here covers pairing attempts. Contact sessions share the
//! same §13 limits; applying them to contact attempts is the caller's job
//! until the core has a single admission point.

use core::fmt;
use core::time::Duration;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use todoke_proto::pairing::{CodeOffer, CodeOfferRequest, STRANGER_TOKEN_LEN};
use todoke_proto::session::{Hello, SessionMode};
use todoke_proto::time::UnixTime;
use zeroize::Zeroizing;

use super::PairingError;
use super::code::HumanCode;
use super::qr::{OFFER_LIFETIME_SECONDS, QrPayload};
use crate::identity::KeyStore;
use crate::rng;
use crate::session::LocalIdentity;

/// Local quota: live offers at once.
pub const MAX_OFFERS: usize = 4;
/// §3.2: failed attempts a code offer allows in total.
pub const MAX_CODE_FAILURES: u8 = 5;
/// §3.2: minimum time between two attempts on one code offer.
pub const CODE_ATTEMPT_SPACING: Duration = Duration::from_secs(2);
/// §13: unauthenticated attempts in progress at once.
pub const MAX_CONCURRENT_ATTEMPTS: usize = 4;
/// §13: attempt starts per minute.
pub const MAX_ATTEMPT_STARTS_PER_MINUTE: usize = 20;
const MINUTE: Duration = Duration::from_secs(60);
const OFFER_LIFETIME: Duration = Duration::from_secs(OFFER_LIFETIME_SECONDS);

/// The secret behind an offer.
#[derive(Clone)]
pub(crate) enum OfferSecret {
    /// The QR one-time PSK.
    Qr(Zeroizing<[u8; 32]>),
    /// The human code.
    Code(HumanCode),
}

impl OfferSecret {
    fn mode(&self) -> SessionMode {
        match self {
            Self::Qr(_) => SessionMode::Qr,
            Self::Code(_) => SessionMode::Code,
        }
    }
}

struct Slot {
    secret: OfferSecret,
    expires_at: UnixTime,
    /// Monotonic expiry.
    deadline: Duration,
    reserved: bool,
    failures: u8,
    last_attempt: Option<Duration>,
}

impl Slot {
    fn live(&self, now: UnixTime, mono: Duration) -> bool {
        now < self.expires_at && mono < self.deadline && self.failures < MAX_CODE_FAILURES
    }
}

/// §13: unauthenticated attempts in progress and recent starts.
#[derive(Debug, Default)]
struct Budget {
    active: usize,
    starts: VecDeque<Duration>,
}

impl Budget {
    fn try_start(&mut self, mono: Duration) -> Result<(), PairingError> {
        while self
            .starts
            .front()
            .is_some_and(|&start| mono.saturating_sub(start) >= MINUTE)
        {
            self.starts.pop_front();
        }
        if self.active >= MAX_CONCURRENT_ATTEMPTS
            || self.starts.len() >= MAX_ATTEMPT_STARTS_PER_MINUTE
        {
            return Err(PairingError::RateLimited);
        }
        self.active += 1;
        self.starts.push_back(mono);
        Ok(())
    }

    fn finish(&mut self) {
        self.active = self.active.saturating_sub(1);
    }
}

#[derive(Default)]
struct Table {
    budget: Budget,
    offers: BTreeMap<[u8; 16], Slot>,
}

impl Table {
    fn prune(&mut self, now: UnixTime, mono: Duration) {
        // A reserved offer stays until its reservation ends.
        self.offers
            .retain(|_, slot| slot.reserved || slot.live(now, mono));
    }
}

/// The displayer's live offers, shared by every incoming attempt. Cloning
/// shares the same offers.
///
/// Every method takes the trusted wall-clock time (`now`) and the
/// monotonic time (`mono`) of one clock the caller keeps for all calls.
#[derive(Clone, Default)]
pub struct PairingOffers {
    table: Arc<Mutex<Table>>,
}

/// Which way an offer is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfferKind {
    /// A QR code (§3.1).
    Qr,
    /// A human code (§3.2).
    Code,
}

impl PairingOffers {
    /// An empty set of offers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<MutexGuard<'_, Table>, PairingError> {
        // A poisoned table fails closed: no offer is usable any more.
        self.table.lock().map_err(|_| PairingError::Unavailable)
    }

    fn expiry(now: UnixTime) -> Result<UnixTime, PairingError> {
        UnixTime::new(now.seconds().saturating_add(OFFER_LIFETIME_SECONDS))
            .ok_or(PairingError::LocalIdentity)
    }

    fn insert(
        table: &mut Table,
        secret: OfferSecret,
        now: UnixTime,
        mono: Duration,
    ) -> Result<([u8; 16], UnixTime), PairingError> {
        table.prune(now, mono);
        if table.offers.len() >= MAX_OFFERS {
            return Err(PairingError::TooManyOffers);
        }
        let pairing_id = rng::nonzero_id().map_err(|_| PairingError::Random)?;
        let expires_at = Self::expiry(now)?;
        table.offers.insert(
            pairing_id,
            Slot {
                secret,
                expires_at,
                deadline: mono.saturating_add(OFFER_LIFETIME),
                reserved: false,
                failures: 0,
                last_attempt: None,
            },
        );
        Ok((pairing_id, expires_at))
    }

    /// Creates a QR offer for `local`: a fresh pairing ID and one-time PSK,
    /// valid for 300 seconds. Show it with [`QrPayload::to_text`]; it is
    /// sensitive (§3.1).
    ///
    /// # Errors
    ///
    /// [`PairingError::LocalIdentity`] if the local binding is not valid at
    /// `now`, [`PairingError::TooManyOffers`], or [`PairingError::Random`].
    pub fn create_qr<K: KeyStore>(
        &self,
        local: &LocalIdentity<'_, K>,
        now: UnixTime,
        mono: Duration,
    ) -> Result<QrPayload, PairingError> {
        local
            .check_valid_at(now)
            .map_err(|_| PairingError::LocalIdentity)?;
        let mut psk = Zeroizing::new([0; 32]);
        rng::fill(psk.as_mut_slice()).map_err(|_| PairingError::Random)?;
        let mut table = self.lock()?;
        let (pairing_id, expires_at) =
            Self::insert(&mut table, OfferSecret::Qr(psk.clone()), now, mono)?;
        let binding = local.binding();
        Ok(QrPayload::new(
            pairing_id,
            expires_at,
            *binding.device_public(),
            *binding.noise_static(),
            Box::new(*binding.kem_static()),
            psk,
        ))
    }

    /// Creates a human-code offer, valid for 300 seconds, and returns the
    /// code to show. It replaces any earlier code offer: a new code is the
    /// local action §3.2 requires after an offer is exhausted.
    ///
    /// # Errors
    ///
    /// [`PairingError::TooManyOffers`] or [`PairingError::Random`].
    pub fn create_code(&self, now: UnixTime, mono: Duration) -> Result<HumanCode, PairingError> {
        let code = HumanCode::generate().map_err(|_| PairingError::Random)?;
        let mut table = self.lock()?;
        table
            .offers
            .retain(|_, slot| !matches!(slot.secret, OfferSecret::Code(_)));
        Self::insert(&mut table, OfferSecret::Code(code.clone()), now, mono)?;
        Ok(code)
    }

    /// Withdraws every offer (the user closed the pairing screen). Attempts
    /// in progress fail at their next authority step.
    pub fn cancel_all(&self) {
        if let Ok(mut table) = self.lock() {
            table.offers.clear();
        }
    }

    /// The number of live offers of `kind`.
    #[must_use]
    pub fn live(&self, kind: OfferKind, now: UnixTime, mono: Duration) -> usize {
        self.lock().map_or(0, |table| {
            table
                .offers
                .values()
                .filter(|slot| {
                    slot.live(now, mono)
                        && matches!(
                            (&slot.secret, kind),
                            (OfferSecret::Qr(_), OfferKind::Qr)
                                | (OfferSecret::Code(_), OfferKind::Code)
                        )
                })
                .count()
        })
    }

    /// Answers a `CodeOfferRequest` (§3.2) with the live code offer, if the
    /// request names the stranger token this device currently advertises
    /// (`advertised`, from the discovery layer). The offer is public; any
    /// number of requests may receive it, and none reserves it.
    ///
    /// # Errors
    ///
    /// [`PairingError::UnknownOffer`] for a stale or unknown token or when
    /// no code offer is live: close the stream silently.
    pub fn answer_code_request(
        &self,
        request: &CodeOfferRequest,
        advertised: &[u8; STRANGER_TOKEN_LEN],
        now: UnixTime,
        mono: Duration,
    ) -> Result<CodeOffer, PairingError> {
        if request.stranger_token() != advertised {
            return Err(PairingError::UnknownOffer);
        }
        let table = self.lock()?;
        let (pairing_id, slot) = table
            .offers
            .iter()
            .find(|(_, slot)| matches!(slot.secret, OfferSecret::Code(_)) && slot.live(now, mono))
            .ok_or(PairingError::UnknownOffer)?;
        CodeOffer::new(request, *pairing_id, slot.expires_at)
            .map_err(|_| PairingError::UnknownOffer)
    }

    /// Reserves the offer named by `hello`'s locator for this attempt.
    ///
    /// The `ClientHello` is untrusted: this only decides whether an attempt
    /// may start. The reservation ends when it is burned (the attempt
    /// reached the §4.4 journal) or dropped; a dropped QR reservation frees
    /// the offer again, while a dropped code reservation counts as a failed
    /// attempt.
    ///
    /// # Errors
    ///
    /// [`PairingError::UnknownOffer`] (unknown, withdrawn, burned, or
    /// exhausted), [`PairingError::Expired`], [`PairingError::Mode`] for a
    /// Hello of the other pairing mode, [`PairingError::OfferBusy`] while
    /// another attempt holds it, [`PairingError::TooSoon`] within 2 s of
    /// the previous code attempt, or [`PairingError::RateLimited`].
    pub fn reserve(
        &self,
        hello: &Hello,
        now: UnixTime,
        mono: Duration,
    ) -> Result<OfferReservation, PairingError> {
        let mut guard = self.lock()?;
        let table = &mut *guard;
        let pairing_id = *hello.locator();
        let slot = table
            .offers
            .get_mut(&pairing_id)
            .ok_or(PairingError::UnknownOffer)?;
        if slot.secret.mode() != hello.mode() {
            return Err(PairingError::Mode);
        }
        if slot.reserved {
            return Err(PairingError::OfferBusy);
        }
        if !slot.live(now, mono) {
            table.offers.remove(&pairing_id);
            return Err(PairingError::Expired);
        }
        if let OfferSecret::Code(_) = slot.secret
            && slot
                .last_attempt
                .is_some_and(|last| mono < last.saturating_add(CODE_ATTEMPT_SPACING))
        {
            return Err(PairingError::TooSoon);
        }
        table.budget.try_start(mono)?;
        slot.reserved = true;
        slot.last_attempt = Some(mono);
        Ok(OfferReservation {
            table: Arc::clone(&self.table),
            pairing_id,
            expires_at: slot.expires_at,
            secret: slot.secret.clone(),
            state: ReservationState::Unauthenticated,
        })
    }

    #[cfg(test)]
    pub(crate) fn active_attempts(&self) -> usize {
        self.lock().map_or(usize::MAX, |table| table.budget.active)
    }

    #[cfg(test)]
    pub(crate) fn failures(&self, pairing_id: &[u8; 16]) -> Option<u8> {
        self.lock()
            .ok()?
            .offers
            .get(pairing_id)
            .map(|slot| slot.failures)
    }

    #[cfg(test)]
    pub(crate) fn code_pairing_id(&self) -> Option<[u8; 16]> {
        self.lock()
            .ok()?
            .offers
            .iter()
            .find_map(|(id, slot)| matches!(slot.secret, OfferSecret::Code(_)).then_some(*id))
    }
}

impl fmt::Debug for PairingOffers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (offers, active) = self
            .lock()
            .map_or((0, 0), |table| (table.offers.len(), table.budget.active));
        f.debug_struct("PairingOffers")
            .field("offers", &offers)
            .field("active_attempts", &active)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReservationState {
    /// Counts against the §13 budget.
    Unauthenticated,
    /// The peer's `Identity` verified; no longer counts against §13.
    Authenticated,
    /// The offer is burned.
    Burned,
}

/// One attempt's hold on an offer. Dropping it without burning frees the
/// offer (QR) or records a failed attempt (code).
pub struct OfferReservation {
    table: Arc<Mutex<Table>>,
    pairing_id: [u8; 16],
    expires_at: UnixTime,
    secret: OfferSecret,
    state: ReservationState,
}

impl OfferReservation {
    /// The reserved offer's pairing ID.
    #[must_use]
    pub fn pairing_id(&self) -> &[u8; 16] {
        &self.pairing_id
    }

    /// The offer's expiry.
    #[must_use]
    pub fn expires_at(&self) -> UnixTime {
        self.expires_at
    }

    /// The pairing mode of the offer.
    #[must_use]
    pub fn kind(&self) -> OfferKind {
        match self.secret {
            OfferSecret::Qr(_) => OfferKind::Qr,
            OfferSecret::Code(_) => OfferKind::Code,
        }
    }

    pub(crate) fn secret(&self) -> &OfferSecret {
        &self.secret
    }

    /// The peer authenticated (§4.3): the attempt leaves the §13
    /// unauthenticated budget.
    pub(crate) fn authenticated(&mut self) {
        if self.state == ReservationState::Unauthenticated {
            if let Ok(mut table) = self.table.lock() {
                table.budget.finish();
            }
            self.state = ReservationState::Authenticated;
        }
    }

    /// Burns the offer: it can never be reserved again (§3.1, §3.2).
    pub(crate) fn burn(&mut self) {
        if self.state == ReservationState::Burned {
            return;
        }
        if let Ok(mut table) = self.table.lock() {
            if self.state == ReservationState::Unauthenticated {
                table.budget.finish();
            }
            table.offers.remove(&self.pairing_id);
        }
        self.state = ReservationState::Burned;
    }
}

impl Drop for OfferReservation {
    fn drop(&mut self) {
        if self.state == ReservationState::Burned {
            return;
        }
        // A poisoned table stays as it is: the offer remains reserved and
        // so unusable (fail closed).
        let Ok(mut guard) = self.table.lock() else {
            return;
        };
        let table = &mut *guard;
        if self.state == ReservationState::Unauthenticated {
            table.budget.finish();
        }
        let exhausted = match table.offers.get_mut(&self.pairing_id) {
            Some(slot) => {
                slot.reserved = false;
                if let OfferSecret::Code(_) = slot.secret {
                    slot.failures = slot.failures.saturating_add(1);
                }
                slot.failures >= MAX_CODE_FAILURES
            }
            None => false,
        };
        if exhausted {
            table.offers.remove(&self.pairing_id);
        }
    }
}

impl fmt::Debug for OfferReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfferReservation")
            .field("kind", &self.kind())
            .field("expires_at", &self.expires_at)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
