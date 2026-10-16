//! Link setup inside the session (PROTOCOL §10.2): this engine checks and
//! sequences the records; the caller decides whether to take part (it
//! sends `LinkAbilities` only if it can host or join something now), when
//! to host (only for a transfer the user started or accepted, pending or
//! running), and does the hosting and joining.
//!
//! Each side sends `LinkAbilities` at most once, after `Capabilities`.
//! Once both have, the choice is made once ([`todoke_proto::link::choose`])
//! and reported. Only the chosen host may offer, once, exactly the chosen
//! kind with exactly the security the choice gives (the strongest the
//! joiner can join): anything else from the peer is STATE, so a host
//! cannot talk a joiner into a weaker link. Only the joiner answers, once,
//! the offer it got. An endpoint that sent no `LinkAbilities` takes no
//! part: any `LinkOffer` or `LinkAnswer` it receives is STATE.

use todoke_proto::link::{
    LinkAbilities, LinkAnswer, LinkChoice, LinkOffer, LinkResult, LinkRole, OFFER_ID_LEN, choose,
};

use super::{Violation, violation};
use crate::events::FailureCode;

/// Why a local link-setup step was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// The session is not ready (Capabilities not exchanged) or closed.
    NotReady,
    /// `LinkAbilities` was already sent in this session.
    AlreadySent,
    /// No link was chosen, or this endpoint is not the chosen host (for an
    /// offer) or joiner (for an answer).
    NotChosen,
    /// The offer is not the chosen kind and security.
    WrongOffer,
    /// An offer was already sent, or the offer was already answered.
    Done,
    /// No offer was received, or the answer names another offer.
    NoOffer,
}

impl core::fmt::Display for LinkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotReady => "the session is not ready for link setup",
            Self::AlreadySent => "link abilities were already sent in this session",
            Self::NotChosen => "this endpoint does not have that role in the chosen link",
            Self::WrongOffer => "the offer is not the chosen kind and security",
            Self::Done => "link setup already went past this step",
            Self::NoOffer => "no such link offer",
        })
    }
}

impl std::error::Error for LinkError {}

/// Where the offer stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Offer {
    None,
    /// The host sent this offer; its answer is awaited.
    Sent([u8; OFFER_ID_LEN]),
    /// The joiner got this offer; its answer is to be sent.
    Received([u8; OFFER_ID_LEN]),
    /// Answered: link setup is over for the session.
    Answered,
}

/// The session's link setup.
#[derive(Debug)]
pub(crate) struct LinkSetup {
    own: Option<LinkAbilities>,
    peer: Option<LinkAbilities>,
    choice: Option<LinkChoice>,
    offer: Offer,
}

/// What a step produced, for the engine to report.
pub(crate) enum Step {
    Nothing,
    Chosen(LinkChoice),
    Offered(Box<LinkOffer>),
    Answered(LinkAnswer),
}

impl LinkSetup {
    pub(crate) const fn new() -> Self {
        Self {
            own: None,
            peer: None,
            choice: None,
            offer: Offer::None,
        }
    }

    /// The choice, once both sides have sent their abilities and one fits.
    pub(crate) const fn choice(&self) -> Option<LinkChoice> {
        self.choice
    }

    /// This side sends `own`; `own_key_smaller` breaks a hosting tie.
    pub(crate) fn send_abilities(
        &mut self,
        own: LinkAbilities,
        own_key_smaller: bool,
    ) -> Result<Step, LinkError> {
        if self.own.is_some() {
            return Err(LinkError::AlreadySent);
        }
        self.own = Some(own);
        Ok(self.decide(own_key_smaller))
    }

    /// The peer's `LinkAbilities`: decoded, once.
    pub(crate) fn on_abilities(
        &mut self,
        body: &[u8],
        own_key_smaller: bool,
    ) -> Result<Step, Violation> {
        let peer = LinkAbilities::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        if self.peer.is_some() {
            return Err(violation(FailureCode::State));
        }
        self.peer = Some(peer);
        Ok(self.decide(own_key_smaller))
    }

    fn decide(&mut self, own_key_smaller: bool) -> Step {
        let (Some(own), Some(peer)) = (self.own, self.peer) else {
            return Step::Nothing;
        };
        self.choice = choose(own, peer, own_key_smaller);
        self.choice.map_or(Step::Nothing, Step::Chosen)
    }

    /// The host's offer: only the chosen kind and security, once.
    pub(crate) fn offer(&mut self, offer: &LinkOffer) -> Result<(), LinkError> {
        let choice = self.choice.ok_or(LinkError::NotChosen)?;
        if choice.role != LinkRole::Host {
            return Err(LinkError::NotChosen);
        }
        if offer.kind() != choice.kind || offer.security() != choice.security {
            return Err(LinkError::WrongOffer);
        }
        if self.offer != Offer::None {
            return Err(LinkError::Done);
        }
        self.offer = Offer::Sent(*offer.offer_id());
        Ok(())
    }

    /// The host's `LinkOffer`, for the joiner: decoded and checked against
    /// the choice.
    pub(crate) fn on_offer(&mut self, body: &[u8]) -> Result<Step, Violation> {
        let state = || violation(FailureCode::State);
        // No abilities sent: no part in link setup, whatever the body.
        if self.own.is_none() {
            return Err(state());
        }
        let offer = LinkOffer::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        // No abilities sent (no part in link setup), no choice, or this
        // side is the host: an offer is out of place.
        let choice = self.choice.ok_or_else(state)?;
        if self.own.is_none() || choice.role != LinkRole::Join || self.offer != Offer::None {
            return Err(state());
        }
        // Another kind, or a security weaker (or other) than the strongest
        // this side can join: never passed on.
        if offer.kind() != choice.kind || offer.security() != choice.security {
            return Err(state());
        }
        self.offer = Offer::Received(*offer.offer_id());
        Ok(Step::Offered(Box::new(offer)))
    }

    /// The joiner's answer to the offer it got, once.
    pub(crate) fn answer(
        &mut self,
        offer_id: &[u8; OFFER_ID_LEN],
        result: LinkResult,
    ) -> Result<LinkAnswer, LinkError> {
        match self.offer {
            Offer::Received(id) if id == *offer_id => {
                self.offer = Offer::Answered;
                Ok(LinkAnswer {
                    offer_id: *offer_id,
                    result,
                })
            }
            Offer::Answered => Err(LinkError::Done),
            _ => Err(LinkError::NoOffer),
        }
    }

    /// The joiner's `LinkAnswer`, for the host: to its offer, once.
    pub(crate) fn on_answer(&mut self, body: &[u8]) -> Result<Step, Violation> {
        if self.own.is_none() {
            return Err(violation(FailureCode::State));
        }
        let answer = LinkAnswer::decode(body).map_err(|_| violation(FailureCode::Malformed))?;
        match self.offer {
            Offer::Sent(id) if id == answer.offer_id => {
                self.offer = Offer::Answered;
                Ok(Step::Answered(answer))
            }
            _ => Err(violation(FailureCode::State)),
        }
    }
}
