//! Link setup records (PROTOCOL §10.2) on arbitrary bytes: the first byte
//! picks the record (0 `LinkAbilities`, 1 `LinkOffer`, 2 `LinkAnswer`), the
//! rest is its body (for `LinkAbilities`, two bodies: this end's and the
//! peer's). An accepted body must be canonical, re-encoding to exactly its
//! input, and the link choice must look the same from both ends.
#![no_main]

use libfuzzer_sys::fuzz_target;
use todoke_proto::link::{LinkAbilities, LinkAnswer, LinkOffer, choose};

fuzz_target!(|data: &[u8]| {
    let Some((&kind, body)) = data.split_first() else {
        return;
    };
    match kind % 3 {
        0 => {
            let (Some(own), Some(rest)) = (body.get(..3), body.get(3..)) else {
                return;
            };
            if let Ok(abilities) = LinkAbilities::decode(own) {
                assert_eq!(abilities.encode().as_slice(), own);
                if let Some(peer) = rest.get(..3).and_then(|peer| LinkAbilities::decode(peer).ok()) {
                    for smaller in [true, false] {
                        let mine = choose(abilities, peer, smaller);
                        let theirs = choose(peer, abilities, !smaller);
                        assert_eq!(mine.map(|c| (c.kind, c.security)), theirs.map(|c| (c.kind, c.security)));
                        if let (Some(mine), Some(theirs)) = (mine, theirs) {
                            assert_ne!(mine.role, theirs.role);
                            assert!(mine.security.fits(mine.kind));
                        }
                    }
                }
            }
        }
        1 => {
            if let Ok(offer) = LinkOffer::decode(body) {
                assert_eq!(offer.encode().as_slice(), body);
                assert!(offer.security().fits(offer.kind()));
            }
        }
        _ => {
            if let Ok(answer) = LinkAnswer::decode(body) {
                assert_eq!(answer.encode().as_slice(), body);
            }
        }
    }
});
