//! Link setup records (PROTOCOL §10.2) on arbitrary bytes: the first byte
//! picks the record (0 `LinkAbilities`, 1 `LinkOffer`, 2 `LinkAnswer`), the
//! rest is its body. An accepted body must be canonical, re-encoding to
//! exactly its input, and the link choice must look the same from both
//! ends.
#![no_main]

use libfuzzer_sys::fuzz_target;
use todoke_proto::link::{LinkAbilities, LinkAnswer, LinkOffer, LinkRole, choose};

fuzz_target!(|data: &[u8]| {
    let Some((&kind, body)) = data.split_first() else {
        return;
    };
    match kind % 3 {
        0 => {
            if let Ok(abilities) = LinkAbilities::decode(body) {
                assert_eq!(abilities.encode().as_slice(), body);
                if let Some(peer) = body
                    .get(..2)
                    .and_then(|_| LinkAbilities::decode(&[body[1], body[0]]).ok())
                {
                    for smaller in [true, false] {
                        let mine = choose(abilities, peer, smaller);
                        let theirs = choose(peer, abilities, !smaller);
                        assert_eq!(mine.map(|(kind, _)| kind), theirs.map(|(kind, _)| kind));
                        if let (Some((_, a)), Some((_, b))) = (mine, theirs) {
                            assert!(matches!(
                                (a, b),
                                (LinkRole::Host, LinkRole::Join) | (LinkRole::Join, LinkRole::Host)
                            ));
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
