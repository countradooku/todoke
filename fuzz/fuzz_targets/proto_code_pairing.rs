//! Human-code pairing prelude bodies (`CodeOfferRequest`, `CodeOffer`,
//! `CodeShareA`/`CodeShareB`) on arbitrary bytes; accepted input must be
//! canonical, and a reply must echo its request.
#![no_main]

use libfuzzer_sys::fuzz_target;
use todoke_proto::pairing::{
    CODE_OFFER_REQUEST_LEN, CodeOffer, CodeOfferRequest, CodeShare,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = CodeOfferRequest::decode(data) {
        assert_eq!(request.encode().as_slice(), data);
    }
    if let Ok(offer) = CodeOffer::decode(data) {
        assert_eq!(offer.encode().as_slice(), data);
    }
    if let Ok(share) = CodeShare::decode(data) {
        assert_eq!(share.encode().as_slice(), data);
    }
    // A request followed by a reply, as on the wire.
    if let Some((request, reply)) = data.split_first_chunk::<CODE_OFFER_REQUEST_LEN>() {
        if let Ok(request) = CodeOfferRequest::decode(request) {
            if let Ok(offer) = CodeOffer::decode_reply(reply, &request) {
                assert_eq!(offer.stranger_token(), request.stranger_token());
                assert_eq!(offer.encode().as_slice(), reply);
            }
        }
    }
});
