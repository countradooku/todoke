//! Entry points for `cargo fuzz` harnesses; compiled only with `--cfg fuzzing`.
//!
//! Every input is parsed by the real prelude reader and handshake driver,
//! set up deterministically from the public §4.2 fixture inputs
//! (`spec/test-vectors/handshake-*.json`), so a fuzzer can start from the
//! committed transcripts and mutate them.

use core::time::Duration;

use todoke_proto::session::{Hello, SessionMode, prelude_record_len};
use zeroize::Zeroizing;

use super::UnauditedSuite0001;
use super::engine::Entropy;
use super::handshake::{
    CODE_OFFER_LEN, CODE_SHARE_LEN, CodeTranscript, HandshakeDriver, InitiatorPlan, ResponderPlan,
    read_client_hello,
};
use super::keys::{NoiseStaticKey, PairingPsk};

const START: Duration = Duration::from_secs(1);
/// Fuzz builds enable the `unaudited-suite-0001` feature (`fuzz/Cargo.toml`).
const GATE: UnauditedSuite0001 = UnauditedSuite0001::acknowledge_not_production_ready();
const INIT_STATIC: [u8; 32] = [0x11; 32];
const RESP_STATIC: [u8; 32] = [0x33; 32];
const PSK: [u8; 32] = [0x55; 32];

/// Splits `data` into prelude records (`kind || body`), stopping at the
/// first invalid prefix or incomplete record.
fn records(mut data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while let Some((prefix, rest)) = data.split_first_chunk::<2>() {
        let Ok(length) = prelude_record_len(*prefix) else {
            break;
        };
        let Some(record) = rest.get(..length) else {
            break;
        };
        out.push(record);
        data = &rest[length..];
    }
    out
}

fn mode(selector: u8) -> SessionMode {
    match selector % 3 {
        0 => SessionMode::Qr,
        1 => SessionMode::Code,
        _ => SessionMode::Contact,
    }
}

fn key(secret: [u8; 32]) -> Option<NoiseStaticKey> {
    NoiseStaticKey::from_secret(Zeroizing::new(secret)).ok()
}

fn psk() -> PairingPsk {
    PairingPsk::from_bytes(Zeroizing::new(PSK))
}

fn transcript() -> CodeTranscript {
    CodeTranscript::new(
        [0x31; CODE_OFFER_LEN],
        [0x32; CODE_SHARE_LEN],
        [0x33; CODE_SHARE_LEN],
    )
}

/// The fixture `ClientHello` for `mode` (generation 7 for contacts).
fn client_hello(mode: SessionMode) -> Option<Hello> {
    let generation = if mode == SessionMode::Contact { 7 } else { 0 };
    Hello::client(mode, generation, [0xa1; 16], [0xa5; 16]).ok()
}

/// Handshake input parsing. The first byte selects the mode (`% 3`) and
/// the role (`& 4`: responder when clear); the rest is a stream of prelude
/// records fed to the driver until it fails or completes. The responder
/// also parses the first record as a `ClientHello`.
pub fn handshake_records(data: &[u8]) {
    let Some((&selector, stream)) = data.split_first() else {
        return;
    };
    let mode = mode(selector);
    let (Some(initiator_static), Some(responder_static)) = (key(INIT_STATIC), key(RESP_STATIC))
    else {
        return;
    };
    let Some(hello) = client_hello(mode) else {
        return;
    };
    let inputs = records(stream);
    if let Some(first) = inputs.first() {
        let _ = read_client_hello(first);
    }
    let driver = if selector & 4 == 0 {
        let plan = match mode {
            SessionMode::Qr => ResponderPlan::qr(psk()),
            SessionMode::Code => ResponderPlan::code(psk(), transcript()),
            SessionMode::Contact => {
                ResponderPlan::contact(7, Zeroizing::new(PSK), *initiator_static.public_key())
            }
        };
        let entropy = Entropy::scripted(vec![vec![0x62; 32], vec![0x64; 32]]);
        HandshakeDriver::responder(
            GATE,
            hello,
            plan,
            &responder_static,
            [0xa6; 16],
            entropy,
            START,
        )
        .map(|(driver, _)| driver)
    } else {
        let plan = match mode {
            SessionMode::Qr => InitiatorPlan::qr([0xa1; 16], *responder_static.public_key(), psk()),
            SessionMode::Code => InitiatorPlan::code([0xa1; 16], psk(), transcript()),
            SessionMode::Contact => InitiatorPlan::contact(
                7,
                [0xa1; 16],
                Zeroizing::new(PSK),
                *responder_static.public_key(),
            ),
        };
        let entropy = Entropy::scripted(vec![vec![0x61; 32], vec![0x63; 64]]);
        HandshakeDriver::initiator(GATE, plan, &initiator_static, [0xa5; 16], entropy, START)
            .map(|(driver, _)| driver)
    };
    let Ok(mut driver) = driver else {
        return;
    };
    for record in inputs {
        if driver.receive(record, START).is_err() {
            return;
        }
        if driver.is_done() {
            let _ = driver.finish();
            return;
        }
    }
}
