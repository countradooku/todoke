use super::*;
use crate::session::test_vectors::{Vector, hex_array_at, hex_at, json_at, load};
use todoke_proto::session::PRELUDE_PREFIX_LEN;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

const T: Duration = Duration::from_secs(1000);
const GATE: UnauditedSuite0001 = UnauditedSuite0001::acknowledge_not_production_ready();

fn static_key(vector: &Vector, pointer: &str) -> AnyResult<NoiseStaticKey> {
    Ok(NoiseStaticKey::from_secret(Zeroizing::new(
        hex_array_at::<32>(vector, pointer)?,
    ))?)
}

fn psk(vector: &Vector) -> AnyResult<PairingPsk> {
    Ok(PairingPsk::from_bytes(Zeroizing::new(hex_array_at::<32>(
        vector,
        "/inputs/psk_hex",
    )?)))
}

/// Strips and validates the length prefix of a complete prelude record.
fn body(record: &[u8]) -> AnyResult<&[u8]> {
    let prefix = record.first_chunk::<PRELUDE_PREFIX_LEN>().ok_or("short")?;
    let length = todoke_proto::session::prelude_record_len(*prefix)?;
    let rest = &record[PRELUDE_PREFIX_LEN..];
    if rest.len() != length {
        return Err("length prefix mismatch".into());
    }
    Ok(rest)
}

struct Pair {
    initiator: HandshakeDriver,
    responder: HandshakeDriver,
    client_hello: Vec<u8>,
    server_hello: Vec<u8>,
}

/// Both drivers for a fixture, with the fixture's nonces and scripted
/// randomness; returns the Hello records too.
fn fixture_pair(file: &str) -> AnyResult<Pair> {
    let vector = load(file)?;
    let client_bytes = hex_at(&vector, "/inputs/prelude/client_hello_body_hex")?;
    let server_bytes = hex_at(&vector, "/inputs/prelude/server_hello_body_hex")?;
    let client = Hello::decode_client(&client_bytes)?;
    let server = Hello::decode_server(&server_bytes, &client)?;
    let init_static = static_key(&vector, "/inputs/initiator_static_private_hex")?;
    let resp_static = static_key(&vector, "/inputs/responder_static_private_hex")?;
    let (initiator_plan, responder_plan) = match client.mode() {
        SessionMode::Qr => (
            InitiatorPlan::qr(*client.locator(), *resp_static.public_key(), psk(&vector)?),
            ResponderPlan::qr(psk(&vector)?),
        ),
        SessionMode::Contact => (
            InitiatorPlan::contact(
                client.generation(),
                *client.locator(),
                psk(&vector)?.0,
                *resp_static.public_key(),
            ),
            ResponderPlan::contact(
                client.generation(),
                psk(&vector)?.0,
                *init_static.public_key(),
            ),
        ),
        SessionMode::Code => return Err("the XX fixture has a synthetic prologue".into()),
    };
    let (initiator, client_hello) = HandshakeDriver::initiator(
        GATE,
        initiator_plan,
        &init_static,
        *client.client_nonce(),
        Entropy::scripted(vec![
            hex_at(&vector, "/inputs/initiator_ephemeral_private_hex")?,
            hex_at(&vector, "/inputs/initiator_mlkem_keygen_d_then_z_hex")?,
        ]),
        T,
    )?;
    let received = read_client_hello(body(&client_hello)?)?;
    assert_eq!(received, client);
    let (responder, server_hello) = HandshakeDriver::responder(
        GATE,
        received,
        responder_plan,
        &resp_static,
        *server.server_nonce(),
        Entropy::scripted(vec![
            hex_at(&vector, "/inputs/responder_ephemeral_private_hex")?,
            hex_at(&vector, "/inputs/responder_mlkem_encapsulation_m_hex")?,
        ]),
        T,
    )?;
    Ok(Pair {
        initiator,
        responder,
        client_hello,
        server_hello,
    })
}

/// The full prelude path (Hellos, prologue construction, framing, exact
/// sizes) reproduces the committed IK and KK records byte for byte.
#[test]
fn drivers_reproduce_committed_prelude_records() -> TestResult {
    for file in ["handshake-ikpsk2.json", "handshake-kkpsk2.json"] {
        let vector = load(file)?;
        let Pair {
            mut initiator,
            mut responder,
            client_hello,
            server_hello,
        } = fixture_pair(file)?;
        assert_eq!(
            body(&client_hello)?[1..],
            hex_at(&vector, "/inputs/prelude/client_hello_body_hex")?[..]
        );
        assert_eq!(
            body(&server_hello)?[1..],
            hex_at(&vector, "/inputs/prelude/server_hello_body_hex")?[..]
        );
        let first = initiator.receive(body(&server_hello)?, T)?;
        assert_eq!(
            first,
            vec![hex_at(&vector, "/messages/0/prelude_record_hex")?]
        );
        let second = responder.receive(body(&first[0])?, T)?;
        assert_eq!(
            second,
            vec![hex_at(&vector, "/messages/1/prelude_record_hex")?]
        );
        assert!(responder.is_done());
        assert_eq!(
            initiator.receive(body(&second[0])?, T)?,
            Vec::<Vec<u8>>::new()
        );
        assert!(initiator.is_done());
        let initiator = initiator.finish()?;
        let responder = responder.finish()?;
        let hash = hex_array_at::<32>(&vector, "/final_handshake_hash_hex")?;
        assert_eq!(initiator.handshake_hash, hash);
        assert_eq!(responder.handshake_hash, hash);
        assert_eq!(
            initiator.session_id,
            hex_array_at::<32>(&vector, "/session_id_hex")?
        );
        assert_eq!(initiator.role, Role::Initiator);
        assert_eq!(responder.role, Role::Responder);
        assert_eq!(
            initiator.peer_static,
            *responder_public(&vector)?.public_key()
        );
        let messages = json_at(&vector, "/messages")?
            .as_array()
            .map_or(0, Vec::len);
        assert_eq!(messages, 2);
    }
    Ok(())
}

fn responder_public(vector: &Vector) -> AnyResult<NoiseStaticKey> {
    static_key(vector, "/inputs/responder_static_private_hex")
}

fn transcript() -> CodeTranscript {
    CodeTranscript::new(
        [0x31; CODE_OFFER_LEN],
        [0x32; CODE_SHARE_LEN],
        [0x33; CODE_SHARE_LEN],
    )
}

fn code_pair(
    responder_transcript: CodeTranscript,
) -> AnyResult<(HandshakeDriver, HandshakeDriver, Vec<u8>)> {
    let init_static = NoiseStaticKey::generate()?;
    let resp_static = NoiseStaticKey::generate()?;
    let psk = || PairingPsk::from_bytes(Zeroizing::new([0x44; 32]));
    let (initiator, client_hello) = HandshakeDriver::initiator(
        GATE,
        InitiatorPlan::code([0x21; 16], psk(), transcript()),
        &init_static,
        [0x22; 16],
        Entropy::Os,
        T,
    )?;
    let hello = read_client_hello(body(&client_hello)?)?;
    let (responder, server_hello) = HandshakeDriver::responder(
        GATE,
        hello,
        ResponderPlan::code(psk(), responder_transcript),
        &resp_static,
        [0x23; 16],
        Entropy::Os,
        T,
    )?;
    Ok((initiator, responder, server_hello))
}

fn run_to_end(
    initiator: &mut HandshakeDriver,
    responder: &mut HandshakeDriver,
    server_hello: &[u8],
) -> Result<(), SessionError> {
    let mut to_responder = initiator.receive(server_hello, T)?;
    while let Some(record) = to_responder.pop() {
        let to_initiator = responder.receive(&record[2..], T)?;
        for record in to_initiator {
            to_responder.extend(initiator.receive(&record[2..], T)?);
        }
    }
    Ok(())
}

#[test]
fn code_mode_binds_the_code_transcript_into_the_prologue() -> TestResult {
    let (mut initiator, mut responder, server_hello) = code_pair(transcript())?;
    run_to_end(&mut initiator, &mut responder, body(&server_hello)?)?;
    assert!(initiator.is_done() && responder.is_done());
    let (a, b) = (initiator.finish()?, responder.finish()?);
    assert_eq!(a.handshake_hash, b.handshake_hash);
    assert_eq!(a.mode, SessionMode::Code);
    // A different share on one side changes the prologue: XX's first two
    // messages carry no authentication, so the failure shows at message 3.
    let mut other = transcript();
    other.share_b[0] ^= 1;
    let (mut initiator, mut responder, server_hello) = code_pair(other)?;
    assert_eq!(
        run_to_end(&mut initiator, &mut responder, body(&server_hello)?),
        Err(SessionError::Authentication)
    );
    Ok(())
}

#[test]
fn plan_and_hello_must_agree() -> TestResult {
    let key = NoiseStaticKey::generate()?;
    let psk = || PairingPsk::from_bytes(Zeroizing::new([1; 32]));
    let qr = Hello::client(SessionMode::Qr, 0, [1; 16], [2; 16])?;
    let contact = Hello::client(SessionMode::Contact, 5, [1; 16], [2; 16])?;
    let code = Hello::client(SessionMode::Code, 0, [1; 16], [2; 16])?;
    let mismatch = |hello: Hello, plan: ResponderPlan| {
        HandshakeDriver::responder(GATE, hello, plan, &key, [3; 16], Entropy::Os, T).map(|_| ())
    };
    assert_eq!(
        mismatch(qr, ResponderPlan::code(psk(), transcript())),
        Err(SessionError::Usage)
    );
    assert_eq!(
        mismatch(contact, ResponderPlan::contact(6, psk().0, [9; 32])),
        Err(SessionError::GenerationMismatch)
    );
    assert_eq!(
        mismatch(contact, ResponderPlan::qr(psk())),
        Err(SessionError::Usage)
    );
    assert!(mismatch(code, ResponderPlan::code(psk(), transcript())).is_ok());
    assert!(mismatch(qr, ResponderPlan::qr(psk())).is_ok());
    // A zero locator cannot start a session.
    assert_eq!(
        HandshakeDriver::initiator(
            GATE,
            InitiatorPlan::qr([0; 16], [9; 32], psk()),
            &key,
            [2; 16],
            Entropy::Os,
            T
        )
        .map(|_| ())
        .err(),
        Some(SessionError::Usage)
    );
    Ok(())
}

#[test]
fn client_hello_reader_rejects_other_records() -> TestResult {
    let hello = Hello::client(SessionMode::Qr, 0, [1; 16], [2; 16])?.encode();
    let mut record = vec![PreludeKind::ClientHello.to_u8()];
    record.extend_from_slice(&hello);
    assert!(read_client_hello(&record).is_ok());
    record[0] = PreludeKind::ServerHello.to_u8();
    assert_eq!(read_client_hello(&record), Err(state()));
    record[0] = 0x08;
    assert_eq!(read_client_hello(&record), Err(malformed()));
    record[0] = PreludeKind::ClientHello.to_u8();
    record.push(0);
    assert_eq!(read_client_hello(&record), Err(malformed()));
    assert_eq!(read_client_hello(&[]), Err(malformed()));
    Ok(())
}

/// Wrong kinds, replays, reordering, wrong sender, and late records all
/// poison the attempt with a state, malformed, or timeout error.
#[test]
fn out_of_order_and_late_records_poison_the_attempt() -> TestResult {
    let vector = load("handshake-kkpsk2.json")?;
    let message_1 = hex_at(&vector, "/messages/0/prelude_record_hex")?;
    let message_2 = hex_at(&vector, "/messages/1/prelude_record_hex")?;
    // Initiator receiving a Noise record before ServerHello.
    let mut pair = fixture_pair("handshake-kkpsk2.json")?;
    assert_eq!(pair.initiator.receive(body(&message_2)?, T), Err(state()));
    assert_eq!(
        pair.initiator.receive(body(&pair.server_hello)?, T),
        Err(state())
    );
    // Responder receiving ServerHello, a ClientHello, or its own message.
    for record in [&pair.server_hello, &pair.client_hello, &message_2] {
        let mut pair = fixture_pair("handshake-kkpsk2.json")?;
        assert!(pair.responder.receive(body(record)?, T).is_err());
        assert!(pair.responder.receive(body(&message_1)?, T).is_err());
    }
    // Message index from the wrong sender: index 1 arriving at the initiator.
    let mut pair = fixture_pair("handshake-kkpsk2.json")?;
    let first = pair.initiator.receive(body(&pair.server_hello)?, T)?;
    assert_eq!(pair.initiator.receive(body(&first[0])?, T), Err(state()));
    // Replay of message 1 after it was accepted.
    let mut pair = fixture_pair("handshake-kkpsk2.json")?;
    let first = pair.initiator.receive(body(&pair.server_hello)?, T)?;
    pair.responder.receive(body(&first[0])?, T)?;
    assert!(pair.responder.receive(body(&first[0])?, T).is_err());
    assert!(pair.responder.finish().is_err());
    // A record at or after the 30-second deadline.
    let mut pair = fixture_pair("handshake-kkpsk2.json")?;
    assert_eq!(pair.initiator.deadline(), T + HANDSHAKE_TIMEOUT);
    assert_eq!(
        pair.initiator
            .receive(body(&pair.server_hello)?, T + HANDSHAKE_TIMEOUT),
        Err(SessionError::Timeout)
    );
    // A reserved kind or a wrong-size Noise record.
    let mut pair = fixture_pair("handshake-kkpsk2.json")?;
    let mut reserved = body(&pair.server_hello)?.to_vec();
    reserved[0] = 0x00;
    assert_eq!(pair.initiator.receive(&reserved, T), Err(malformed()));
    let mut pair = fixture_pair("handshake-kkpsk2.json")?;
    let mut short = body(&message_1)?.to_vec();
    short.pop();
    assert_eq!(pair.responder.receive(&short, T), Err(malformed()));
    // An unfinished driver cannot produce a Split.
    let pair = fixture_pair("handshake-kkpsk2.json")?;
    assert!(pair.initiator.finish().is_err());
    Ok(())
}

#[test]
fn changed_hello_fields_break_the_transcript() -> TestResult {
    // A responder that saw a different ServerHello nonce (as if a relay
    // rewrote it) derives a different prologue: message 1 fails.
    let vector = load("handshake-kkpsk2.json")?;
    let pair = fixture_pair("handshake-kkpsk2.json")?;
    let mut initiator = pair.initiator;
    let mut server = body(&pair.server_hello)?.to_vec();
    let last = server.len() - 1;
    server[last] ^= 1;
    let first = initiator.receive(&server, T)?;
    let mut responder = fixture_pair("handshake-kkpsk2.json")?.responder;
    assert_eq!(
        responder.receive(body(&first[0])?, T),
        Err(SessionError::Authentication)
    );
    assert_ne!(first[0], hex_at(&vector, "/messages/0/prelude_record_hex")?);
    Ok(())
}

#[test]
fn debug_output_is_structural() -> TestResult {
    let pair = fixture_pair("handshake-ikpsk2.json")?;
    let debug = format!("{:?}", pair.initiator);
    assert!(
        debug.contains("Initiator") && debug.contains("Qr") && debug.contains("AwaitServerHello")
    );
    assert_eq!(format!("{:?}", transcript()), "CodeTranscript { .. }");
    let plan = InitiatorPlan::qr(
        [1; 16],
        [2; 32],
        PairingPsk::from_bytes(Zeroizing::new([5; 32])),
    );
    assert_eq!(plan.mode(), SessionMode::Qr);
    assert!(!format!("{plan:?}").contains("05, 05"));
    assert_eq!(
        ResponderPlan::qr(PairingPsk::from_bytes(Zeroizing::new([5; 32]))).mode(),
        SessionMode::Qr
    );
    Ok(())
}

/// §14.2: plans carry the locator (a pairing ID or contact rendezvous-token
/// prefix); `Debug` must not print it, nor the pinned static key or PSK.
#[test]
fn plans_do_not_print_locators_or_keys() {
    let psk = || PairingPsk::from_bytes(Zeroizing::new([0x44; 32]));
    let transcript = || {
        CodeTranscript::new(
            [0x31; CODE_OFFER_LEN],
            [0x32; CODE_SHARE_LEN],
            [0x33; CODE_SHARE_LEN],
        )
    };
    let debug = [
        format!("{:?}", InitiatorPlan::qr([0xa7; 16], [0xb8; 32], psk())),
        format!("{:?}", InitiatorPlan::code([0xa7; 16], psk(), transcript())),
        format!(
            "{:?}",
            InitiatorPlan::contact(9, [0xa7; 16], Zeroizing::new([0x44; 32]), [0xb8; 32])
        ),
        format!("{:?}", ResponderPlan::qr(psk())),
        format!(
            "{:?}",
            ResponderPlan::contact(9, Zeroizing::new([0x44; 32]), [0xb8; 32])
        ),
    ];
    for debug in debug {
        for needle in ["a7a7", "167", "b8b8", "184", "4444", "68, 68"] {
            assert!(!debug.contains(needle), "{debug}");
        }
        assert!(debug.contains("Plan"), "{debug}");
    }
}
