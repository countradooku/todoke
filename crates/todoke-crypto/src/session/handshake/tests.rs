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

/// The KK fixture's pair generation (public fixture state; no Hello carries
/// it since §16 O12).
const FIXTURE_GENERATION: u64 = 7;

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
                FIXTURE_GENERATION,
                *client.locator(),
                psk(&vector)?.0,
                *resp_static.public_key(),
            ),
            ResponderPlan::contact(
                FIXTURE_GENERATION,
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
        // The generation comes from the plans: no Hello carries it.
        let generation = if file.contains("kk") {
            FIXTURE_GENERATION
        } else {
            0
        };
        assert_eq!(
            (initiator.generation, responder.generation),
            (generation, generation)
        );
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
        InitiatorPlan::code_with_psk([0x21; 16], psk(), transcript()),
        &init_static,
        [0x22; 16],
        Entropy::Os,
        T,
    )?;
    let hello = read_client_hello(body(&client_hello)?)?;
    let (responder, server_hello) = HandshakeDriver::responder(
        GATE,
        hello,
        ResponderPlan::code_with_psk(psk(), responder_transcript),
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

/// §3.2/§4.2.6: the code-mode prologue is exactly
/// `"todoke/v1/noise-prologue\0" || CodeOfferRequest (10) || CodeOffer (34)
/// || ClientHello (58) || ServerHello (58) || CodeShareA (49) || CodeShareB
/// (49)`, written out here from the spec sizes.
#[test]
fn code_prologue_is_the_spec_concatenation() -> TestResult {
    let (mut initiator, mut responder, server_hello) = code_pair(transcript())?;
    let server = Hello::decode_server(&body(&server_hello)?[1..], &initiator.client)?;
    let mut expected = b"todoke/v1/noise-prologue\x00".to_vec();
    expected.extend_from_slice(&[0x31; 10 + 34]);
    expected.extend_from_slice(&initiator.client.encode());
    expected.extend_from_slice(&server.encode());
    expected.extend_from_slice(&[0x32; 49]);
    expected.extend_from_slice(&[0x33; 49]);
    assert_eq!(expected.len(), 25 + 44 + 58 + 58 + 49 + 49);
    assert_eq!(initiator.prologue(&server)?, expected);
    assert_eq!(responder.prologue(&server)?, expected);
    run_to_end(&mut initiator, &mut responder, body(&server_hello)?)?;
    let split = initiator.finish()?;
    assert_eq!(
        format!("{split:?}"),
        "Split { role: Initiator, mode: Code, generation: 0, .. }"
    );
    Ok(())
}

#[test]
fn plan_and_hello_must_agree() -> TestResult {
    let key = NoiseStaticKey::generate()?;
    let psk = || PairingPsk::from_bytes(Zeroizing::new([1; 32]));
    let qr = Hello::client(SessionMode::Qr, [1; 16], [2; 16])?;
    let contact = Hello::client(SessionMode::Contact, [1; 16], [2; 16])?;
    let code = Hello::client(SessionMode::Code, [1; 16], [2; 16])?;
    let mismatch = |hello: Hello, plan: ResponderPlan| {
        HandshakeDriver::responder(GATE, hello, plan, &key, [3; 16], Entropy::Os, T).map(|_| ())
    };
    assert_eq!(
        mismatch(qr, ResponderPlan::code_with_psk(psk(), transcript())),
        Err(SessionError::Usage)
    );
    // Any stored generation answers a contact Hello, which names none.
    assert!(mismatch(contact, ResponderPlan::contact(6, psk().0, [9; 32])).is_ok());
    assert_eq!(
        mismatch(contact, ResponderPlan::qr(psk())),
        Err(SessionError::Usage)
    );
    assert!(mismatch(code, ResponderPlan::code_with_psk(psk(), transcript())).is_ok());
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
    let hello = Hello::client(SessionMode::Qr, [1; 16], [2; 16])?.encode();
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

/// Two sides at different generations hold different PSKs: the KK
/// handshake fails when the PSK is mixed in, at message 2, with the
/// generic authentication error. Nothing on the wire says why (§4.1).
#[test]
fn divergent_generations_fail_authentication() -> TestResult {
    let (init_static, resp_static) = (NoiseStaticKey::generate()?, NoiseStaticKey::generate()?);
    let (mut initiator, client_hello) = HandshakeDriver::initiator(
        GATE,
        InitiatorPlan::contact(
            7,
            [0x51; 16],
            Zeroizing::new([0x61; 32]),
            *resp_static.public_key(),
        ),
        &init_static,
        [0x52; 16],
        Entropy::Os,
        T,
    )?;
    let hello = read_client_hello(body(&client_hello)?)?;
    let (mut responder, server_hello) = HandshakeDriver::responder(
        GATE,
        hello,
        ResponderPlan::contact(8, Zeroizing::new([0x62; 32]), *init_static.public_key()),
        &resp_static,
        [0x53; 16],
        Entropy::Os,
        T,
    )?;
    assert_eq!(
        run_to_end(&mut initiator, &mut responder, body(&server_hello)?),
        Err(SessionError::Authentication)
    );
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
        format!(
            "{:?}",
            InitiatorPlan::code_with_psk([0xa7; 16], psk(), transcript())
        ),
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

/// The public inputs of one real code-pairing attempt (§3.2).
struct CodeInputs {
    code_offer: [u8; CODE_OFFER_LEN],
    pairing_id: [u8; 16],
    client_nonce: [u8; 16],
    server_nonce: [u8; 16],
}

impl CodeInputs {
    fn new() -> AnyResult<Self> {
        let pairing_id = [0xa1; 16];
        let request = todoke_proto::pairing::CodeOfferRequest::new([0x5e; 8])?;
        let offer = todoke_proto::pairing::CodeOffer::new(
            &request,
            pairing_id,
            todoke_proto::time::UnixTime::new(1_760_000_300).ok_or("time")?,
        )?;
        let mut code_offer = [0; CODE_OFFER_LEN];
        code_offer[..10].copy_from_slice(&request.encode());
        code_offer[10..].copy_from_slice(&offer.encode());
        Ok(Self {
            code_offer,
            pairing_id,
            client_nonce: [0xc1; 16],
            server_nonce: [0x5c; 16],
        })
    }

    /// Both drivers of a real code-pairing attempt with the code
    /// `0123456789`, each drawing its `CPace` scalar from `seed_a` /
    /// `seed_b` (the initiator also gets its two Noise draws), and the
    /// `ServerHello` record.
    fn drivers(
        &self,
        seed_a: [u8; 64],
        seed_b: [u8; 64],
    ) -> AnyResult<(HandshakeDriver, HandshakeDriver, Vec<u8>)> {
        let gate = crate::pairing::UnauditedCodePairing::acknowledge_not_production_ready();
        let code = HumanCode::parse("0123456789")?;
        let (initiator, client_record) = HandshakeDriver::initiator(
            GATE,
            InitiatorPlan::code_pairing(gate, self.pairing_id, code.clone(), self.code_offer),
            &NoiseStaticKey::generate()?,
            self.client_nonce,
            Entropy::scripted(vec![seed_a.to_vec(), vec![0x61; 32], vec![0x63; 64]]),
            T,
        )?;
        let client = read_client_hello(body(&client_record)?)?;
        let mut plan = ResponderPlan::code_pairing(gate, code);
        plan.bind_code_offer(self.code_offer)?;
        let (responder, server_record) = HandshakeDriver::responder(
            GATE,
            client,
            plan,
            &NoiseStaticKey::generate()?,
            self.server_nonce,
            Entropy::scripted(vec![seed_b.to_vec()]),
            T,
        )?;
        Ok((initiator, responder, server_record))
    }
}

/// HKDF-SHA-256 with one output block, written out with `RustCrypto`'s
/// HMAC (RFC 5869), independently of the crate's KDF.
fn hkdf_one_block(salt: &[u8], ikm: &[u8], info: &[u8]) -> AnyResult<[u8; 32]> {
    use hmac::{Hmac, KeyInit, Mac};
    let mut extract = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(salt)?;
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();
    let mut expand = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&prk)?;
    expand.update(info);
    expand.update(&[1]);
    Ok(expand.finalize().into_bytes().into())
}

/// §3.2 through the drivers: both sides give `CPace` exactly the spec's
/// inputs and derive exactly the spec's PSK. Everything expected here is
/// written out from the spec, not taken from `pairing::transcript`: `CI =
/// "todoke/v1/cpace-ci\0" || code_offer || ClientHello || ServerHello`,
/// `sid = client_nonce || server_nonce`, `ADa`/`ADb`, the 49-byte share
/// layouts, and `psk = HKDF(B3(pre_noise), ISK, "todoke/v1/cpace-psk\0",
/// 32)`. The `CPace` computation itself is pinned to the draft's vectors
/// in `pairing::cpace::tests`; this pins what the session feeds it.
#[test]
fn code_pairing_feeds_cpace_exactly_the_spec_inputs() -> TestResult {
    let inputs = CodeInputs::new()?;
    let (seed_a, seed_b) = ([0x0a; 64], [0x0b; 64]);
    let (mut initiator, mut responder, server_record) = inputs.drivers(seed_a, seed_b)?;
    let server = Hello::decode_server(&body(&server_record)?[1..], &initiator.client)?;
    let share_a = initiator.receive(body(&server_record)?, T)?;
    let [share_a] = share_a.as_slice() else {
        return Err("one CodeShareA record".into());
    };
    let share_b = responder.receive(body(share_a)?, T)?;
    let [share_b] = share_b.as_slice() else {
        return Err("one CodeShareB record".into());
    };

    let mut ci = b"todoke/v1/cpace-ci\x00".to_vec();
    ci.extend_from_slice(&inputs.code_offer);
    ci.extend_from_slice(&initiator.client.encode());
    ci.extend_from_slice(&server.encode());
    assert_eq!(ci.len(), 19 + 44 + 58 + 58);
    let mut sid = inputs.client_nonce.to_vec();
    sid.extend_from_slice(&inputs.server_nonce);
    let (ad_a, ad_b) = (b"todoke/v1/cpace-a\x00", b"todoke/v1/cpace-b\x00");
    let password = b"0123456789";
    let (ya, _) = crate::pairing::cpace::start(
        password,
        &ci,
        &sid,
        ad_a,
        &Entropy::scripted(vec![seed_a.to_vec()]),
    )?;
    let (yb, isk) = crate::pairing::cpace::respond(
        &ya,
        password,
        &ci,
        &sid,
        ad_a,
        ad_b,
        &Entropy::scripted(vec![seed_b.to_vec()]),
    )?;
    // length (2) || kind || pairing_id || role || element
    let mut expected_a = vec![0, 50, 0x03];
    expected_a.extend_from_slice(&inputs.pairing_id);
    expected_a.push(0);
    expected_a.extend_from_slice(&ya);
    assert_eq!(share_a, &expected_a);
    let mut expected_b = vec![0, 50, 0x04];
    expected_b.extend_from_slice(&inputs.pairing_id);
    expected_b.push(1);
    expected_b.extend_from_slice(&yb);
    assert_eq!(share_b, &expected_b);

    let mut pre_noise = inputs.code_offer.to_vec();
    pre_noise.extend_from_slice(&initiator.client.encode());
    pre_noise.extend_from_slice(&server.encode());
    pre_noise.extend_from_slice(&expected_a[3..]);
    pre_noise.extend_from_slice(&expected_b[3..]);
    assert_eq!(pre_noise.len(), 44 + 58 + 58 + 49 + 49);
    let psk = hkdf_one_block(
        blake3::hash(&pre_noise).as_bytes(),
        isk.as_bytes(),
        b"todoke/v1/cpace-psk\x00",
    )?;
    assert_eq!(responder.psk.as_deref(), Some(&psk));
    // The initiator derives the same PSK from share B and starts Noise.
    let first = initiator.receive(body(share_b)?, T)?;
    assert_eq!(first.len(), 1);
    assert_eq!(initiator.psk.as_deref(), Some(&psk));
    let mut prologue = b"todoke/v1/noise-prologue\x00".to_vec();
    prologue.extend_from_slice(&pre_noise);
    assert_eq!(initiator.prologue(&server)?, prologue);
    assert_eq!(responder.prologue(&server)?, prologue);
    Ok(())
}

/// §3.2: a share whose role byte does not match its record kind aborts,
/// on either side, even with a valid element for the right offer.
#[test]
fn a_share_with_the_wrong_role_byte_aborts() -> TestResult {
    let inputs = CodeInputs::new()?;
    // The Ristretto255 basepoint, a valid element (RFC 9496 §4.4).
    let element: [u8; 32] =
        hex::decode("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76")?
            .try_into()
            .map_err(|_| "element")?;
    let share = |kind: PreludeKind, role: CodeRole| -> AnyResult<Vec<u8>> {
        let body = CodeShare::new(inputs.pairing_id, role, element)?.encode();
        let mut record = vec![kind.to_u8()];
        record.extend_from_slice(&body);
        Ok(record)
    };
    // The responder: kind CodeShareA, role B.
    let (_, mut responder, _) = inputs.drivers([0x0a; 64], [0x0b; 64])?;
    assert_eq!(
        responder.receive(&share(PreludeKind::CodeShareA, CodeRole::B)?, T),
        Err(state())
    );
    assert!(responder.psk.is_none());
    // The initiator, after sending share A: kind CodeShareB, role A.
    let (mut initiator, _, server_record) = inputs.drivers([0x0a; 64], [0x0b; 64])?;
    initiator.receive(body(&server_record)?, T)?;
    assert_eq!(
        initiator.receive(&share(PreludeKind::CodeShareB, CodeRole::A)?, T),
        Err(state())
    );
    assert!(initiator.psk.is_none());
    // The matching role byte is accepted on both sides.
    let (mut initiator, mut responder, server_record) = inputs.drivers([0x0a; 64], [0x0b; 64])?;
    initiator.receive(body(&server_record)?, T)?;
    let reply = responder.receive(&share(PreludeKind::CodeShareA, CodeRole::A)?, T)?;
    assert_eq!(reply.len(), 1);
    assert_eq!(
        initiator
            .receive(&share(PreludeKind::CodeShareB, CodeRole::B)?, T)
            .map(|records| records.len()),
        Ok(1)
    );
    Ok(())
}

/// Randomness that fails while `CPace` draws its scalar ends the attempt
/// with a local randomness error on either side, before any share or PSK.
#[test]
fn cpace_randomness_failure_fails_closed() -> TestResult {
    let inputs = CodeInputs::new()?;
    let gate = crate::pairing::UnauditedCodePairing::acknowledge_not_production_ready();
    let code = HumanCode::parse("0123456789")?;
    let (mut initiator, client_record) = HandshakeDriver::initiator(
        GATE,
        InitiatorPlan::code_pairing(gate, inputs.pairing_id, code.clone(), inputs.code_offer),
        &NoiseStaticKey::generate()?,
        inputs.client_nonce,
        Entropy::scripted(Vec::new()),
        T,
    )?;
    let client = read_client_hello(body(&client_record)?)?;
    let mut plan = ResponderPlan::code_pairing(gate, code);
    plan.bind_code_offer(inputs.code_offer)?;
    let (mut responder, server_record) = HandshakeDriver::responder(
        GATE,
        client,
        plan,
        &NoiseStaticKey::generate()?,
        inputs.server_nonce,
        Entropy::scripted(Vec::new()),
        T,
    )?;
    assert_eq!(
        initiator.receive(body(&server_record)?, T),
        Err(SessionError::Random)
    );
    assert!(initiator.psk.is_none());
    // A valid share A for the responder, from a working initiator.
    let (mut working, _, server_record) = inputs.drivers([0x0a; 64], [0x0b; 64])?;
    let share_a = working.receive(body(&server_record)?, T)?;
    let [share_a] = share_a.as_slice() else {
        return Err("one CodeShareA record".into());
    };
    assert_eq!(
        responder.receive(body(share_a)?, T),
        Err(SessionError::Random)
    );
    assert!(responder.psk.is_none());
    Ok(())
}
