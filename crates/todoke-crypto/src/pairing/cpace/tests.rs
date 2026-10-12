//! Conformance of the `CPace` backend with draft-irtf-cfrg-cpace-21:
//! the string utilities of Appendix A and the complete ristretto255/SHA-512
//! test vector of Appendix B.3 (generator, both shares, ISK, invalid
//! inputs). The hex values are copied from the draft
//! (<https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-21.txt>).

use pakery_core::crypto::{CpaceGroup, Hash};
use pakery_crypto::{Ristretto255Group, Sha512Hash};
use rand_core::TryRng as _;

use super::backend::{Drawn, Ristretto255Sha512};
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn hex(text: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(text.split_whitespace().collect::<String>())
}

fn array<const N: usize>(text: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
    Ok(<[u8; N]>::try_from(hex(text)?.as_slice())?)
}

const PRS: &[u8] = b"Password";
const CI: &str = "0b415f696e69746961746f720b425f726573706f6e646572";
const SID: &str = "7e4b4791d6a8ef019b936c79fb7f2c57";
const GENERATOR_STRING: &str = "
    11435061636552697374726574746f3235350850617373776f726464
    00000000000000000000000000000000000000000000000000000000
    00000000000000000000000000000000000000000000000000000000
    00000000000000000000000000000000000000000000000000000000
    00000000000000000000000000000000180b415f696e69746961746f
    720b425f726573706f6e646572107e4b4791d6a8ef019b936c79fb7f
    2c57";
const GENERATOR_HASH: &str = "
    da6d3ddc8802fca9058755ffd3ebde08a9c2c74945901a258482a288
    b6663af06bf645c93cd1c51512307199c80e84908916d983b34af772
    05f90851a657ee27";
const GENERATOR: &str = "222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56";
const YA_SCALAR: &str = "da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08";
const YA: &str = "d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157";
const YB_SCALAR: &str = "d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d";
const YB: &str = "3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f7258";
const K: &str = "80b69a8a76457ab6a4d7f887a4bf6b55a2f80ac19c333f917a05fc9887c8b40f";
const TRANSCRIPT_IR: &str = "
    20d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0e
    ec482b915703414461203ea7e0b19560d7c0b0f5734f63b955286dfa
    8232b5ebe63324e2d9e7433f725803414462";
const ISK_IR: &str = "
    b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dc
    ae7b35cd2b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c
    3fa2068af7900447";
const SCALAR_S: &str = "7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05";
const POINT_X: &str = "2c3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c";
const S_TIMES_X: &str = "7c13645fe790a468f62c39beb7388e541d8405d1ade69d1778c5fe3e7f6b600e";
const INVALID_Y1: &str = "2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c";

/// Scripted randomness that makes the backend's scalar equal `scalar`:
/// pakery reduces 64 bytes modulo the group order, and a 252-bit
/// little-endian scalar followed by zeros reduces to itself.
fn scalar_entropy(scalar: &str) -> Result<Entropy, Box<dyn std::error::Error>> {
    let mut seed = hex(scalar)?;
    seed.resize(SCALAR_SEED_LEN, 0);
    Ok(Entropy::scripted(vec![seed]))
}

#[test]
fn appendix_a_string_utilities() -> TestResult {
    use pakery_core::encoding::{lv_cat, prepend_len};
    assert_eq!(prepend_len(b""), hex("00")?);
    assert_eq!(prepend_len(b"1234"), hex("0431323334")?);
    let bytes127: Vec<u8> = (0..127).collect();
    assert_eq!(prepend_len(&bytes127)[0], 0x7f);
    let bytes128: Vec<u8> = (0..128).collect();
    assert_eq!(prepend_len(&bytes128)[..2], [0x80, 0x01]);
    assert_eq!(
        lv_cat(&[b"1234", b"5", b"", b"678"]),
        hex("043132333401350003363738")?
    );
    assert_eq!(
        pakery_cpace::transcript::transcript_ir(b"123", b"PartyA", b"234", b"PartyB"),
        hex("03313233065061727479410332333406506172747942")?
    );
    assert_eq!(
        pakery_cpace::transcript::transcript_ir(b"3456", b"PartyA", b"2345", b"PartyB"),
        hex("043334353606506172747941043233343506506172747942")?
    );
    Ok(())
}

#[test]
fn appendix_b3_generator() -> TestResult {
    let ci = hex(CI)?;
    let sid = hex(SID)?;
    let generator_string =
        pakery_cpace::generator::generator_string::<Ristretto255Sha512>(PRS, &ci, &sid);
    assert_eq!(generator_string, hex(GENERATOR_STRING)?);
    assert_eq!(Sha512Hash::digest(&generator_string), hex(GENERATOR_HASH)?);
    let generator =
        pakery_cpace::generator::calculate_generator::<Ristretto255Sha512>(PRS, &ci, &sid)
            .map_err(|error| format!("{error:?}"))?;
    assert_eq!(generator.to_bytes(), hex(GENERATOR)?);
    Ok(())
}

#[test]
fn appendix_b3_shares_and_isk_through_the_backend() -> TestResult {
    let ci = hex(CI)?;
    let sid = hex(SID)?;
    let (ya, initiator) = start(PRS, &ci, &sid, b"ADa", &scalar_entropy(YA_SCALAR)?)?;
    assert_eq!(ya, array::<32>(YA)?);
    let (yb, responder_isk) = respond(
        &ya,
        PRS,
        &ci,
        &sid,
        b"ADa",
        b"ADb",
        &scalar_entropy(YB_SCALAR)?,
    )?;
    assert_eq!(yb, array::<32>(YB)?);
    let initiator_isk = initiator.finish(&yb, b"ADb")?;
    assert_eq!(initiator_isk.as_bytes(), &array::<64>(ISK_IR)?);
    assert_eq!(responder_isk.as_bytes(), &array::<64>(ISK_IR)?);
    // K and the transcript, recomputed from the published values.
    let mut ya_scalar = hex(YA_SCALAR)?;
    ya_scalar.resize(64, 0);
    let pake = |error: pakery_core::PakeError| format!("{error:?}");
    let k = Ristretto255Group::from_bytes(&yb)
        .map_err(pake)?
        .scalar_mul(&Ristretto255Group::scalar_from_wide_bytes(&ya_scalar).map_err(pake)?);
    assert_eq!(k.to_bytes(), hex(K)?);
    assert_eq!(
        pakery_cpace::transcript::transcript_ir(&ya, b"ADa", &yb, b"ADb"),
        hex(TRANSCRIPT_IR)?
    );
    Ok(())
}

#[test]
fn appendix_b3_scalar_mult_and_invalid_inputs() -> TestResult {
    let mut s = hex(SCALAR_S)?;
    s.resize(64, 0);
    let pake = |error: pakery_core::PakeError| format!("{error:?}");
    let scalar = Ristretto255Group::scalar_from_wide_bytes(&s).map_err(pake)?;
    let x = Ristretto255Group::from_bytes(&hex(POINT_X)?).map_err(pake)?;
    assert_eq!(x.scalar_mul(&scalar).to_bytes(), hex(S_TIMES_X)?);
    // Y_i1 does not decode; Y_i2 is the neutral element. Both abort, on
    // either side.
    let ci = hex(CI)?;
    let sid = hex(SID)?;
    for invalid in [array::<32>(INVALID_Y1)?, [0; 32]] {
        assert_eq!(
            respond(
                &invalid,
                PRS,
                &ci,
                &sid,
                b"ADa",
                b"ADb",
                &scalar_entropy(YB_SCALAR)?
            )
            .err(),
            Some(CpaceError::Abort)
        );
        let (_, initiator) = start(PRS, &ci, &sid, b"ADa", &scalar_entropy(YA_SCALAR)?)?;
        assert_eq!(
            initiator.finish(&invalid, b"ADb").err(),
            Some(CpaceError::Abort)
        );
    }
    Ok(())
}

/// Non-canonical encodings (RFC 9496 §4.3.1): a field element at or above
/// p, and a negative (odd) one. Both must abort, never be reduced.
#[test]
fn non_canonical_shares_abort() -> TestResult {
    let ci = hex(CI)?;
    let sid = hex(SID)?;
    let canonical = array::<32>(YA)?;
    let mut at_least_p = [0xff; 32];
    at_least_p[31] = 0x7f;
    let mut negative = canonical;
    negative[0] |= 1;
    let mut high_bit = canonical;
    high_bit[31] |= 0x80;
    for share in [at_least_p, negative, high_bit] {
        assert_eq!(
            respond(
                &share,
                PRS,
                &ci,
                &sid,
                b"ADa",
                b"ADb",
                &scalar_entropy(YB_SCALAR)?
            )
            .err(),
            Some(CpaceError::Abort)
        );
    }
    Ok(())
}

#[test]
fn every_input_changes_the_isk() -> TestResult {
    let ci = hex(CI)?;
    let sid = hex(SID)?;
    let run = |prs: &[u8],
               ci_b: &[u8],
               sid_b: &[u8],
               ad_a_b: &[u8],
               ad_b_a: &[u8]|
     -> Result<bool, Box<dyn std::error::Error>> {
        let (ya, initiator) = start(PRS, &ci, &sid, b"ADa", &Entropy::Os)?;
        let (yb, responder) = respond(&ya, prs, ci_b, sid_b, ad_a_b, b"ADb", &Entropy::Os)?;
        let isk = initiator.finish(&yb, ad_b_a)?;
        Ok(isk.as_bytes() == responder.as_bytes())
    };
    assert!(run(PRS, &ci, &sid, b"ADa", b"ADb")?);
    assert!(!run(b"Passwore", &ci, &sid, b"ADa", b"ADb")?);
    assert!(!run(PRS, b"other", &sid, b"ADa", b"ADb")?);
    assert!(!run(PRS, &ci, &[0; 16], b"ADa", b"ADb")?);
    assert!(!run(PRS, &ci, &sid, b"ADx", b"ADb")?);
    assert!(!run(PRS, &ci, &sid, b"ADa", b"ADx")?);
    Ok(())
}

#[test]
fn randomness_failures_and_overdraws_fail_closed() -> TestResult {
    let empty = Entropy::scripted(Vec::new());
    assert_eq!(
        start(PRS, b"", b"", b"", &empty).err(),
        Some(CpaceError::Random)
    );
    assert_eq!(
        respond(&array::<32>(YA)?, PRS, b"", b"", b"", b"", &empty).err(),
        Some(CpaceError::Random)
    );
    let mut drawn = Drawn::new(&Entropy::Os)?;
    let mut first = [0; 64];
    drawn.try_fill_bytes(&mut first)?;
    assert!(!drawn.overdrawn);
    assert_ne!(first, [0; 64]);
    let mut more = [0xaa; 8];
    drawn.try_fill_bytes(&mut more)?;
    assert!(drawn.overdrawn);
    assert_eq!(more, [0; 8]);
    let mut words = Drawn::new(&Entropy::Os)?;
    let _ = words.try_next_u32()?;
    let _ = words.try_next_u64()?;
    assert!(!words.overdrawn);
    Ok(())
}

#[test]
fn debug_is_redacted() -> TestResult {
    let (_, initiator) = start(PRS, b"", b"", b"", &Entropy::Os)?;
    assert_eq!(format!("{initiator:?}"), "cpace::Initiator { .. }");
    let (_, isk) = respond(&array::<32>(YA)?, PRS, b"", b"", b"", b"", &Entropy::Os)?;
    assert_eq!(format!("{isk:?}"), "Isk([REDACTED])");
    Ok(())
}
