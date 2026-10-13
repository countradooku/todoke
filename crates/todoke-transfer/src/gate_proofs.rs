//! Proof harnesses for the receiver's consent invariant (§7.2): no key or
//! content is admitted before a valid Accept opened the gate, none for a
//! file outside the selection or under another Accept hash, no content
//! before that file's key, and nothing after the authorization closed.
//!
//! Each harness body is written once against [`Nondet`], a source of
//! nondeterministic choices:
//!
//! - under `cfg(kani)`, [`kani_harnesses`] feed it `kani::any()`, so
//!   `cargo kani -p todoke-transfer` checks every choice (CI job `kani`);
//! - under `cfg(test)`, the unit tests enumerate every choice sequence of
//!   the same bodies exhaustively for short runs, so the harness logic is
//!   also exercised locally without the model checker.
//!
//! The proof stand-in [`StubProof`] has an arbitrary Accept hash (from a
//! two-value domain) and an arbitrary selection; the engine's real proof is
//! a `VerifiedAccept`, whose only constructor verifies the signed record.
//!
//! These harnesses check the gate's admission rules only. That the engine
//! passes every `FileKey` and `Chunk` through the gate is covered by the
//! engine tests (`tests::basic`, `tests::adversarial`), not by them.

use crate::gate::{AcceptProof, ConsentGate, GateRefusal};

/// File IDs the harnesses use: 0..FILES.
const FILES: u8 = 3;

/// A source of choices: `choose(n)` returns any value in `0..n`.
pub(crate) trait Nondet {
    fn choose(&mut self, n: u8) -> u8;
}

/// An accept proof with an arbitrary hash and selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StubProof {
    hash: [u8; 32],
    selected: [bool; FILES as usize],
}

impl StubProof {
    fn any<N: Nondet>(n: &mut N) -> Self {
        let mut selected = [false; FILES as usize];
        for slot in &mut selected {
            *slot = n.choose(2) == 1;
        }
        Self {
            hash: hash(n.choose(2)),
            selected,
        }
    }
}

impl AcceptProof for StubProof {
    fn accept_hash(&self) -> &[u8; 32] {
        &self.hash
    }

    fn is_selected(&self, file_id: u32) -> bool {
        usize::try_from(file_id)
            .ok()
            .and_then(|index| self.selected.get(index))
            .copied()
            .unwrap_or(false)
    }
}

const fn hash(choice: u8) -> [u8; 32] {
    [choice; 32]
}

/// What the gate has been told, tracked independently of it.
struct Ghost {
    proof: Option<StubProof>,
    closed: bool,
    keyed: [bool; FILES as usize],
}

impl Ghost {
    /// Whether the gate must admit a key for `file` under `accept_hash`.
    fn may_key(&self, accept_hash: &[u8; 32], file: u32) -> bool {
        !self.closed
            && self
                .proof
                .is_some_and(|proof| proof.is_selected(file) && proof.hash == *accept_hash)
    }

    fn keyed(&self, file: u32) -> bool {
        usize::try_from(file)
            .ok()
            .and_then(|index| self.keyed.get(index))
            .copied()
            .unwrap_or(false)
    }
}

/// Any sequence of `steps` operations — open with any proof, close, admit
/// a key or content for any file under either hash, query — keeps the gate
/// in agreement with the ghost model: an admission succeeds exactly when
/// consent covers it.
pub(crate) fn consent_invariant<N: Nondet>(n: &mut N, steps: usize) {
    let mut gate = ConsentGate::<StubProof>::new();
    let mut ghost = Ghost {
        proof: None,
        closed: false,
        keyed: [false; FILES as usize],
    };
    for _ in 0..steps {
        match n.choose(5) {
            0 => {
                let proof = StubProof::any(n);
                let opened = gate.open(proof).is_ok();
                assert_eq!(opened, ghost.proof.is_none() && !ghost.closed);
                if opened {
                    ghost.proof = Some(proof);
                }
            }
            1 => {
                let returned = gate.close();
                assert_eq!(returned.is_some(), ghost.proof.is_some() && !ghost.closed);
                ghost.closed = true;
            }
            2 => {
                let file = u32::from(n.choose(FILES));
                let accept_hash = hash(n.choose(2));
                let result = gate.admit_key(&accept_hash, file);
                assert_eq!(result.is_ok(), ghost.may_key(&accept_hash, file));
                if let Ok(new) = result {
                    assert_eq!(new, !ghost.keyed(file));
                    if let Some(slot) = ghost.keyed.get_mut(usize::from(n_index(file))) {
                        *slot = true;
                    }
                }
            }
            3 => {
                let file = u32::from(n.choose(FILES));
                let accept_hash = hash(n.choose(2));
                let result = gate.admit_content(&accept_hash, file);
                let expected = ghost.may_key(&accept_hash, file) && ghost.keyed(file);
                assert_eq!(result.is_ok(), expected);
                if !ghost.closed && ghost.proof.is_none() {
                    assert_eq!(result, Err(GateRefusal::NotAccepted));
                }
            }
            _ => {
                let open = ghost.proof.is_some() && !ghost.closed;
                assert_eq!(gate.is_open(), open);
                assert_eq!(gate.proof().is_some(), open);
            }
        }
    }
}

fn n_index(file: u32) -> u8 {
    u8::try_from(file).unwrap_or(u8::MAX)
}

/// Before any Accept, nothing is admitted, whatever the record names.
pub(crate) fn nothing_before_accept<N: Nondet>(n: &mut N) {
    let mut gate = ConsentGate::<StubProof>::new();
    let file = u32::from(n.choose(FILES));
    let accept_hash = hash(n.choose(2));
    assert_eq!(
        gate.admit_content(&accept_hash, file),
        Err(GateRefusal::NotAccepted)
    );
    assert_eq!(
        gate.admit_key(&accept_hash, file),
        Err(GateRefusal::NotAccepted)
    );
    assert!(!gate.is_keyed(file));
}

/// After the gate closes, nothing is admitted and it cannot reopen.
pub(crate) fn nothing_after_close<N: Nondet>(n: &mut N) {
    let mut gate = ConsentGate::<StubProof>::new();
    let proof = StubProof::any(n);
    assert!(gate.open(proof).is_ok());
    let file = u32::from(n.choose(FILES));
    let accept_hash = hash(n.choose(2));
    let _ = gate.admit_key(&accept_hash, file);
    assert!(gate.close().is_some());
    assert_eq!(gate.admit_key(&accept_hash, file), Err(GateRefusal::Closed));
    assert_eq!(
        gate.admit_content(&accept_hash, file),
        Err(GateRefusal::Closed)
    );
    assert_eq!(gate.open(StubProof::any(n)), Err(GateRefusal::Closed));
    assert!(!gate.is_open());
}

/// Admitted content is always for a selected, keyed file under the
/// proof's hash; a second Accept never replaces the first.
pub(crate) fn content_only_within_selection<N: Nondet>(n: &mut N) {
    let mut gate = ConsentGate::<StubProof>::new();
    let proof = StubProof::any(n);
    assert!(gate.open(proof).is_ok());
    assert_eq!(gate.open(StubProof::any(n)), Err(GateRefusal::AlreadyOpen));
    let keyed_file = u32::from(n.choose(FILES));
    let key_hash = hash(n.choose(2));
    let keyed = gate.admit_key(&key_hash, keyed_file).is_ok();
    let file = u32::from(n.choose(FILES));
    let accept_hash = hash(n.choose(2));
    if gate.admit_content(&accept_hash, file).is_ok() {
        assert!(proof.is_selected(file));
        assert_eq!(accept_hash, proof.hash);
        assert!(keyed && keyed_file == file);
    }
    if !proof.is_selected(file) {
        assert_eq!(
            gate.admit_content(&accept_hash, file),
            Err(GateRefusal::Unselected)
        );
    }
}

#[cfg(kani)]
mod kani_harnesses {
    //! `cargo kani -p todoke-transfer` entry points.

    struct Any;

    impl super::Nondet for Any {
        fn choose(&mut self, n: u8) -> u8 {
            let value: u8 = kani::any();
            kani::assume(value < n);
            value
        }
    }

    /// Every sequence of up to two gate operations. Longer sequences (four
    /// and five steps were tried) exhausted the 16 GB CI runner's memory
    /// while CBMC built the formula: each step branches over five operation
    /// kinds. Every choice here comes from a small finite domain (30 per
    /// step), so longer sequences are checked exhaustively instead:
    /// `tests::consent_gate_invariant_exhaustive` (four steps, every test run)
    /// and `tests::consent_gate_invariant_exhaustive_six_steps` (six steps,
    /// CI, release).
    #[kani::proof]
    #[kani::unwind(34)]
    fn consent_gate_invariant() {
        super::consent_invariant(&mut Any, 2);
    }

    #[kani::proof]
    #[kani::unwind(34)]
    fn no_key_or_content_before_accept() {
        super::nothing_before_accept(&mut Any);
    }

    #[kani::proof]
    #[kani::unwind(34)]
    fn no_key_or_content_after_close() {
        super::nothing_after_close(&mut Any);
    }

    #[kani::proof]
    #[kani::unwind(34)]
    fn content_only_for_selected_keyed_files() {
        super::content_only_within_selection(&mut Any);
    }
}

#[cfg(test)]
mod tests {
    //! Exhaustive runs of the harness bodies over every choice sequence.

    use super::Nondet;

    /// Replays a recorded choice prefix and extends it with zeros; after a
    /// run, [`Self::advance`] moves to the next sequence (depth first).
    struct Explorer {
        trail: Vec<(u8, u8)>,
        position: usize,
    }

    impl Nondet for Explorer {
        fn choose(&mut self, n: u8) -> u8 {
            let value = if let Some(&(value, _)) = self.trail.get(self.position) {
                value
            } else {
                self.trail.push((0, n));
                0
            };
            self.position += 1;
            value
        }
    }

    impl Explorer {
        fn advance(&mut self) -> bool {
            self.position = 0;
            while let Some((value, n)) = self.trail.pop() {
                if value + 1 < n {
                    self.trail.push((value + 1, n));
                    return true;
                }
            }
            false
        }
    }

    fn exhaust(mut body: impl FnMut(&mut Explorer)) -> usize {
        let mut explorer = Explorer {
            trail: Vec::new(),
            position: 0,
        };
        let mut runs = 0;
        loop {
            body(&mut explorer);
            runs += 1;
            if !explorer.advance() {
                return runs;
            }
        }
    }

    #[test]
    fn consent_gate_invariant_exhaustive() {
        // Every sequence of four operations: 810000 runs.
        let runs = exhaust(|n| super::consent_invariant(n, 4));
        assert_eq!(runs, 30_usize.pow(4));
    }

    /// Every sequence of six operations: 729,000,000 runs. Each step has 30
    /// choices (open with any of 16 proofs, close, a key or content for any
    /// of 3 files under either of 2 hashes, query), so this covers the same
    /// space a six-step Kani proof would, which does not fit in a CI runner's
    /// memory. Too slow for debug test runs; the CI `kani` job runs it in
    /// release mode.
    #[test]
    #[ignore = "729 million runs; CI runs it with --release --ignored"]
    fn consent_gate_invariant_exhaustive_six_steps() {
        let runs = exhaust(|n| super::consent_invariant(n, 6));
        assert_eq!(runs, 30_usize.pow(6));
    }

    #[test]
    fn no_key_or_content_before_accept_exhaustive() {
        assert_eq!(exhaust(super::nothing_before_accept), 6);
    }

    #[test]
    fn no_key_or_content_after_close_exhaustive() {
        assert_eq!(exhaust(super::nothing_after_close), 16 * 6 * 16);
    }

    #[test]
    fn content_only_for_selected_keyed_files_exhaustive() {
        assert_eq!(
            exhaust(super::content_only_within_selection),
            16 * 16 * 6 * 6
        );
    }
}
