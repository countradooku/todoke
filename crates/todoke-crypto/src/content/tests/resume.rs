//! Resume with random interruptions and restarts (§7.5): a receiver keeps
//! stored ciphertext across sessions, revalidates it after each restart,
//! and requests only what is missing.

use std::collections::BTreeMap;

use proptest::prelude::*;

use super::{AnyResult, Source, local_suites};
use crate::content::{ContentError, ContentSuite, SegmentTracker};

#[derive(Clone, Debug)]
enum Event {
    /// Request one of the lowest missing segments (at most 16 outstanding)
    /// and store the response.
    Deliver(usize),
    /// A response arrives with one flipped bit: it is rejected, nothing is
    /// recorded, and the session ends.
    Tamper(usize, usize),
    /// The connection or process dies. The last stored segment may be torn
    /// and another stored segment may rot on disk.
    Interrupt { torn: bool, rot: Option<usize> },
}

fn event() -> impl Strategy<Value = Event> {
    prop_oneof![
        8 => (0..16_usize).prop_map(Event::Deliver),
        1 => (0..16_usize, any::<usize>()).prop_map(|(pick, bit)| Event::Tamper(pick, bit)),
        2 => (any::<bool>(), proptest::option::of(any::<usize>()))
            .prop_map(|(torn, rot)| Event::Interrupt { torn, rot }),
    ]
}

/// The receiver's durable state: ciphertext per segment, in store order.
#[derive(Default)]
struct Disk {
    stored: BTreeMap<u32, Vec<u8>>,
    order: Vec<u32>,
}

struct Receiver<'a> {
    source: &'a Source,
    tracker: SegmentTracker,
    requests: usize,
}

impl<'a> Receiver<'a> {
    /// A fresh session after a restart: a new Accept, then every stored
    /// segment is reopened before it counts (§7.5: revalidate, do not trust
    /// disk metadata). Invalid ones are deleted.
    fn restart(source: &'a Source, disk: &mut Disk) -> AnyResult<Self> {
        let opener = source.opener()?;
        let mut tracker = SegmentTracker::new(&source.binding);
        let mut invalid = Vec::new();
        for (&index, ciphertext) in &disk.stored {
            match opener.open_segment(index, ciphertext) {
                Ok(segment) => {
                    assert_eq!(segment.data(), source.segment_bytes(index)?);
                    assert_eq!(tracker.record(&segment), Ok(true));
                }
                Err(ContentError::Authentication | ContentError::CiphertextLength) => {
                    invalid.push(index);
                }
                Err(error) => return Err(error.into()),
            }
        }
        for index in invalid {
            disk.stored.remove(&index);
            disk.order.retain(|&stored| stored != index);
        }
        Ok(Self {
            source,
            tracker,
            requests: 0,
        })
    }

    /// The segment to request next: one of the lowest missing ones.
    fn choose(&self, pick: usize) -> Option<u32> {
        let window: Vec<u32> = self.tracker.missing().take(16).collect();
        (!window.is_empty()).then(|| window[pick % window.len()])
    }

    fn fetch(&mut self, index: u32) -> AnyResult<Vec<u8>> {
        assert!(
            !self.tracker.contains(index),
            "requested a verified segment"
        );
        self.requests += 1;
        // The sender reseals from its immutable source each time.
        self.source.seal(&self.source.sealer()?, index)
    }

    fn deliver(&mut self, disk: &mut Disk, index: u32) -> AnyResult<()> {
        let ciphertext = self.fetch(index)?;
        let segment = self.source.opener()?.open_segment(index, &ciphertext)?;
        disk.stored.insert(index, ciphertext);
        disk.order.push(index);
        assert_eq!(self.tracker.record(&segment), Ok(true));
        Ok(())
    }
}

fn run(len: usize, suite: ContentSuite, events: Vec<Event>) -> AnyResult<()> {
    let source = Source::new(super::counter_input(len)?, suite)?;
    let count = source.binding.layout().count();
    let mut disk = Disk::default();
    let mut receiver = Receiver::restart(&source, &mut disk)?;
    for event in events {
        match event {
            Event::Deliver(pick) => {
                if let Some(index) = receiver.choose(pick) {
                    receiver.deliver(&mut disk, index)?;
                }
            }
            Event::Tamper(pick, bit) => {
                if let Some(index) = receiver.choose(pick) {
                    let mut ciphertext = receiver.fetch(index)?;
                    let bit = bit % (ciphertext.len() * 8);
                    ciphertext[bit / 8] ^= 1 << (bit % 8);
                    let opened = source.opener()?.open_segment(index, &ciphertext);
                    assert_eq!(opened.err(), Some(ContentError::Authentication));
                    assert!(!receiver.tracker.contains(index));
                    receiver = Receiver::restart(&source, &mut disk)?;
                }
            }
            Event::Interrupt { torn, rot } => {
                if torn
                    && let Some(&last) = disk.order.last()
                    && let Some(ciphertext) = disk.stored.get_mut(&last)
                {
                    let keep = ciphertext.len() / 2;
                    ciphertext.truncate(keep);
                }
                if let Some(pick) = rot
                    && !disk.order.is_empty()
                {
                    let index = disk.order[pick % disk.order.len()];
                    if let Some(ciphertext) = disk.stored.get_mut(&index) {
                        let byte = pick % ciphertext.len().max(1);
                        if let Some(value) = ciphertext.get_mut(byte) {
                            *value ^= 0x20;
                        }
                    }
                }
                let before = disk.stored.len();
                receiver = Receiver::restart(&source, &mut disk)?;
                // Damaged entries were dropped, intact ones kept.
                assert!(disk.stored.len() <= before);
                assert_eq!(
                    usize::try_from(receiver.tracker.verified_count())?,
                    disk.stored.len()
                );
            }
        }
    }
    // A final session finishes the file, requesting only what is missing.
    receiver = Receiver::restart(&source, &mut disk)?;
    let missing = count - receiver.tracker.verified_count();
    while let Some(index) = receiver.choose(0) {
        receiver.deliver(&mut disk, index)?;
    }
    assert_eq!(receiver.requests, usize::try_from(missing)?);
    assert!(receiver.tracker.is_complete());
    // Reassemble from disk exactly as a restarted receiver would and check
    // the whole file (§7.7).
    let opener = source.opener()?;
    let mut file = Vec::with_capacity(len);
    for (&index, ciphertext) in &disk.stored {
        file.extend_from_slice(opener.open_segment(index, ciphertext)?.data());
    }
    assert_eq!(file, source.content);
    assert_eq!(blake3::hash(&file).as_bytes(), source.binding.root());
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn resume_after_random_interruptions(
        len in prop_oneof![Just(0_usize), 1..(6 * 16_384 + 100_usize)],
        suite in any::<bool>(),
        events in proptest::collection::vec(event(), 0..40),
    ) {
        let suites = local_suites();
        let suite = suites[usize::from(suite) % suites.len()];
        run(len, suite, events).map_err(|e| TestCaseError::fail(e.to_string()))?;
    }
}
