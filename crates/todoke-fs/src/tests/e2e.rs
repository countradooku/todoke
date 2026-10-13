//! End to end: P07's transfer engine on both sides of real suite 0x0001
//! session bindings, with files read from disk by `FsSource` and written by
//! `FsSink`, including a receiver restart and resume, a source changed
//! after the offer, and hostile names.

use core::time::Duration;
use std::path::{Path, PathBuf};

use todoke_crypto::consent::SessionBinding;
use todoke_crypto::content::ContentSuites;
use todoke_crypto::identity::{KeyStore, SoftwareSealer};
use todoke_proto::session::{ErrorScope, FrameType};
use todoke_proto::transfer::{Capabilities, ManifestLimits};
use todoke_transfer::{
    Clock, EngineConfig, Failure, FailureCode, LocalCapabilities, ManifestBuilder, OutgoingFrame,
    OutgoingOffer, Party, ReceiveSink, SendSource, TransferEngine, TransferEvent, TransferId,
};

use super::sink::files_below;
use super::support::*;
use super::*;
use crate::dest::DirDestination;
use crate::detect::{ContentWarning, DetectedType};
use crate::{FsSink, FsSource, SinkConfig};

type Sink = FsSink<DirDestination, SoftwareSealer>;
type Engine<'k> = TransferEngine<'k, Keys, FsSource, Sink>;

fn config() -> AnyResult<EngineConfig> {
    let maximums = Capabilities::PROTOCOL_MAXIMUMS;
    let record = Capabilities::new(
        ContentSuites::local().bits(),
        maximums.max_manifest_bytes(),
        maximums.max_entries(),
        maximums.max_file_bytes(),
        maximums.max_transfer_bytes(),
        16,
    )?;
    Ok(EngineConfig {
        capabilities: LocalCapabilities::new(record)?,
        transport: "test-pipe",
    })
}

/// Hands one frame to an engine as the session layer would.
fn deliver<K: KeyStore, S: SendSource, R: ReceiveSink>(
    engine: &mut TransferEngine<'_, K, S, R>,
    frame: OutgoingFrame,
    now: Duration,
) {
    if engine.is_closed() {
        return;
    }
    let _ = match frame {
        OutgoingFrame::Frame { frame_type, body } => engine.handle_frame(frame_type, &body, now),
        OutgoingFrame::Error(record) => {
            if record.scope() == ErrorScope::Session {
                engine.close(Some(Failure {
                    code: FailureCode::from_error_code(record.code()),
                    by: Party::Peer,
                }));
                Ok(())
            } else {
                engine.handle_frame(FrameType::ERROR, &record.encode(), now)
            }
        }
    };
}

/// Two engines and their events.
struct Link<'k> {
    alice: Engine<'k>,
    bob: Engine<'k>,
    alice_events: Vec<TransferEvent>,
    bob_events: Vec<TransferEvent>,
    chunks: usize,
}

impl<'k> Link<'k> {
    fn new(
        fixture: &'k Fixture,
        bindings: (SessionBinding, SessionBinding),
        source: FsSource,
        sink: Sink,
    ) -> AnyResult<Self> {
        let clock = Clock::new(time(WALL)?, START);
        let alice = TransferEngine::new(
            bindings.0,
            &fixture.alice.keys,
            fixture.alice.signing_key,
            source,
            placeholder_sink()?,
            config()?,
            clock,
            START,
        )?;
        let bob = TransferEngine::new(
            bindings.1,
            &fixture.bob.keys,
            fixture.bob.signing_key,
            FsSource::new(&scratch()?)?,
            sink,
            config()?,
            clock,
            START,
        )?;
        Ok(Self {
            alice,
            bob,
            alice_events: Vec::new(),
            bob_events: Vec::new(),
            chunks: 0,
        })
    }

    /// Moves frames both ways until both engines are quiet, or until
    /// `chunk_limit` chunks have reached Bob.
    fn settle(&mut self, chunk_limit: Option<usize>) {
        for _ in 0..1_000_000 {
            let mut moved = false;
            while let Some(frame) = self.alice.pop_frame() {
                if let OutgoingFrame::Frame { frame_type, .. } = &frame
                    && *frame_type == FrameType::CHUNK
                {
                    if chunk_limit.is_some_and(|limit| self.chunks >= limit) {
                        return;
                    }
                    self.chunks += 1;
                }
                moved = true;
                deliver(&mut self.bob, frame, START);
            }
            while let Some(frame) = self.bob.pop_frame() {
                moved = true;
                deliver(&mut self.alice, frame, START);
            }
            self.alice_events
                .extend(core::iter::from_fn(|| self.alice.pop_event()));
            self.bob_events
                .extend(core::iter::from_fn(|| self.bob.pop_event()));
            if !moved {
                return;
            }
        }
    }

    fn offered(&self) -> Option<TransferId> {
        self.bob_events.iter().find_map(|event| match event {
            TransferEvent::OfferReceived(view) => Some(view.transfer_id),
            _ => None,
        })
    }
}

/// Alice's engine needs a sink of the same type; it never receives.
fn placeholder_sink() -> AnyResult<Sink> {
    let state = scratch()?;
    let dest = scratch()?;
    Ok(FsSink::open(
        &state,
        DirDestination::open(&dest)?,
        sealer(3),
        SinkConfig::default(),
        time(WALL)?,
    )?)
}

thread_local! {
    static SCRATCH: std::cell::RefCell<Vec<TempDir>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// A temporary directory that lives until the test thread ends.
fn scratch() -> AnyResult<PathBuf> {
    let dir = TempDir::new()?;
    let path = dir.path().to_owned();
    SCRATCH.with(|cell| cell.borrow_mut().push(dir));
    Ok(path)
}

/// Writes `files` (name, parent index, content) under `root` and offers
/// them: returns the offer and Alice's source.
fn offer_from_disk(
    fixture: &Fixture,
    root: &Path,
    entries: &[Entry],
) -> AnyResult<(OutgoingOffer, FsSource)> {
    let mut source = FsSource::new(&scratch()?)?;
    let mut builder = ManifestBuilder::new(
        &fixture.alice.key(),
        &fixture.bob.key(),
        time(WALL)?,
        time(WALL + 3600)?,
    )?;
    let mut prepared = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        match &entry.content {
            None => {
                builder.add_directory(entry.parent, &entry.name);
            }
            Some(bytes) => {
                let path = root.join(format!("source-{index}"));
                std::fs::write(&path, bytes)?;
                let file = source.prepare(&path)?;
                let id = builder.add_file(
                    entry.parent,
                    &entry.name,
                    "application/octet-stream",
                    file.size(),
                    *file.root(),
                );
                prepared.push((id, file));
            }
        }
    }
    let manifest = builder.build(suite()?, &ManifestLimits::SPEC)?;
    for (id, file) in prepared {
        source.insert(*manifest.transfer_id(), id, file);
    }
    Ok((OutgoingOffer::new(manifest)?, source))
}

fn open_sink(state: &Path, dest: &Path) -> AnyResult<Sink> {
    Ok(FsSink::open(
        state,
        DirDestination::open(dest)?,
        sealer(7),
        SinkConfig::default(),
        time(WALL)?,
    )?)
}

fn has(events: &[TransferEvent], f: impl Fn(&TransferEvent) -> bool) -> bool {
    events.iter().any(f)
}

fn entries() -> Vec<Entry> {
    vec![
        dir_entry("photos", 0),
        file_entry("a.bin", 1, content(200_000, 1)),
        file_entry("empty", 1, Vec::new()),
        dir_entry("deep", 1),
        file_entry("b.bin", 4, content(16_384 * 3 + 5, 3)),
        file_entry("run.sh", 0, b"#!/bin/sh\necho hello\n".to_vec()),
    ]
}

#[test]
fn a_folder_transfer_lands_on_disk_through_the_engine() -> TestResult {
    let fixture = fixture()?;
    let (sources, state, dest) = (TempDir::new()?, TempDir::new()?, TempDir::new()?);
    let (offer, source) = offer_from_disk(&fixture, sources.path(), &entries())?;
    let transfer_id = *offer.transfer_id();
    let mut link = Link::new(
        &fixture,
        fixture.first,
        source,
        open_sink(state.path(), dest.path())?,
    )?;
    link.settle(None);
    link.alice.offer(offer, START)?;
    link.settle(None);
    assert_eq!(link.offered(), Some(transfer_id));
    // The receive sheet's plan exists before consent, and nothing is on
    // disk yet.
    let plan = link.bob.sink().plan(&transfer_id).ok_or("plan")?;
    assert_eq!(plan.entry(6).map(|e| e.local().as_str()), Some("run.sh"));
    assert_eq!(files_below(dest.path())?, Vec::<PathBuf>::new());
    link.bob.accept(&transfer_id, vec![2, 3, 5, 6], START)?;
    link.settle(None);
    assert!(has(&link.bob_events, |e| matches!(
        e,
        TransferEvent::Completed { .. }
    )));
    assert!(has(&link.alice_events, |e| matches!(
        e,
        TransferEvent::DeliveryConfirmed { .. }
    )));
    let root = dest.path();
    assert_eq!(
        std::fs::read(root.join("photos").join("a.bin"))?,
        content(200_000, 1)
    );
    assert_eq!(
        std::fs::read(root.join("photos").join("empty"))?,
        Vec::<u8>::new()
    );
    assert_eq!(
        std::fs::read(root.join("photos").join("deep").join("b.bin"))?,
        content(16_384 * 3 + 5, 3)
    );
    assert_eq!(
        std::fs::read(root.join("run.sh"))?,
        b"#!/bin/sh\necho hello\n"
    );
    assert_eq!(files_below(root)?.len(), 4);
    let report = link
        .bob
        .sink()
        .content_report(&transfer_id, 6)
        .ok_or("report")?;
    assert_eq!(report.detected(), Some(DetectedType::Shebang));
    assert!(matches!(
        report.warnings(),
        [ContentWarning::Risky(DetectedType::Shebang, _)]
    ));
    // The quarantine kept only the record.
    let (_, mut sink) = link.bob.into_parts();
    assert!(sink.retained(&transfer_id, time(WALL)?).is_some());
    let left: Vec<PathBuf> = files_below(&state.path().join("transfers"))?;
    assert_eq!(left.len(), 2, "journal and manifest only");
    sink.sweep(time(WALL + 3600)?);
    assert_eq!(
        files_below(&state.path().join("transfers"))?,
        Vec::<PathBuf>::new()
    );
    Ok(())
}

#[test]
fn an_interrupted_transfer_resumes_after_the_receiver_restarts() -> TestResult {
    let fixture = fixture()?;
    let (sources, state, dest) = (TempDir::new()?, TempDir::new()?, TempDir::new()?);
    let (offer, source) = offer_from_disk(&fixture, sources.path(), &entries())?;
    let transfer_id = *offer.transfer_id();
    let mut link = Link::new(
        &fixture,
        fixture.first,
        source,
        open_sink(state.path(), dest.path())?,
    )?;
    link.settle(None);
    link.alice.offer(offer, START)?;
    link.settle(None);
    link.bob.accept(&transfer_id, vec![2, 3, 5, 6], START)?;
    // The connection drops after a few chunks.
    link.settle(Some(6));
    let first_chunks = link.chunks;
    link.alice.close(None);
    link.bob.close(None);
    let resumable = link.alice.take_resumable();
    let (source, _) = link.alice.into_parts();
    let (_, sink) = link.bob.into_parts();
    // The receiving app restarts.
    drop(sink);
    let sink = open_sink(state.path(), dest.path())?;
    assert!(sink.retained(&transfer_id, time(WALL)?).is_some());
    // A fresh session, a fresh Accept with the same selection.
    let mut link = Link::new(&fixture, fixture.second, source, sink)?;
    link.settle(None);
    for offer in resumable {
        link.alice.offer(offer, START)?;
    }
    link.settle(None);
    link.bob.accept(&transfer_id, vec![2, 3, 5, 6], START)?;
    link.settle(None);
    assert!(has(&link.alice_events, |e| matches!(
        e,
        TransferEvent::DeliveryConfirmed { .. }
    )));
    assert_eq!(
        std::fs::read(dest.path().join("photos").join("a.bin"))?,
        content(200_000, 1)
    );
    assert_eq!(
        std::fs::read(dest.path().join("run.sh"))?,
        b"#!/bin/sh\necho hello\n"
    );
    // Retained segments were not fetched again: 13 + 1 + 4 + 1 segments in
    // all, some of them received before the restart.
    let total = 13 + 1 + 4 + 1;
    assert!(first_chunks > 0);
    assert!(link.chunks < total, "{} chunks after resuming", link.chunks);
    assert_eq!(files_below(dest.path())?.len(), 4);
    Ok(())
}

#[test]
fn a_source_changed_after_the_offer_is_never_delivered() -> TestResult {
    let fixture = fixture()?;
    let (sources, state, dest) = (TempDir::new()?, TempDir::new()?, TempDir::new()?);
    let (offer, source) = offer_from_disk(&fixture, sources.path(), &entries())?;
    let transfer_id = *offer.transfer_id();
    // The user edits a file after offering it (same path, same size).
    let mut edited = content(200_000, 1);
    edited[100] ^= 1;
    std::fs::write(sources.path().join("source-1"), &edited)?;
    let mut link = Link::new(
        &fixture,
        fixture.first,
        source,
        open_sink(state.path(), dest.path())?,
    )?;
    link.settle(None);
    link.alice.offer(offer, START)?;
    link.settle(None);
    link.bob.accept(&transfer_id, vec![2, 3, 5, 6], START)?;
    link.settle(None);
    assert!(has(&link.alice_events, |e| matches!(
        e,
        TransferEvent::Failed { failure, .. } if failure.code == FailureCode::SourceChanged
    )));
    assert!(!has(&link.bob_events, |e| matches!(
        e,
        TransferEvent::Completed { .. }
    )));
    assert!(!dest.path().join("photos").join("a.bin").exists());
    Ok(())
}

#[test]
fn hostile_names_from_the_peer_land_safely_inside_the_destination() -> TestResult {
    let fixture = fixture()?;
    let (sources, state, dest) = (TempDir::new()?, TempDir::new()?, TempDir::new()?);
    let hostile = vec![
        file_entry("photo\u{202E}gpj.exe", 0, b"MZ\x90\0payload".to_vec()),
        file_entry("invoice.pdf.exe", 0, b"x".to_vec()),
        file_entry("CON .txt", 0, b"y".to_vec()),
        file_entry("a.txt", 0, b"lower".to_vec()),
        file_entry("A.TXT", 0, b"upper".to_vec()),
        file_entry("desktop.ini", 0, b"[.ShellClassInfo]".to_vec()),
        dir_entry("COM\u{B9}", 0),
        file_entry("PROGRA~1", 7, b"z".to_vec()),
    ];
    let (offer, source) = offer_from_disk(&fixture, sources.path(), &hostile)?;
    let transfer_id = *offer.transfer_id();
    let mut link = Link::new(
        &fixture,
        fixture.first,
        source,
        open_sink(state.path(), dest.path())?,
    )?;
    link.settle(None);
    link.alice.offer(offer, START)?;
    link.settle(None);
    link.bob
        .accept(&transfer_id, vec![1, 2, 3, 4, 5, 6, 8], START)?;
    link.settle(None);
    assert!(has(&link.alice_events, |e| matches!(
        e,
        TransferEvent::DeliveryConfirmed { .. }
    )));
    let root = std::fs::canonicalize(dest.path())?;
    let mut names: Vec<String> = files_below(&root)?
        .iter()
        .map(|path| {
            path.strip_prefix(&root)
                .map(|relative| relative.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default()
        })
        .collect();
    names.sort();
    let mut expected = vec![
        "photo\u{FFFD}gpj.exe".to_owned(),
        "invoice_pdf.exe".to_owned(),
        "_CON.txt".to_owned(),
        "a.txt".to_owned(),
        "A (2).TXT".to_owned(),
        "desktop.ini.txt".to_owned(),
        "_COM\u{B9}/PROGRA_1".to_owned(),
    ];
    expected.sort();
    assert_eq!(names, expected);
    assert_eq!(std::fs::read(root.join("a.txt"))?, b"lower");
    assert_eq!(std::fs::read(root.join("A (2).TXT"))?, b"upper");
    let report = link
        .bob
        .sink()
        .content_report(&transfer_id, 1)
        .ok_or("report")?;
    assert_eq!(report.detected(), Some(DetectedType::WindowsExecutable));
    Ok(())
}

/// Every segment of a multi-segment file seals from `FsSource`'s readers,
/// requested in any order and repeatedly, and matches the in-memory
/// outboard path byte for byte.
#[test]
fn every_segment_seals_from_files_on_disk() -> TestResult {
    let fixture = fixture()?;
    let dir = TempDir::new()?;
    let data = content(16_384 * 70 + 3, 5);
    std::fs::write(dir.path().join("x"), &data)?;
    let mut source = FsSource::new(&scratch()?)?;
    let prepared = source.prepare(&dir.path().join("x"))?;
    assert_eq!(prepared.size(), data.len() as u64);
    assert_eq!(prepared.root(), blake3::hash(&data).as_bytes());
    let entries = vec![file_entry("x", 0, data)];
    let manifest = build_manifest(&fixture, [0x31; 16], &entries, 3600)?;
    let consented = Consented::new(&fixture, &manifest, &entries, &[1], false, 1)?;
    source.insert([0x31; 16], 1, prepared);
    let file = consented.sender_accept.file(1).ok_or("file")?;
    let sealer = todoke_crypto::content::ContentSealer::new(&file, &consented.master(1)?)?;
    let count = consented.count(1)?;
    for index in (0..count).rev().chain([0, count / 2, count - 1]) {
        let (content, outboard) = source.open(&[0x31; 16], 1).map_err(|e| format!("{e:?}"))?;
        let ciphertext = sealer.seal_segment(index, content, outboard)?;
        assert_eq!(ciphertext, consented.ciphertext(1, index)?);
    }
    // A file changed after hashing is refused before anything is read.
    std::fs::write(dir.path().join("x"), b"changed")?;
    assert!(source.open(&[0x31; 16], 1).is_err());
    source.remove_transfer(&[0x31; 16]);
    assert_eq!(
        source.open(&[0x31; 16], 1).map(|_| ()),
        Err(todoke_transfer::SourceError::NotFound)
    );
    Ok(())
}

/// Two sessions' engines share one sink through `SharedSink`.
#[test]
fn engines_share_one_sink() -> TestResult {
    let fixture = fixture()?;
    let (state, dest) = (TempDir::new()?, TempDir::new()?);
    let shared = crate::SharedSink::new(open_sink(state.path(), dest.path())?);
    let entries = vec![file_entry("x.txt", 0, content(1000, 2))];
    let manifest = build_manifest(&fixture, [0x44; 16], &entries, 3600)?;
    let consented = Consented::new(&fixture, &manifest, &entries, &[1], false, 4)?;
    let (mut one, mut two) = (shared.clone(), shared.clone());
    one.check_offer(&manifest).map_err(|r| format!("{r:?}"))?;
    one.record_accept(&manifest, &consented.accept)?;
    let file = consented.accept.file(1).ok_or("file")?;
    two.record_file_key(&file, &consented.master(1)?)?;
    let ciphertext = consented.ciphertext(1, 0)?;
    two.store_segment(&consented.verified(1, 0, &ciphertext)?, &ciphertext)?;
    assert_eq!(one.retained_segment(&[0x44; 16], 1, 0)?, Some(ciphertext));
    one.publish(&manifest, 1)?;
    assert!(two.published_intact(&manifest, 1));
    assert!(shared.lock()?.published_path(&[0x44; 16], 1).is_some());
    two.tombstone(&[0x44; 16], time(WALL + 7200)?);
    assert!(one.is_tombstoned(&[0x44; 16], time(WALL)?));
    Ok(())
}
