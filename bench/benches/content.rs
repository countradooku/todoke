//! Content-layer throughput (PROTOCOL §7.4, §8): sealing and opening one
//! full 16384-byte segment per content suite, and building the BLAKE3/Bao
//! outboard of a file. Synthetic data only. See `bench/README.md`.
//!
//! On wasm32, which has no criterion (see `Cargo.toml`), this is an empty
//! program.

#[cfg(not(target_family = "wasm"))]
criterion::criterion_main!(content::benches);

#[cfg(target_family = "wasm")]
fn main() {}

#[cfg(not(target_family = "wasm"))]
mod content {
    use std::hint::black_box;
    use std::io::Cursor;

    use criterion::{BenchmarkId, Criterion, Throughput, criterion_group};
    use todoke_crypto::content::{
        AcceptedFile, ContentOpener, ContentSealer, ContentSuite, ContentSuites, FileBinding,
        FileMaster, SEGMENT_LEN, outboard,
    };
    use zeroize::Zeroizing;

    /// Eight full segments; the benchmarks use a middle one, whose slice
    /// carries a typical proof.
    const FILE_LEN: usize = 8 * SEGMENT_LEN as usize;
    const SEGMENT: u32 = 3;

    struct Fixture {
        content: Vec<u8>,
        tree: Vec<u8>,
        sealer: ContentSealer,
        opener: ContentOpener,
        ciphertext: Vec<u8>,
    }

    fn fixture(suite: ContentSuite) -> Option<Fixture> {
        let content: Vec<u8> = (0..FILE_LEN)
            .map(|i| i.to_le_bytes()[0] ^ i.to_le_bytes()[1])
            .collect();
        let (tree, root) = outboard(&content);
        let size = u64::try_from(content.len()).ok()?;
        let binding = FileBinding::new([0xa3; 16], [0x59; 32], 1, suite, size, root).ok()?;
        // Benchmarks only: the feature behind this constructor never ships.
        let file = AcceptedFile::assume_accepted_without_verification(binding);
        let master = || FileMaster::from_secret(Zeroizing::new([0xa5; 32]));
        let sealer = ContentSealer::new(&file, &master()).ok()?;
        let opener = ContentOpener::new(&file, &master()).ok()?;
        let ciphertext = sealer
            .seal_segment(SEGMENT, Cursor::new(&content), Cursor::new(&tree))
            .ok()?;
        Some(Fixture {
            content,
            tree,
            sealer,
            opener,
            ciphertext,
        })
    }

    fn suite_name(suite: ContentSuite) -> &'static str {
        match suite {
            ContentSuite::Aes256GcmStream => "aes-256-gcm",
            ContentSuite::XChaCha20Poly1305Stream => "xchacha20-poly1305",
        }
    }

    /// Seal: extract the slice from the source and outboard, verify it against
    /// the root, encrypt. Open: decrypt and authenticate, then verify the slice.
    /// Throughput counts the segment's 16384 logical bytes.
    fn segments(c: &mut Criterion) {
        let mut group = c.benchmark_group("content-segment");
        group.throughput(Throughput::Bytes(u64::from(SEGMENT_LEN)));
        for suite in [
            ContentSuite::Aes256GcmStream,
            ContentSuite::XChaCha20Poly1305Stream,
        ] {
            if !ContentSuites::local().contains(suite) {
                eprintln!(
                    "skipping {}: not advertised on this device",
                    suite_name(suite)
                );
                continue;
            }
            let Some(fixture) = fixture(suite) else {
                eprintln!("skipping {}: fixture setup failed", suite_name(suite));
                continue;
            };
            group.bench_function(BenchmarkId::new("seal", suite_name(suite)), |b| {
                b.iter(|| {
                    fixture.sealer.seal_segment(
                        black_box(SEGMENT),
                        Cursor::new(&fixture.content),
                        Cursor::new(&fixture.tree),
                    )
                });
            });
            group.bench_function(BenchmarkId::new("open", suite_name(suite)), |b| {
                b.iter(|| {
                    fixture
                        .opener
                        .open_segment(black_box(SEGMENT), black_box(&fixture.ciphertext))
                });
            });
        }
        group.finish();
    }

    /// BLAKE3 root and Bao outboard of a 1 MiB file (the sender's one-time
    /// cost per file before building the manifest).
    fn outboards(c: &mut Criterion) {
        let content = vec![0x5a_u8; 1 << 20];
        let mut group = c.benchmark_group("content-outboard");
        group.throughput(Throughput::Bytes(1 << 20));
        group.bench_function("outboard-1MiB", |b| {
            b.iter(|| outboard(black_box(&content)));
        });
        group.finish();
    }

    criterion_group!(benches, segments, outboards);
}
