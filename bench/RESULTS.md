# Benchmark results

Procedures are in [README.md](README.md). Every result records the
revision, hardware, OS, Rust version, workload, and procedure.

## Content layer

**aarch64 (measured 2026-10-13).** Apple M5 Pro, 48 GB, macOS 27.0.1;
rustc 1.99.0; revision `9cf0b5c` plus the `feat/content-layer` changes;
the content command in README.md, with no other heavy work running. Ranges
are criterion's
95% confidence intervals:

| Benchmark | Time per segment | Throughput |
| --- | --- | --- |
| seal, AES-256-GCM | 30.6–31.5 µs | 496–511 MiB/s |
| open, AES-256-GCM | 33.2–33.5 µs | 466–471 MiB/s |
| seal, XChaCha20-Poly1305 | 46.6–47.6 µs | 328–335 MiB/s |
| open, XChaCha20-Poly1305 | 49.5–51.2 µs | 305–315 MiB/s |
| outboard, 1 MiB | 884–904 µs | 1.08–1.10 GiB/s |

Bao hashing dominates: the `bao` crate hashes one 1024-byte chunk at a time
(about 1.1 GiB/s here), and both seal and open hash the whole slice once.
These are single-thread numbers for one segment; a transfer may seal or
open several segments in parallel.

**x86_64: not measured.** This machine cannot run x86_64 benchmarks
natively, and emulated numbers would be meaningless. Run the content command
in README.md on an x86_64 machine with AVX2 and AES-NI (for example a CI runner or a
developer PC) and add the results here with the same details. Without those
CPU features AES is not advertised and is skipped.

## LAN

**Loopback (measured 2026-10-14).** Apple M5 Pro, 48 GB, macOS 27.0.1;
rustc 1.99.0; revision `d893997` plus the benchmark itself; the one-machine
command, three runs, with no other heavy work running:

| Workload | 1 GiB | 10 GiB |
| --- | --- | --- |
| Raw TCP | 9.1–13.2 GiB/s | 12.5–13.2 GiB/s |
| Session (suite 0x0001) | 505–553 MiB/s (4.2–4.6 Gbit/s) | 535–553 MiB/s (4.5–4.6 Gbit/s) |

The session is CPU-bound: one core per end encrypts and authenticates
every frame (ChaCha20-Poly1305 from libcrux, §5) and frames records of at
most 65535 bytes; loopback TCP itself is more than twenty times faster.
That ceiling is about five times what gigabit Ethernet (about 0.94 Gbit/s
of TCP payload) and real Wi-Fi 6 links carry, so on those networks the
link, not the session, should limit a transfer. A whole transfer also pays
for content sealing and opening (content-layer results above, single
thread per segment) and for disk I/O.

**1 GbE and Wi-Fi 6: not measured.** They need two machines on such a
network; this was measured on one. Run the two-machine commands in
README.md on a wired gigabit link and on a Wi-Fi 6 link, and add the
results here with the machines, the network (switch or access point,
channel width, signal), the revision, and three runs of each size.
