# Bao 0.13.1 reference data

Used by `src/content/tests/bao_vectors.rs` to show that the `bao` crate and
todoke's strict slice verifier match the Bao 0.13.1 format pinned by
PROTOCOL §7.4 (see `docs/adr/0003-bao.md`).

## `test_vectors.json`

An unmodified copy of the Bao repository's own test vectors.

- Repository: <https://github.com/oconnor663/bao>, tag `0.13.1`, commit
  `19763d70a5bda9402cc37a63e823cd7b9aa7f777`
- Upstream path: `tests/test_vectors.json`
- SHA-256: `e819b403a62e5fef51764d00783c3f750a78f8cb72e646f8a9add0c521333de3`
- License: CC0-1.0 OR Apache-2.0 (the repository's license)

Upstream generated it with `tests/generate_vectors.py` from the
pure-Python reference implementation `tests/bao.py`. Inputs are a 4-byte
little-endian counter starting at 1. Its largest input is 13 KiB, smaller
than one todoke segment.

## `segment_slices.json`

Generated for todoke by `generate_segment_slices.py` (in this directory)
from the same reference implementation, for 16384-byte segments: 14 file
sizes from 0 to 34 segments, the root, and for every segment the slice
length and BLAKE3 hash of the complete combined slice (full bytes for files
up to 1025 bytes). The generator also decodes each slice with the reference
decoder.

- Reference: `tests/bao.py` at the commit above, SHA-256
  `47f0423249c150a9ce143a701020c82bf69e51e18e5bd2d4ea7800576e4b5045`
- Output SHA-256:
  `eca16f996a78f07c829ffd057c23c6d949e995bf494bbdc2fb4ca1acd78e295d`

To regenerate (Python 3, about 3 seconds; `bao.py` is pure Python and needs
no packages):

```sh
C=19763d70a5bda9402cc37a63e823cd7b9aa7f777
mkdir -p /tmp/bao-ref
curl -sL -o /tmp/bao-ref/bao.py "https://raw.githubusercontent.com/oconnor663/bao/$C/tests/bao.py"
shasum -a 256 /tmp/bao-ref/bao.py
python3 -I generate_segment_slices.py /tmp/bao-ref/bao.py > segment_slices.json
```
