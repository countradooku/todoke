# Wycheproof AEAD vectors

Unmodified copies from Project Wycheproof (C2SP), used by
`src/content/tests/wycheproof.rs` for content suites 1 and 2 (PROTOCOL §8).

| File | Upstream path | SHA-256 |
| --- | --- | --- |
| `aes_gcm_test.json` | `testvectors_v1/aes_gcm_test.json` | `985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7` |
| `xchacha20_poly1305_test.json` | `testvectors_v1/xchacha20_poly1305_test.json` | `a79de072571b90eb40c3a63ce0c7f75dcb4b62323c8870228e1f61dcc61d63a9` |

- Repository: <https://github.com/C2SP/wycheproof>
- Commit: `7a325932231bd7a724c791c8b0d65ea4d6d2f435` (2026-10-12)
- Fetched: 2026-10-13 from
  `https://raw.githubusercontent.com/C2SP/wycheproof/<commit>/<path>`
- License: Apache-2.0 (the repository's license)

To check the copies:

```sh
C=7a325932231bd7a724c791c8b0d65ea4d6d2f435
for f in aes_gcm_test.json xchacha20_poly1305_test.json; do
  curl -sL "https://raw.githubusercontent.com/C2SP/wycheproof/$C/testvectors_v1/$f" | shasum -a 256
done
shasum -a 256 *.json
```

The tests run every case whose parameters todoke uses (AES: 256-bit key,
96-bit nonce, 128-bit tag, 66 cases; XChaCha: 192-bit nonce, 306 cases) and
count the skipped ones, so a changed file fails loudly.
