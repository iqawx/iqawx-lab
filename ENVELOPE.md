# IQAWX authenticated envelope v1

An envelope is UTF-8 JSON with exactly five required fields. Unknown and duplicate fields are rejected.

| Field | Meaning |
|---|---|
| `version` | Integer `1` |
| `algorithm` | `aes128-gcm`, `aes256-gcm`, `chacha20-poly1305`, or `xchacha20-poly1305` |
| `nonce_hex` | Random nonce encoded as hex: 12 bytes for GCM/ChaCha20, 24 for XChaCha20 |
| `aad_base64` | Caller-supplied nonsecret context encoded as standard Base64 |
| `ciphertext_base64` | Ciphertext followed by the 16-byte authentication tag, standard Base64 |

The raw key is stored separately. AES-128 uses 16 bytes; other supported envelope algorithms use 32. The authenticated data passed to the AEAD implementation is the concatenation of UTF-8 `IQAWX-SEALED`, byte `00`, UTF-8 `v1`, byte `00`, the exact algorithm name, byte `00`, and decoded caller AAD. Consequently raw `decrypt` is not directly interchangeable with `open` unless this bound AAD is supplied.

Version and algorithm are authenticated by this prefix. Nonces come from the operating system CSPRNG for every encryption; the CLI accepts no user-supplied nonce for envelopes. JSON whitespace and equivalent hex letter case are representation details and are not authenticated. Semantic changes to nonce, AAD or ciphertext fail authentication.

Plaintext is bounded to 64 MiB and caller AAD to 64 KiB. The JSON reader accepts at most 128 MiB to accommodate Base64 expansion and whitespace, then validates individual field lengths. Unsupported versions and algorithms are rejected. `open` verifies before writing any plaintext and does not truncate an existing destination on authentication failure. Normal filesystem writes are not atomic against disk errors; existing output replacement requires `--force`.

Use the library's `sealed::seal` and `sealed::open` functions to work with this format. General raw interoperability remains available through `crypto::decrypt`. No password-based encryption or private-key generation is part of envelope v1.
