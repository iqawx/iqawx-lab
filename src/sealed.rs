//! Versioned authenticated-encryption envelopes. Keys are always separate files.
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm,
};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use rsa::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};

pub const MAX_PLAINTEXT: usize = 64 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u8,
    pub algorithm: String,
    pub nonce_hex: String,
    pub aad_base64: String,
    pub ciphertext_base64: String,
}

fn parameters(algorithm: &str) -> Result<(usize, usize), String> {
    match algorithm {
        "aes128-gcm" => Ok((16, 12)),
        "aes256-gcm" | "chacha20-poly1305" => Ok((32, 12)),
        "xchacha20-poly1305" => Ok((32, 24)),
        _ => Err("Unsupported envelope algorithm".into()),
    }
}

pub fn random_bytes(length: usize) -> Result<Vec<u8>, String> {
    if !matches!(length, 12 | 16 | 24 | 32) {
        return Err("Unsupported random key/nonce length".into());
    }
    let mut bytes = vec![0; length];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| format!("System random generator failed: {e}"))?;
    Ok(bytes)
}

// Bind format version and algorithm as well as the caller's AAD.
fn authenticated_data(algorithm: &str, aad: &[u8]) -> Vec<u8> {
    let mut bytes = format!("IQAWX-SEALED\0v1\0{algorithm}\0").into_bytes();
    bytes.extend_from_slice(aad);
    bytes
}

fn encrypt_aead<C: Aead + KeyInit>(
    plain: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = C::new_from_slice(key).map_err(|_| "Invalid key length".to_string())?;
    cipher
        .encrypt(
            aes_gcm::aead::Nonce::<C>::from_slice(nonce),
            Payload { msg: plain, aad },
        )
        .map_err(|_| "Encryption failed".into())
}

pub fn seal(algorithm: &str, plain: &[u8], key: &[u8], aad: &[u8]) -> Result<Envelope, String> {
    use base64::Engine;
    let (key_len, nonce_len) = parameters(algorithm)?;
    if key.len() != key_len {
        return Err(format!("{algorithm} requires a {key_len}-byte key"));
    }
    if plain.len() > MAX_PLAINTEXT || aad.len() > 65536 {
        return Err("Plaintext exceeds 64 MiB or AAD exceeds 64 KiB".into());
    }
    let nonce = random_bytes(nonce_len)?;
    let bound_aad = authenticated_data(algorithm, aad);
    let ciphertext = match algorithm {
        "aes128-gcm" => encrypt_aead::<Aes128Gcm>(plain, key, &nonce, &bound_aad),
        "aes256-gcm" => encrypt_aead::<Aes256Gcm>(plain, key, &nonce, &bound_aad),
        "chacha20-poly1305" => encrypt_aead::<ChaCha20Poly1305>(plain, key, &nonce, &bound_aad),
        "xchacha20-poly1305" => encrypt_aead::<XChaCha20Poly1305>(plain, key, &nonce, &bound_aad),
        _ => unreachable!(),
    }?;
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(Envelope {
        version: 1,
        algorithm: algorithm.into(),
        nonce_hex: hex::encode(nonce),
        aad_base64: b64.encode(aad),
        ciphertext_base64: b64.encode(ciphertext),
    })
}

pub fn open(envelope: &Envelope, key: &[u8]) -> Result<Vec<u8>, String> {
    if envelope.version != 1 {
        return Err("Unsupported envelope version".into());
    }
    let (key_len, nonce_len) = parameters(&envelope.algorithm)?;
    if key.len() != key_len {
        return Err(format!(
            "{} requires a {key_len}-byte key",
            envelope.algorithm
        ));
    }
    if envelope.nonce_hex.len() != nonce_len * 2
        || envelope.aad_base64.len() > 65536usize.div_ceil(3) * 4
        || envelope.ciphertext_base64.len() > (MAX_PLAINTEXT + 16).div_ceil(3) * 4
    {
        return Err("Invalid envelope field length".into());
    }
    let nonce = crate::crypto::decode("hex", envelope.nonce_hex.as_bytes())?;
    let aad = crate::crypto::decode("base64", envelope.aad_base64.as_bytes())?;
    let ciphertext = crate::crypto::decode("base64", envelope.ciphertext_base64.as_bytes())?;
    if aad.len() > 65536 || ciphertext.len() > MAX_PLAINTEXT + 16 {
        return Err("Envelope exceeds size limit".into());
    }
    crate::crypto::decrypt(
        &envelope.algorithm,
        &ciphertext,
        key,
        &nonce,
        &authenticated_data(&envelope.algorithm, &aad),
    )
}

pub fn digest(algorithm: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    match algorithm {
        "sha256" => Ok(Sha256::digest(data).to_vec()),
        "sha384" => Ok(Sha384::digest(data).to_vec()),
        "sha512" => Ok(Sha512::digest(data).to_vec()),
        _ => Err("Unsupported digest algorithm".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encryption_matches_nist_gcm_known_answer() {
        let result = encrypt_aead::<Aes128Gcm>(&[0; 16], &[0; 16], &[0; 12], b"").unwrap();
        assert_eq!(
            hex::encode(result),
            "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"
        );
        let result = encrypt_aead::<Aes256Gcm>(b"", &[0; 32], &[0; 12], b"").unwrap();
        assert_eq!(hex::encode(result), "530f8afbc74536b9a963b4f1c4cb738b");
    }

    #[test]
    fn envelopes_roundtrip_binary_empty_and_unicode_with_unique_nonces() {
        for alg in [
            "aes128-gcm",
            "aes256-gcm",
            "chacha20-poly1305",
            "xchacha20-poly1305",
        ] {
            let key = vec![42; parameters(alg).unwrap().0];
            for plain in [&b""[..], &b"\x00\xff\x80"[..], "مرحبا 🔐".as_bytes()] {
                let e = seal(alg, plain, &key, b"context").unwrap();
                assert_eq!(open(&e, &key).unwrap(), plain);
                let other = seal(alg, plain, &key, b"context").unwrap();
                assert_ne!(e.nonce_hex, other.nonce_hex);
                assert!(open(&e, &vec![43; key.len()]).is_err());
                let mut value = serde_json::to_value(&e).unwrap();
                for field in ["nonce_hex", "aad_base64", "ciphertext_base64"] {
                    let original = value[field].clone();
                    let s = value[field].as_str().unwrap();
                    value[field] =
                        format!("{}{}", if s.starts_with('0') { "1" } else { "0" }, &s[1..]).into();
                    let broken: Envelope = serde_json::from_value(value.clone()).unwrap();
                    assert!(open(&broken, &key).is_err(), "{alg} {field}");
                    value[field] = original;
                }
            }
        }
    }
    #[test]
    fn metadata_and_key_lengths_are_validated() {
        assert!(seal("aes256-gcm", b"data", &[0; 16], b"").is_err());
        assert!(seal("aes256-cbc", b"data", &[0; 32], b"").is_err());
        let mut e = seal("aes256-gcm", b"data", &[0; 32], b"").unwrap();
        e.algorithm = "chacha20-poly1305".into();
        assert!(open(&e, &[0; 32]).is_err());
        e.version = 2;
        assert!(open(&e, &[0; 32]).is_err());
        assert!(serde_json::from_str::<Envelope>(r#"{"version":1,"version":2}"#).is_err());
    }
    #[test]
    fn sha2_known_answers() {
        assert_eq!(
            hex::encode(digest("sha256", b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(hex::encode(digest("sha384", b"abc").unwrap()), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
        assert_eq!(hex::encode(digest("sha512", b"abc").unwrap()), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    }
}
