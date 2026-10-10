//! Strict byte-preserving decoders and keyed decryption.
//!
//! AEAD input is ciphertext followed by its 16-byte authentication tag. CBC
//! uses PKCS#7 padding. CTR uses a full-width, big-endian 128-bit counter and
//! no padding. Neither CBC nor CTR provides authenticity: successful decryption
//! is not proof that the key, IV/counter, or ciphertext is correct. RSA is an offline
//! OAEP/SHA-256 operation with an empty label and an unencrypted private PEM.

use aes::cipher::{
    block_padding::Pkcs7, consts::U16, Block, BlockDecryptMut, BlockEncrypt, BlockSizeUser,
    KeyIvInit,
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm,
};
use base64::{engine::general_purpose, Engine};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use rsa::{
    pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts, Oaep,
    RsaPrivateKey,
};
use sha2::Sha256;
use zeroize::Zeroize;

/// Decode without replacing invalid bytes or guessing the input format.
/// Hex/Base64/Base32 ignore surrounding ASCII whitespace (for text files), but
/// reject embedded whitespace. Base64/Base32 accept canonical padding or none.
/// Binary accepts whole octets, optionally separated by ASCII whitespace.
pub fn decode(format: &str, input: &[u8]) -> Result<Vec<u8>, String> {
    let format = format.to_ascii_lowercase();
    let input = if matches!(format.as_str(), "hex" | "base64" | "base64url" | "base32") {
        let start = input
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(input.len());
        let end = input
            .iter()
            .rposition(|b| !b.is_ascii_whitespace())
            .map_or(start, |i| i + 1);
        &input[start..end]
    } else {
        input
    };
    match format.as_str() {
        "raw" => Ok(input.to_vec()),
        "text" => {
            std::str::from_utf8(input).map_err(|_| "text input is not valid UTF-8".to_string())?;
            Ok(input.to_vec())
        }
        "hex" => hex::decode(input).map_err(|_| {
            "invalid hex: expected an even number of hexadecimal digits without embedded whitespace".into()
        }),
        "base64" | "base64url" => {
            let padded = input.contains(&b'=');
            let url = format.eq_ignore_ascii_case("base64url");
            let engine = match (url, padded) {
                (false, true) => &general_purpose::STANDARD,
                (false, false) => &general_purpose::STANDARD_NO_PAD,
                (true, true) => &general_purpose::URL_SAFE,
                (true, false) => &general_purpose::URL_SAFE_NO_PAD,
            };
            engine
                .decode(input)
                .map_err(|_| "invalid Base64 alphabet, padding, length, or trailing bits".into())
        }
        "base32" => {
            let encoding = if input.contains(&b'=') {
                data_encoding::BASE32
            } else {
                data_encoding::BASE32_NOPAD
            };
            encoding.decode(input).map_err(|_| "invalid Base32: expected uppercase RFC 4648 data with canonical padding or no padding".into())
        }
        "url" => percent_decode(input, false),
        "form" => percent_decode(input, true),
        "binary" => decode_binary(input),
        _ => Err(
            "unknown encoding; use raw, text, hex, base64, base64url, base32, url, form, or binary"
                .into(),
        ),
    }
}

fn percent_decode(input: &[u8], plus_as_space: bool) -> Result<Vec<u8>, String> {
    fn digit(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let mut output = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' => {
                let pair = input
                    .get(i + 1..i + 3)
                    .ok_or_else(|| format!("incomplete percent escape at byte {i}"))?;
                let high =
                    digit(pair[0]).ok_or_else(|| format!("invalid percent escape at byte {i}"))?;
                let low =
                    digit(pair[1]).ok_or_else(|| format!("invalid percent escape at byte {i}"))?;
                output.push((high << 4) | low);
                i += 3;
            }
            b'+' if plus_as_space => {
                output.push(b' ');
                i += 1;
            }
            value => {
                output.push(value);
                i += 1;
            }
        }
    }
    Ok(output)
}

fn decode_binary(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(input.len() / 8);
    for group in input
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|group| !group.is_empty())
    {
        if group.len() % 8 != 0 {
            return Err(
                "binary data must contain whole 8-bit bytes; whitespace may separate bytes".into(),
            );
        }
        for octet in group.chunks_exact(8) {
            let mut value = 0u8;
            for bit in octet {
                value = (value << 1)
                    | match bit {
                        b'0' => 0,
                        b'1' => 1,
                        _ => {
                            return Err(
                                "binary data may contain only 0, 1, and ASCII whitespace".into()
                            )
                        }
                    };
            }
            output.push(value);
        }
    }
    Ok(output)
}

/// Decrypt a supported algorithm using supplied raw key/nonce/AAD bytes.
/// RSA expects unencrypted PEM bytes as the key; nonce and AAD must be empty.
/// CBC expects a 16-byte IV as `nonce`; AAD must be empty.
/// CTR expects the entire 16-byte initial counter as `nonce`; AAD must be empty.
/// It increments all 128 bits in big-endian order, rejects overflow, and applies
/// no padding. It cannot detect an incorrect key/counter or modified ciphertext.
pub fn decrypt(
    algorithm: &str,
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let algorithm = algorithm.to_ascii_lowercase();
    match algorithm.as_str() {
        "aes128-gcm" | "aes-128-gcm" => decrypt_aead::<Aes128Gcm>(ciphertext, key, nonce, aad, 16, 12),
        "aes256-gcm" | "aes-256-gcm" => decrypt_aead::<Aes256Gcm>(ciphertext, key, nonce, aad, 32, 12),
        "chacha20-poly1305" => decrypt_aead::<ChaCha20Poly1305>(ciphertext, key, nonce, aad, 32, 12),
        "xchacha20-poly1305" => decrypt_aead::<XChaCha20Poly1305>(ciphertext, key, nonce, aad, 32, 24),
        "aes128-ctr" | "aes-128-ctr" => decrypt_ctr::<aes::Aes128>(ciphertext, key, nonce, aad, 16),
        "aes192-ctr" | "aes-192-ctr" => decrypt_ctr::<aes::Aes192>(ciphertext, key, nonce, aad, 24),
        "aes256-ctr" | "aes-256-ctr" => decrypt_ctr::<aes::Aes256>(ciphertext, key, nonce, aad, 32),
        "aes128-cbc" | "aes-128-cbc" | "aes192-cbc" | "aes-192-cbc" | "aes256-cbc" | "aes-256-cbc" => {
            if !aad.is_empty() { return Err("CBC does not accept AAD and does not authenticate data".into()); }
            if nonce.len() != 16 { return Err("CBC requires a 16-byte IV".into()); }
            if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
                return Err("CBC ciphertext must be a nonempty multiple of 16 bytes".into());
            }
            let result = if algorithm.contains("128") {
                cbc::Decryptor::<aes::Aes128>::new_from_slices(key, nonce)
                    .map_err(|_| "AES-128-CBC requires a 16-byte key".to_string())?
                    .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            } else if algorithm.contains("192") {
                cbc::Decryptor::<aes::Aes192>::new_from_slices(key, nonce)
                    .map_err(|_| "AES-192-CBC requires a 24-byte key".to_string())?
                    .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            } else {
                cbc::Decryptor::<aes::Aes256>::new_from_slices(key, nonce)
                    .map_err(|_| "AES-256-CBC requires a 32-byte key".to_string())?
                    .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            };
            result.map_err(|_| "CBC decryption failed: invalid PKCS#7 padding or incorrect parameters".into())
        }
        "rsa-oaep-sha256" => {
            if !nonce.is_empty() || !aad.is_empty() {
                return Err("RSA-OAEP-SHA256 does not accept nonce/IV or AAD; only an empty OAEP label is supported".into());
            }
            let pem = std::str::from_utf8(key).map_err(|_| "RSA key must be an unencrypted PKCS#8 or PKCS#1 private PEM".to_string())?;
            let private_key = RsaPrivateKey::from_pkcs8_pem(pem)
                .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
                .map_err(|_| "invalid RSA private PEM; expected unencrypted PKCS#8 or PKCS#1".to_string())?;
            private_key.validate().map_err(|_| "invalid RSA private key".to_string())?;
            if ciphertext.len() != private_key.size() {
                return Err("RSA ciphertext length must equal the key modulus length in bytes".into());
            }
            // Blinding reduces timing leakage, but this offline CLI must not be
            // exposed as a remotely callable RSA decryption service.
            private_key.decrypt_blinded(&mut rsa::rand_core::OsRng, Oaep::new::<Sha256>(), ciphertext)
                .map_err(|_| "RSA-OAEP decryption failed: incorrect key, ciphertext, hash, or label".into())
        }
        _ => Err("unsupported cipher; use aes128-gcm, aes256-gcm, chacha20-poly1305, xchacha20-poly1305, aes128-cbc, aes192-cbc, aes256-cbc, aes128-ctr, aes192-ctr, aes256-ctr, or rsa-oaep-sha256".into()),
    }
}

fn decrypt_ctr<C>(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    key_len: usize,
) -> Result<Vec<u8>, String>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16> + KeyInit,
{
    if !aad.is_empty() {
        return Err("CTR does not accept AAD and does not authenticate data".into());
    }
    if key.len() != key_len {
        return Err(format!("AES-CTR requires a {key_len}-byte key"));
    }
    let initial_counter = u128::from_be_bytes(
        nonce
            .try_into()
            .map_err(|_| "CTR requires a 16-byte initial counter".to_string())?,
    );
    let blocks = ciphertext.len().div_ceil(16);
    // Check the last counter before producing any plaintext. The maximum
    // counter itself can be used once, but must never wrap around to zero.
    if blocks > 0 && initial_counter.checked_add((blocks - 1) as u128).is_none() {
        return Err("CTR counter would overflow; refusing to wrap the 128-bit counter".into());
    }
    let cipher = C::new_from_slice(key).map_err(|_| "invalid AES-CTR key length".to_string())?;
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for (index, chunk) in ciphertext.chunks(16).enumerate() {
        let counter = initial_counter + index as u128;
        let mut keystream = Block::<C>::default();
        keystream.copy_from_slice(&counter.to_be_bytes());
        cipher.encrypt_block(&mut keystream);
        plaintext.extend(
            chunk
                .iter()
                .zip(keystream.iter())
                .map(|(byte, mask)| byte ^ mask),
        );
        keystream.as_mut_slice().zeroize();
    }
    Ok(plaintext)
}

fn decrypt_aead<C: Aead + KeyInit>(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    key_len: usize,
    nonce_len: usize,
) -> Result<Vec<u8>, String> {
    if key.len() != key_len {
        return Err(format!("cipher requires a {key_len}-byte key"));
    }
    if nonce.len() != nonce_len {
        return Err(format!("cipher requires a {nonce_len}-byte nonce"));
    }
    if ciphertext.len() < 16 {
        return Err("AEAD ciphertext must include its trailing 16-byte authentication tag".into());
    }
    let cipher = C::new_from_slice(key).map_err(|_| "invalid cipher key length".to_string())?;
    cipher
        .decrypt(
            aes_gcm::aead::Nonce::<C>::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "authentication failed: incorrect key, nonce, AAD, ciphertext, or tag".into())
}

/// Repeating-key XOR is a classical transformation, not secure encryption.
pub fn xor(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.is_empty() {
        return Err("XOR key must not be empty".into());
    }
    Ok(data
        .iter()
        .zip(key.iter().cycle())
        .map(|(byte, key_byte)| byte ^ key_byte)
        .collect())
}

/// Rotate ASCII letters by `shift`, preserving all other Unicode characters.
/// A positive shift moves A to B; use a negative shift to undo that rotation.
pub fn caesar(text: &str, shift: i32) -> String {
    let shift = shift.rem_euclid(26) as u8;
    text.chars()
        .map(|character| {
            let base = if character.is_ascii_lowercase() {
                b'a'
            } else if character.is_ascii_uppercase() {
                b'A'
            } else {
                return character;
            };
            (base + (character as u8 - base + shift) % 26) as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(input: &str) -> Vec<u8> {
        hex::decode(input).unwrap()
    }

    #[test]
    fn decoders_keep_arbitrary_bytes_and_unicode() {
        assert_eq!(decode("raw", &[0xff, 0, 0x80]).unwrap(), [0xff, 0, 0x80]);
        assert!(decode("text", &[0xff]).is_err());
        assert_eq!(
            decode("text", "مرحبا 🔐".as_bytes()).unwrap(),
            "مرحبا 🔐".as_bytes()
        );
        assert_eq!(decode("hex", b"00fF80").unwrap(), [0, 0xff, 0x80]);
        assert_eq!(decode("base64", b"//8=").unwrap(), [0xff, 0xff]);
        assert_eq!(decode("base64", b"//8").unwrap(), [0xff, 0xff]);
        assert_eq!(decode("base64url", b"__8=").unwrap(), [0xff, 0xff]);
        assert_eq!(decode("base64url", b"__8").unwrap(), [0xff, 0xff]);
        assert_eq!(decode("base32", b"MZXW6===").unwrap(), b"foo");
        assert_eq!(decode("base32", b"MZXW6").unwrap(), b"foo");
        assert_eq!(decode("url", b"%FF%00+%2b").unwrap(), [0xff, 0, b'+', b'+']);
        assert_eq!(
            decode("form", b"%FF%00+%2b").unwrap(),
            [0xff, 0, b' ', b'+']
        );
        assert_eq!(
            decode("url", "مرحبا".as_bytes()).unwrap(),
            "مرحبا".as_bytes()
        );
        assert_eq!(
            decode("binary", b"11111111 00000000\n10000000").unwrap(),
            [255, 0, 128]
        );
        assert_eq!(decode("binary", b"1111111100000000").unwrap(), [255, 0]);
    }

    #[test]
    fn empty_inputs_and_surrounding_ascii_whitespace_are_unambiguous() {
        for format in [
            "raw",
            "text",
            "hex",
            "base64",
            "base64url",
            "base32",
            "url",
            "form",
            "binary",
        ] {
            assert!(decode(format, b"").unwrap().is_empty());
        }
        for format in ["hex", "base64", "base64url", "base32"] {
            assert!(decode(format, b" \r\n\t").unwrap().is_empty());
        }
        assert_eq!(decode("hex", b" 00fF80\r\n").unwrap(), [0, 255, 128]);
        assert_eq!(decode("base64", b"\tZg==\n").unwrap(), b"f");
        assert_eq!(decode("base32", b" MY======\r\n").unwrap(), b"f");
        assert_eq!(decode("text", b" text\n").unwrap(), b" text\n");
        assert_eq!(decode("url", b" +%20\n").unwrap(), b" + \n");
    }

    #[test]
    fn decoders_reject_malformed_input_instead_of_partial_results() {
        for (format, input) in [
            ("hex", "f"),
            ("hex", "GG"),
            ("hex", "00 01"),
            ("base64", "Zh=="),
            ("base64", "Zg="),
            ("base64", "Zg==!"),
            ("base64", "Zg=\n="),
            ("base64", "A"),
            ("base64", "__8="),
            ("base64url", "//8="),
            ("base32", "MZ======"),
            ("base32", "MY="),
            ("base32", "my======"),
            ("url", "%"),
            ("url", "%1"),
            ("url", "%GG"),
            ("binary", "101"),
            ("binary", "0101 0001"),
            ("binary", "0000000x"),
            ("unsupported", "abc"),
        ] {
            assert!(
                decode(format, input.as_bytes()).is_err(),
                "accepted {format}: {input:?}"
            );
        }
    }

    #[test]
    fn aes_gcm_known_answers_and_authenticated_empty_message() {
        // NIST GCM examples: all-zero key, 96-bit nonce, empty AAD.
        let ct = bytes("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf");
        assert_eq!(
            decrypt("aes128-gcm", &ct, &[0; 16], &[0; 12], &[]).unwrap(),
            [0; 16]
        );
        assert_eq!(
            decrypt(
                "aes128-gcm",
                &bytes("58e2fccefa7e3061367f1d57a4e7455a"),
                &[0; 16],
                &[0; 12],
                &[]
            )
            .unwrap(),
            b""
        );
        assert_eq!(
            decrypt(
                "aes256-gcm",
                &bytes("530f8afbc74536b9a963b4f1c4cb738b"),
                &[0; 32],
                &[0; 12],
                &[]
            )
            .unwrap(),
            b""
        );
    }

    #[test]
    fn chacha20_rfc8439_and_xchacha_draft_known_answers() {
        // RFC 8439 section 2.8.2; draft-irtf-cfrg-xchacha-03 A.3.1.
        let key = bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let aad = bytes("50515253c0c1c2c3c4c5c6c7");
        let plain = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ct = bytes(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
        ));
        assert_eq!(
            decrypt(
                "chacha20-poly1305",
                &ct,
                &key,
                &bytes("070000004041424344454647"),
                &aad
            )
            .unwrap(),
            plain
        );
        let ct = bytes(concat!(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
            "21f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49"
        ));
        assert_eq!(
            decrypt(
                "xchacha20-poly1305",
                &ct,
                &key,
                &bytes("404142434445464748494a4b4c4d4e4f5051525354555657"),
                &aad
            )
            .unwrap(),
            plain
        );
    }

    fn exercise_authentication<C: Aead + KeyInit>(algorithm: &str, key: &[u8], nonce: &[u8]) {
        let cipher = C::new_from_slice(key).unwrap();
        let aad = b"authenticated metadata";
        let message = b"\xff\x00binary plaintext";
        let ct = cipher
            .encrypt(
                aes_gcm::aead::Nonce::<C>::from_slice(nonce),
                Payload { msg: message, aad },
            )
            .unwrap();
        assert_eq!(decrypt(algorithm, &ct, key, nonce, aad).unwrap(), message);
        let mut wrong_key = key.to_vec();
        wrong_key[0] ^= 1;
        let mut wrong_nonce = nonce.to_vec();
        wrong_nonce[0] ^= 1;
        assert!(decrypt(algorithm, &ct, &wrong_key, nonce, aad).is_err());
        assert!(decrypt(algorithm, &ct, key, &wrong_nonce, aad).is_err());
        assert!(decrypt(algorithm, &ct, key, nonce, b"changed").is_err());
        for i in 0..ct.len() {
            let mut changed = ct.clone();
            changed[i] ^= 1;
            assert!(decrypt(algorithm, &changed, key, nonce, aad).is_err());
        }
        for truncated in [&ct[..15], &ct[..ct.len() - 1]] {
            assert!(decrypt(algorithm, truncated, key, nonce, aad).is_err());
        }
        assert!(decrypt(algorithm, &ct, &key[..key.len() - 1], nonce, aad).is_err());
        assert!(decrypt(algorithm, &ct, key, &nonce[..nonce.len() - 1], aad).is_err());
    }

    #[test]
    fn every_aead_rejects_tampering_wrong_parameters_and_truncation() {
        exercise_authentication::<Aes128Gcm>("aes128-gcm", &[42; 16], &[24; 12]);
        exercise_authentication::<Aes256Gcm>("aes256-gcm", &[42; 32], &[24; 12]);
        exercise_authentication::<ChaCha20Poly1305>("chacha20-poly1305", &[42; 32], &[24; 12]);
        exercise_authentication::<XChaCha20Poly1305>("xchacha20-poly1305", &[42; 32], &[24; 24]);
    }

    #[test]
    fn aes_ctr_nist_known_answers_and_every_partial_block_length() {
        // NIST SP 800-38A sections F.5.1 through F.5.6:
        // https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf
        let initial_counter = bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plaintext = bytes(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710"
        ));
        for (algorithm, key, ciphertext) in [
            (
                "aes128-ctr",
                "2b7e151628aed2a6abf7158809cf4f3c",
                concat!(
                    "874d6191b620e3261bef6864990db6ce",
                    "9806f66b7970fdff8617187bb9fffdff",
                    "5ae4df3edbd5d35e5b4f09020db03eab",
                    "1e031dda2fbe03d1792170a0f3009cee"
                ),
            ),
            (
                "aes192-ctr",
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                concat!(
                    "1abc932417521ca24f2b0459fe7e6e0b",
                    "090339ec0aa6faefd5ccc2c6f4ce8e94",
                    "1e36b26bd1ebc670d1bd1d665620abf7",
                    "4f78a7f6d29809585a97daec58c6b050"
                ),
            ),
            (
                "aes256-ctr",
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                concat!(
                    "601ec313775789a5b7a7f504bbf3d228",
                    "f443e3ca4d62b59aca84e990cacaf5c5",
                    "2b0930daa23de94ce87017ba2d84988d",
                    "dfc9c58db67aada613c2dd08457941a6"
                ),
            ),
        ] {
            let key = bytes(key);
            let ciphertext = bytes(ciphertext);
            // CTR preserves length and has no padding, including empty input.
            for length in 0..=ciphertext.len() {
                assert_eq!(
                    decrypt(
                        algorithm,
                        &ciphertext[..length],
                        &key,
                        &initial_counter,
                        &[]
                    )
                    .unwrap(),
                    plaintext[..length],
                    "{algorithm}: prefix length {length}"
                );
            }
            assert_eq!(
                decrypt(
                    &algorithm.replace("aes", "AES-"),
                    &ciphertext,
                    &key,
                    &initial_counter,
                    &[]
                )
                .unwrap(),
                plaintext
            );
        }
    }

    #[test]
    fn aes_ctr_validates_key_counter_and_unused_aad() {
        for (algorithm, key_len) in [("aes128-ctr", 16), ("aes192-ctr", 24), ("aes256-ctr", 32)] {
            let key = vec![42; key_len];
            for length in [0, key_len - 1, key_len + 1] {
                assert!(
                    decrypt(algorithm, &[0; 16], &vec![42; length], &[0; 16], &[])
                        .unwrap_err()
                        .contains("key")
                );
            }
            for length in [0, 12, 15, 17, 24] {
                assert!(decrypt(algorithm, &[0; 16], &key, &vec![0; length], &[])
                    .unwrap_err()
                    .contains("16-byte initial counter"));
            }
            assert!(decrypt(algorithm, &[0; 16], &key, &[0; 16], b"unused")
                .unwrap_err()
                .contains("does not accept AAD"));
            // CTR has no authentication: arbitrary ciphertext and keys of the
            // right size produce bytes, and cannot report incorrect parameters.
            assert_eq!(
                decrypt(algorithm, &[0xff; 17], &key, &[0; 16], &[])
                    .unwrap()
                    .len(),
                17
            );
            // Even empty input does not bypass parameter validation.
            assert!(decrypt(algorithm, &[], &[], &[0; 16], &[]).is_err());
            assert!(decrypt(algorithm, &[], &key, &[], &[]).is_err());
        }
    }

    #[test]
    fn aes_ctr_carries_across_64_bits_and_accepts_final_counter_once() {
        // Independent OpenSSL AES-128-CTR fixtures: key/plaintext bytes 00,01,...
        let key: Vec<u8> = (0..16).collect();
        let plaintext: Vec<u8> = (0..32).collect();
        for (initial_counter, ciphertext) in [
            (
                "0000000000000000ffffffffffffffff",
                "39a6ed090e5d54afb7db092848b29a1d03098879f0be11b968bab0a62ca387c1",
            ),
            (
                "fffffffffffffffffffffffffffffffe",
                "b6b4c0db298ed208c747d2ffa26399e12c550d21da1294347cceb882124da50c",
            ),
        ] {
            assert_eq!(
                decrypt(
                    "aes128-ctr",
                    &bytes(ciphertext),
                    &key,
                    &bytes(initial_counter),
                    &[]
                )
                .unwrap(),
                plaintext
            );
        }
        for (algorithm, key_len) in [("aes128-ctr", 16), ("aes192-ctr", 24), ("aes256-ctr", 32)] {
            let key = vec![0; key_len];
            for length in [0, 1, 15, 16] {
                assert_eq!(
                    decrypt(algorithm, &vec![0; length], &key, &[0xff; 16], &[])
                        .unwrap()
                        .len(),
                    length
                );
            }
            for length in [17, 32, 33] {
                assert!(decrypt(algorithm, &vec![0; length], &key, &[0xff; 16], &[])
                    .unwrap_err()
                    .contains("overflow"));
            }
            let penultimate = (u128::MAX - 1).to_be_bytes();
            assert_eq!(
                decrypt(algorithm, &[0; 32], &key, &penultimate, &[])
                    .unwrap()
                    .len(),
                32
            );
            assert!(decrypt(algorithm, &[0; 33], &key, &penultimate, &[])
                .unwrap_err()
                .contains("overflow"));
        }
    }

    #[test]
    fn aes192_cbc_openssl_fixtures_and_validation() {
        // Independently generated using openssl enc -aes-192-cbc with PKCS#7.
        let key: Vec<u8> = (0..24).collect();
        let iv: Vec<u8> = (0..16).collect();
        for (ciphertext, plaintext) in [
            ("93ae3b7f9fc2e8159d05a6a9f5e24f2d", b"".as_slice()),
            (
                "6434795a3a81c4aea3bb5b68d0ea0f5356567aff5bc53323a1bfc04bac53e4de03e7a49df3dc4bc6d267002bfcaac3dd",
                b"IQAWX AES-192-CBC\x00\xff\x80 interoperability".as_slice(),
            ),
        ] {
            let ciphertext = bytes(ciphertext);
            assert_eq!(decrypt("aes192-cbc", &ciphertext, &key, &iv, &[]).unwrap(), plaintext);
            assert_eq!(decrypt("AES-192-CBC", &ciphertext, &key, &iv, &[]).unwrap(), plaintext);
            for length in [16, 23, 25, 32] {
                assert!(decrypt("aes192-cbc", &ciphertext, &vec![0; length], &iv, &[])
                    .unwrap_err().contains("24-byte key"));
            }
            assert!(decrypt("aes192-cbc", &ciphertext, &key, &iv[..15], &[]).is_err());
            assert!(decrypt("aes192-cbc", &ciphertext, &key, &iv, b"unused").is_err());
            assert!(decrypt("aes192-cbc", &ciphertext[..ciphertext.len() - 1], &key, &iv, &[]).is_err());
        }
    }

    #[test]
    fn cbc_pkcs7_known_answer_and_invalid_padding() {
        // Published RustCrypto cbc 0.1.2 example vector.
        let ct = bytes("c7fe247ef97b21f07cbdd26cb5d346bf d27867cb00d9486723e159978fb9a5f9 14cfb228a710de4171e396e7b6cf859e".replace(' ', "").as_str());
        assert_eq!(
            decrypt("aes128-cbc", &ct, &[0x42; 16], &[0x24; 16], &[]).unwrap(),
            b"hello world! this is my plaintext."
        );
        // Corrupt a byte of the final block's known padding through the prior block.
        let mut bad = ct.clone();
        bad[31] ^= 1;
        assert!(decrypt("aes128-cbc", &bad, &[0x42; 16], &[0x24; 16], &[]).is_err());
        assert!(decrypt("aes128-cbc", &ct, &[0x42; 16], &[0x24; 16], b"unused").is_err());
        assert!(decrypt("aes128-cbc", &ct[..31], &[0x42; 16], &[0x24; 16], &[]).is_err());
        assert!(decrypt("aes128-cbc", &[], &[0x42; 16], &[0x24; 16], &[]).is_err());
        assert!(decrypt("aes128-cbc", &ct, &[0x42; 15], &[0x24; 16], &[]).is_err());
        assert!(decrypt("aes128-cbc", &ct, &[0x42; 16], &[0x24; 15], &[]).is_err());
    }

    #[test]
    fn aes256_cbc_preserves_binary_and_handles_empty_plaintext() {
        use aes::cipher::BlockEncryptMut;
        for plaintext in [b"".as_slice(), b"\x00\xff\x80arbitrary bytes".as_slice()] {
            let ct = cbc::Encryptor::<aes::Aes256>::new_from_slices(&[7; 32], &[9; 16])
                .unwrap()
                .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
            assert_eq!(
                decrypt("aes256-cbc", &ct, &[7; 32], &[9; 16], &[]).unwrap(),
                plaintext
            );
        }
    }

    #[test]
    fn caesar_preserves_unicode_case_and_extreme_shifts() {
        assert_eq!(caesar("Az zZ مرحباً 🔐 é", 1), "Ba aA مرحباً 🔐 é");
        assert_eq!(caesar("Ba aA مرحباً 🔐 é", -1), "Az zZ مرحباً 🔐 é");
        assert_eq!(caesar("Hello", 26), "Hello");
        assert_eq!(
            caesar("Hello", i32::MIN),
            caesar("Hello", i32::MIN.rem_euclid(26))
        );
        assert_eq!(
            caesar("Hello", i32::MAX),
            caesar("Hello", i32::MAX.rem_euclid(26))
        );
    }

    #[test]
    fn xor_repeats_key_preserves_binary_and_rejects_empty_key() {
        let original = b"\x00\xff\x80rust";
        let encoded = xor(original, &[0xff, 0x42]).unwrap();
        assert_eq!(xor(&encoded, &[0xff, 0x42]).unwrap(), original);
        assert_eq!(xor(&[0, 255, 128], &[255]).unwrap(), [255, 0, 127]);
        assert!(xor(original, &[]).is_err());
        assert_eq!(xor(&[], &[1]).unwrap(), b"");
    }

    #[test]
    fn rsa_rejects_unused_args_and_malformed_pem() {
        assert!(decrypt("rsa-oaep-sha256", &[0; 256], b"bad PEM", &[], &[]).is_err());
        assert!(decrypt("rsa-oaep-sha256", &[0; 256], &[0xff], &[], &[]).is_err());
        assert!(decrypt("rsa-oaep-sha256", &[0; 256], b"bad PEM", &[0], &[])
            .unwrap_err()
            .contains("does not accept"));
        assert!(decrypt("rsa-oaep-sha256", &[0; 256], b"bad PEM", &[], &[0])
            .unwrap_err()
            .contains("does not accept"));
        assert!(decrypt("magic", &[], &[], &[], &[]).is_err());
    }

    #[test]
    fn rsa_openssl_fixture_pkcs8_pkcs1_and_corrupted_ciphertext() {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        // Disposable test key and ciphertext generated independently by OpenSSL.
        // OAEP SHA-256 and MGF1 SHA-256, with an empty label.
        const PRIVATE_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDDnlxeV9MOeqbj
Nv/CZpFCH9uqJev02etZh6ImKK6VCju7zTQ/mAVSG1MegDQNGaJPdKcDlLEEip+A
r1yOqR/vRvsTc0CQ9D5UyE2nKqTMUsfBRW1Tt0RTlubC0J/dCu1n/UHNrd34xjQ9
8KQs5PsRRJq+kAXDTxtcC5yfISu28wa8/7z78qAHz22XfhYwvmwABMHB9gvM4/m1
Yag8QPrh4t9FRUHZkR0k1oL+cUPA6R46W5pAF6pDoIIUltEQAiAQPdqc/l5Xed32
2yH9AZKYTpfqNIoC1OkB61B/CkGJB4O/s5CEBjOYLBS9NNgeyb6MbwpzFMHaQI20
sZIfAVGzAgMBAAECggEARPfWVSTdsqMnp8BCWAXVfNzCk7CfCkqyoXQihRWex8k9
2i61Fx6/8XzUx1IoB95bzWuxXp/T8Wf2aGZrWZjjO3dpGihuQSz7tOSSDDgKtkcR
SmDx9KwOmPIBFfp8AnDR1vIBe0SrmAQ5cwUevP1WT3ZCoKEihwOi/8bQR4JoaS2U
CGmSsrKnuyIbVdum9Z12LnwDy7r7paXxwtRFU+lCKsL4wSO00uqKDIk9PrvY7WHL
oL69av1IB4xg3YDZFGxFLa71tTMISaOBAkm/oeoRMRXC7t97ZmCJ3930DwvDpx4z
xe4mSYpZOizCGzC+w4SJyMkXUx4zTdW1a9zRm8IkUQKBgQDi+XlYIF8iXWSi4RYA
ZR3JtYDIpumfjlqJ2a1bxo2Q8ADjzMByTOggcTAc55Ncm2A5c52KKcBh/bS+uoHg
FUB/6CvnKdADR5T+h+rKeqwOC+P1ehkMs4zkT/oDftdM7LE8SlmWt/RKuBgXTGDv
bQG7R33WMixAM+uKCc7RSa+mrQKBgQDcomE+XW79nNXsl/jAI0hmazKPCNj6JFPd
F58GR+/AUcXvSEB+6Cke1iMLTiQKAsglS+9A4kKYz5xiyQ5U4RThZHOAIlDLzGDu
s/ojCnsQiOH7OJKtqWEkwRnf0EWJ+Rhbk7tiGg/LzBdPihn5tZ9b9MMc2gIeBgvx
adjgVizF3wKBgQDaM7OwQQ60XsyMuY8JOix06gSw4aXfOl9X/uhmPm+CUvjIBuNL
/xt5dNcoMoi8krLjCH7/gDvu+JR2d5676jJjxLPQO6Y6QOq/97KEjYIyzsOMDqFe
UI62Pxy/l4Ur8rBAocmW16oG2wxt+YOHKWhsvsH+1aUs470gq2UkVo6C0QKBgAx8
kB5UcVyfDKhYLXbKSGWreXAI4ya8+ZYQqSpU1ee/eQFCyIumHfWlztPr9zQt1h/u
PTsh0v0M+t/IWyxIlMLwyWyeBI6UIYRA4U4sYKyd4pQyLnLvnBTVbN5yzgyx8UP1
h2xU50H0aflRaojsU3mDz6sJV4dVdkWSZPjFR8FnAoGATtt6RcxnXUxKt7vgKThu
oW5own2+iflsQDOM4/mL2TSLAWjopi4mFcWM8aCmQgCTBPrPGL5mySyFGY/XgOXN
UEdJxx1BP9K8alNfxwJnJaGKNjqC0K1XSwz3mr7RJ90WCD855FtDS/O8Id9KlFlI
wdNkQ4HGNYp9dbeHNdpU/qQ=
-----END PRIVATE KEY-----
"#;
        let ct = bytes("38588ba5d6ae3e446ff0fc0896466e8f39d151272bd9f1ee44e92bf4135335cded272bdaf304662f7ece0d49f579498e4d1b6cac873096b117b1d6038e3b36bcb793e694acf5cde42249bad6442338f84f728adf6ef4a31b3f1add33da39d03e871a69549ee207652f942adca29f71cc7485adab052a4cc87a3ed36369553c6485a18bba3643a946308d63df2ed21b2ff3dac382c3ce71b1900d5b61f7e4a01ce7b4d7c354551c51b5b23ac6bda8d4ddbd49587a89caf826e5a54675311303bebf179730d4045a7928a2f659b586ab699e0cae805e8dc4d2ea696e7dd62b9e8495c232c1fd7b77eacfc89524204fe853ae005f24d8b9b4f3c8918c3de0135269");
        let expected = b"IQAWX RSA interoperability\x00\xff";
        assert_eq!(
            decrypt("rsa-oaep-sha256", &ct, PRIVATE_PEM.as_bytes(), &[], &[]).unwrap(),
            expected
        );
        let key = RsaPrivateKey::from_pkcs8_pem(PRIVATE_PEM).unwrap();
        let pkcs1 = key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
        assert_eq!(
            decrypt("rsa-oaep-sha256", &ct, pkcs1.as_bytes(), &[], &[]).unwrap(),
            expected
        );
        let mut corrupted = ct.clone();
        corrupted[0] ^= 1;
        assert!(decrypt(
            "rsa-oaep-sha256",
            &corrupted,
            PRIVATE_PEM.as_bytes(),
            &[],
            &[]
        )
        .is_err());
        assert!(decrypt(
            "rsa-oaep-sha256",
            &ct[..ct.len() - 1],
            PRIVATE_PEM.as_bytes(),
            &[],
            &[]
        )
        .is_err());
    }
}
