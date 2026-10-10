//! Byte-preserving inspection and deliberately limited classical-cipher heuristics.
//!
//! Scores rank guesses; they do not identify a cipher or prove a key is correct.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};

const SAMPLE_BYTES: usize = 4096;
const MAX_STRINGS: usize = 128;
const MAX_STRING_BYTES: usize = 256;
pub const MAX_LAYER_INPUT_BYTES: usize = 1_048_576;
const SCORE_CAVEAT: &str = "Heuristic ranking only, not a probability or proof of decryption. Short, binary, compressed, and non-English inputs can yield false positives. Identity is included because the input may already be plaintext.";
const LAYER_CAVEAT: &str =
    "A syntactically possible decoding chain, not confirmed format detection or decryption.";

#[derive(Debug, Serialize)]
pub struct AnalysisReport {
    pub size_bytes: usize,
    pub sha256: String,
    pub crc32_hex: String,
    pub file_type_hint: String,
    pub entropy_bits_per_byte: f64,
    pub ascii_printable_fraction: f64,
    pub unicode: UnicodeInfo,
    pub input_preview_hex: String,
    pub input_preview_utf8: Option<String>,
    pub input_preview_bytes: usize,
    pub input_preview_truncated: bool,
    pub ascii_strings: Vec<ExtractedString>,
    pub ascii_strings_truncated: bool,
    pub candidate_sample_bytes: usize,
    pub candidates_sampled: bool,
    pub candidate_score_caveat: String,
    pub candidates: Vec<HeuristicCandidate>,
}

#[derive(Debug, Serialize)]
pub struct UnicodeInfo {
    pub valid_utf8: bool,
    pub first_invalid_byte: Option<usize>,
    pub scalar_count: Option<usize>,
    pub non_ascii_scalars: Option<usize>,
    pub control_scalars: Option<usize>,
    pub replacement_scalars: Option<usize>,
    pub has_utf8_bom: bool,
    pub utf16_bom_hint: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExtractedString {
    pub offset: usize,
    pub length_bytes: usize,
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct HeuristicCandidate {
    pub method: String,
    pub key: Option<String>,
    pub heuristic_score: f64,
    pub output_hex: String,
    /// Exact UTF-8 only. Invalid sequences are never replaced with spaces or U+FFFD.
    pub text: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LayerCandidate {
    pub chain: Vec<String>,
    pub output_hex: String,
    pub text: Option<String>,
    pub caveat: String,
}

pub fn analyze(data: &[u8], top: usize) -> AnalysisReport {
    let utf8 = std::str::from_utf8(data);
    let (scalar_count, non_ascii_scalars, control_scalars, replacement_scalars) =
        match utf8.as_ref() {
            Ok(text) => {
                let mut counts = [0usize; 4];
                for c in text.chars() {
                    counts[0] += 1;
                    counts[1] += usize::from(!c.is_ascii());
                    counts[2] += usize::from(c.is_control());
                    counts[3] += usize::from(c == '\u{fffd}');
                }
                (
                    Some(counts[0]),
                    Some(counts[1]),
                    Some(counts[2]),
                    Some(counts[3]),
                )
            }
            Err(_) => (None, None, None, None),
        };
    // Keep hex and UTF-8 previews aligned, including when a multibyte character
    // crosses the byte limit. Cipher candidate scoring uses a separate byte sample.
    let mut preview_len = data.len().min(SAMPLE_BYTES);
    if let Ok(text) = utf8.as_ref() {
        while !text.is_char_boundary(preview_len) {
            preview_len -= 1;
        }
    }
    let preview = &data[..preview_len];
    let sample = &data[..data.len().min(SAMPLE_BYTES)];
    let (ascii_strings, ascii_strings_truncated) = extract_ascii_strings(data);
    AnalysisReport {
        size_bytes: data.len(),
        sha256: hex::encode(Sha256::digest(data)),
        crc32_hex: format!("{:08x}", crc32(data)),
        file_type_hint: file_type_hint(data).to_owned(),
        entropy_bits_per_byte: byte_entropy(data),
        ascii_printable_fraction: fraction(
            data.iter().filter(|&&b| ascii_readable(b)).count(),
            data.len(),
        ),
        unicode: UnicodeInfo {
            valid_utf8: utf8.is_ok(),
            first_invalid_byte: utf8.as_ref().err().map(|e| e.valid_up_to()),
            scalar_count,
            non_ascii_scalars,
            control_scalars,
            replacement_scalars,
            has_utf8_bom: data.starts_with(&[0xef, 0xbb, 0xbf]),
            utf16_bom_hint: if data.starts_with(&[0xff, 0xfe]) {
                Some("UTF-16 little-endian BOM; content not validated".to_owned())
            } else if data.starts_with(&[0xfe, 0xff]) {
                Some("UTF-16 big-endian BOM; content not validated".to_owned())
            } else {
                None
            },
        },
        input_preview_hex: hex::encode(preview),
        input_preview_utf8: std::str::from_utf8(preview).ok().map(str::to_owned),
        input_preview_bytes: preview_len,
        input_preview_truncated: preview_len < data.len(),
        ascii_strings,
        ascii_strings_truncated,
        candidate_sample_bytes: sample.len(),
        candidates_sampled: sample.len() < data.len(),
        candidate_score_caveat: SCORE_CAVEAT.to_owned(),
        candidates: rank_candidates(sample, top.min(20)),
    }
}

fn fraction(n: usize, d: usize) -> f64 {
    if d == 0 {
        0.0
    } else {
        n as f64 / d as f64
    }
}

fn ascii_readable(b: u8) -> bool {
    (b' '..=b'~').contains(&b) || matches!(b, b'\n' | b'\r' | b'\t')
}

fn byte_entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    counts
        .iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = fraction(n, data.len());
            -p * p.log2()
        })
        .sum()
}

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, item) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb88320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *item = c;
    }
    let mut crc = !0u32;
    for &b in data {
        crc = table[((crc ^ u32::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

fn file_type_hint(data: &[u8]) -> &'static str {
    const SIGNATURES: &[(&[u8], &str)] = &[
        (b"\x89PNG\r\n\x1a\n", "PNG image signature"),
        (b"\xff\xd8\xff", "JPEG image signature"),
        (b"GIF87a", "GIF image signature"),
        (b"GIF89a", "GIF image signature"),
        (b"%PDF", "PDF document signature"),
        (
            b"PK\x03\x04",
            "ZIP signature (also used by DOCX/XLSX/JAR/APK)",
        ),
        (b"PK\x05\x06", "ZIP empty archive signature"),
        (b"\x7fELF", "ELF executable signature"),
        (b"MZ", "DOS/PE executable signature"),
        (b"\x1f\x8b", "GZIP archive signature"),
        (b"BM", "BMP image signature"),
        (b"Rar!\x1a\x07", "RAR archive signature"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive signature"),
        (b"\xfd7zXZ\0", "XZ archive signature"),
        (b"BZh", "BZIP2 archive signature"),
        (b"SQLite format 3\0", "SQLite database signature"),
        (b"\0asm", "WebAssembly signature"),
    ];
    SIGNATURES
        .iter()
        .find(|(sig, _)| data.starts_with(sig))
        .map(|(_, name)| *name)
        .unwrap_or("No recognized file signature")
}

fn extract_ascii_strings(data: &[u8]) -> (Vec<ExtractedString>, bool) {
    let mut result = Vec::new();
    let mut truncated = false;
    let mut start = 0usize;
    while start < data.len() {
        if !(b' '..=b'~').contains(&data[start]) {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < data.len() && (b' '..=b'~').contains(&data[end]) {
            end += 1;
        }
        if end - start >= 4 {
            if result.len() >= MAX_STRINGS {
                truncated = true;
                break;
            }
            let shown_end = end.min(start + MAX_STRING_BYTES);
            result.push(ExtractedString {
                offset: start,
                length_bytes: end - start,
                // All bytes are ASCII by the loop predicate.
                text: String::from_utf8(data[start..shown_end].to_vec()).expect("ASCII string"),
                truncated: shown_end < end,
            });
            truncated |= shown_end < end;
        }
        start = end;
    }
    (result, truncated)
}

fn rank_candidates(data: &[u8], top: usize) -> Vec<HeuristicCandidate> {
    if data.is_empty() || top == 0 {
        return Vec::new();
    }
    let mut guesses: Vec<(f64, &'static str, Option<String>, Vec<u8>)> = Vec::new();
    let mut seen = HashSet::new();
    let mut add = |method, key, out: Vec<u8>| {
        if seen.insert(out.clone()) {
            guesses.push((plaintext_score(&out), method, key, out));
        }
    };
    add("identity", None, data.to_vec());
    for key in 1u16..=255 {
        add(
            "xor-single-byte",
            Some(format!("0x{key:02x}")),
            data.iter().map(|b| b ^ key as u8).collect(),
        );
    }
    for key in 0u16..=255 {
        add(
            "xor-rolling-key-xor-position",
            Some(format!("0x{key:02x}")),
            data.iter()
                .enumerate()
                .map(|(i, b)| b ^ key as u8 ^ i as u8)
                .collect(),
        );
    }
    for shift in 1u8..=25 {
        add(
            "caesar-shift-forward",
            Some(shift.to_string()),
            data.iter()
                .map(|&b| {
                    if b.is_ascii_lowercase() {
                        b'a' + (b - b'a' + shift) % 26
                    } else if b.is_ascii_uppercase() {
                        b'A' + (b - b'A' + shift) % 26
                    } else {
                        b
                    }
                })
                .collect(),
        );
    }
    guesses.sort_by(|a, b| b.0.total_cmp(&a.0));
    guesses
        .into_iter()
        .take(top)
        .map(|(score, method, key, out)| HeuristicCandidate {
            method: method.to_owned(),
            key,
            heuristic_score: (score * 1000.0).round() / 1000.0,
            output_hex: hex::encode(&out),
            text: String::from_utf8(out).ok(),
        })
        .collect()
}

fn plaintext_score(data: &[u8]) -> f64 {
    let printable = fraction(
        data.iter().filter(|&&b| ascii_readable(b)).count(),
        data.len(),
    );
    let mut score = 30.0 * printable;
    let Ok(text) = std::str::from_utf8(data) else {
        return score - 35.0;
    };
    let count = text.chars().count();
    let readable = text
        .chars()
        .filter(|&c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .count();
    score += 30.0 * fraction(readable, count);
    score -= 70.0 * fraction(count - readable, count);
    score += 15.0 * fraction(text.chars().filter(|c| c.is_alphabetic()).count(), count);
    // Approximate English symbol likelihood. It deliberately does not pretend to
    // recognize every language, and no keyword alone can mark a candidate correct.
    const FREQ: [f64; 26] = [
        8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41, 6.75, 7.51,
        1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07,
    ];
    let mut likelihood = 0.0;
    let mut ascii_count = 0usize;
    for &b in data {
        if !b.is_ascii() {
            continue;
        }
        ascii_count += 1;
        let probability = if b.is_ascii_alphabetic() {
            FREQ[(b.to_ascii_lowercase() - b'a') as usize] / 100.0 * 0.70
        } else if b == b' ' {
            0.18
        } else if b.is_ascii_digit() {
            0.004
        } else if matches!(
            b,
            b'.' | b',' | b'\'' | b'"' | b'!' | b'?' | b':' | b';' | b'\n'
        ) {
            0.005
        } else {
            0.0001
        };
        likelihood += probability.ln();
    }
    if ascii_count > 0 {
        score += 5.0 * (likelihood / ascii_count as f64 + 4.0);
    }
    let mut words = 0usize;
    let mut common = 0usize;
    for word in text
        .split(|c: char| !c.is_alphabetic())
        .filter(|s| !s.is_empty())
    {
        words += 1;
        if matches!(
            word.to_ascii_lowercase().as_str(),
            "the"
                | "and"
                | "this"
                | "that"
                | "with"
                | "for"
                | "is"
                | "are"
                | "to"
                | "of"
                | "in"
                | "it"
                | "you"
                | "a"
                | "an"
                | "hello"
                | "world"
                | "test"
                | "message"
                | "text"
                | "we"
                | "have"
                | "not"
                | "from"
                | "be"
        ) {
            common += 1;
        }
    }
    score += 12.0 * fraction(common, words);
    let upper = data.iter().filter(|b| b.is_ascii_uppercase()).count();
    score -= 3.0 * fraction(upper, data.len());
    score
}

/// Explore at most 64 distinct byte sequences (including input) and five layers.
/// Inputs above 1 MiB
/// return no candidates; callers should report MAX_LAYER_INPUT_BYTES explicitly.
/// Every returned byte sequence is complete: this function never samples input.
pub fn decode_layers(data: &[u8], max_depth: usize) -> Vec<LayerCandidate> {
    if data.is_empty() || data.len() > MAX_LAYER_INPUT_BYTES || max_depth == 0 {
        return Vec::new();
    }
    let mut seen = HashSet::new();
    seen.insert(data.to_vec());
    let mut queue = VecDeque::from([(data.to_vec(), Vec::<String>::new())]);
    let mut results = Vec::new();
    while let Some((bytes, chain)) = queue.pop_front() {
        if chain.len() >= max_depth.min(5) {
            continue;
        }
        for format in [
            "hex",
            "base64",
            "base64url",
            "base32",
            "url",
            "form",
            "binary",
        ] {
            if !plausible_encoding(format, &bytes) {
                continue;
            }
            let Ok(decoded) = crate::crypto::decode(format, &bytes) else {
                continue;
            };
            if decoded.is_empty() || decoded == bytes || !seen.insert(decoded.clone()) {
                continue;
            }
            let mut next_chain = chain.clone();
            next_chain.push(format.to_owned());
            results.push(LayerCandidate {
                chain: next_chain.clone(),
                output_hex: hex::encode(&decoded),
                text: std::str::from_utf8(&decoded).ok().map(str::to_owned),
                caveat: LAYER_CAVEAT.to_owned(),
            });
            if seen.len() >= 64 {
                return results;
            }
            queue.push_back((decoded, next_chain));
        }
    }
    results
}

fn plausible_encoding(format: &str, data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    if matches!(format, "url" | "form") {
        return data
            .windows(3)
            .any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
            || (format == "form" && data.contains(&b'+'));
    }
    let compact: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    match format {
        "hex" => {
            compact.len() >= 2
                && compact.len().is_multiple_of(2)
                && compact.iter().all(u8::is_ascii_hexdigit)
        }
        "base64" | "base64url" => {
            compact.len() >= 2
                && compact.len() % 4 != 1
                && compact.iter().all(|&b| {
                    b.is_ascii_alphanumeric()
                        || b == b'='
                        || (format == "base64" && matches!(b, b'+' | b'/'))
                        || (format == "base64url" && matches!(b, b'-' | b'_'))
                })
        }
        "base32" => {
            compact.len() >= 2
                && compact
                    .iter()
                    .all(|&b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b) || b == b'=')
        }
        "binary" => {
            compact.len() >= 8
                && compact.len().is_multiple_of(8)
                && compact.iter().all(|&b| b == b'0' || b == b'1')
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_crc_entropy_and_file_signatures() {
        assert_eq!(crc32(b"123456789"), 0xcbf43926);
        assert_eq!(crc32(b""), 0);
        assert_eq!(byte_entropy(&[7; 100]), 0.0);
        let all_bytes: Vec<u8> = (0..=255).collect();
        assert!((byte_entropy(&all_bytes) - 8.0).abs() < 1e-10);
        assert_eq!(
            file_type_hint(b"\x89PNG\r\n\x1a\nabc"),
            "PNG image signature"
        );
        assert_eq!(file_type_hint(b"MZexample"), "DOS/PE executable signature");
        assert_eq!(
            file_type_hint(b"ordinary text"),
            "No recognized file signature"
        );
    }

    #[test]
    fn exact_unicode_and_invalid_binary_are_preserved() {
        let text = "مرحبا بالعالم 🌍\nUnicode stays intact.";
        let report = analyze(text.as_bytes(), 3);
        assert_eq!(report.input_preview_utf8.as_deref(), Some(text));
        assert_eq!(
            hex::decode(report.input_preview_hex).unwrap(),
            text.as_bytes()
        );
        assert!(report.unicode.non_ascii_scalars.unwrap() > 0);
        let raw = [0xff, 0x00, b'a', b'b', b'c', b'd', 0x80];
        let report = analyze(&raw, 20);
        assert!(!report.unicode.valid_utf8);
        assert_eq!(report.input_preview_utf8, None);
        assert_eq!(hex::decode(report.input_preview_hex).unwrap(), raw);
        assert_eq!(report.ascii_strings[0].offset, 2);
        for candidate in report.candidates {
            let bytes = hex::decode(candidate.output_hex).unwrap();
            assert_eq!(candidate.text, String::from_utf8(bytes).ok());
        }
    }

    #[test]
    fn xor_ranking_finds_known_sentence_but_is_not_a_success_claim() {
        let plain = b"This is a test message with the words that we have in the world.";
        let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0x73).collect();
        let report = analyze(&cipher, 5);
        assert!(report.candidate_score_caveat.contains("false positives"));
        assert_eq!(report.candidates[0].method, "xor-single-byte");
        assert_eq!(report.candidates[0].key.as_deref(), Some("0x73"));
        assert_eq!(
            report.candidates[0].text.as_deref(),
            std::str::from_utf8(plain).ok()
        );
        let rolling: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ 0xa9 ^ i as u8)
            .collect();
        assert_eq!(
            analyze(&rolling, 1).candidates[0].text.as_deref(),
            std::str::from_utf8(plain).ok()
        );
    }

    #[test]
    fn analysis_sampling_and_top_are_explicitly_bounded() {
        let text = "a".repeat(4095) + "ع";
        let report = analyze(text.as_bytes(), 900);
        assert_eq!(report.candidate_sample_bytes, 4096);
        assert!(report.candidates_sampled);
        assert_eq!(report.input_preview_bytes, 4095);
        assert!(report.input_preview_truncated);
        assert!(report.input_preview_utf8.is_some());
        assert_eq!(report.candidates.len(), 20);
    }

    #[test]
    fn layered_base64_and_hex_preserve_the_final_bytes() {
        let candidates = decode_layers(b"Njg2OTIwZmY=", 5);
        let decoded = candidates
            .iter()
            .find(|c| c.chain == ["base64", "hex"])
            .unwrap();
        assert_eq!(decoded.output_hex, "686920ff");
        assert!(decoded.text.is_none());
        assert!(candidates.len() <= 64);
        assert!(candidates.iter().all(|c| c.chain.len() <= 5));
        assert!(decode_layers(b"unchanged plain text!", 5).is_empty());
        assert!(decode_layers(b"Njg2OTIwZmY=", 0).is_empty());
    }

    #[test]
    fn layer_exploration_accepts_short_canonical_encodings() {
        for encoded in ["SGk=", "SGk", "JBUQ"] {
            let candidates = decode_layers(encoded.as_bytes(), 1);
            assert!(
                candidates
                    .iter()
                    .any(|candidate| candidate.text.as_deref() == Some("Hi")),
                "{encoded}"
            );
        }
    }
}
