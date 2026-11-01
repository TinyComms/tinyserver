//! The sealed attachment blob, as tinyclient's `crates/e2ee` makes it (`attachment.rs`):
//!
//! ```text
//! "TNYA1" || log2(chunk size) = 16 || nonce prefix (7 random bytes) || chunk_0 || ... || chunk_n
//! ```
//!
//! Each chunk is AES-256-GCM in RustCrypto's STREAM (`EncryptorBE32`) over up to 64 KiB of the
//! file; all but the last are full. The first chunk's associated data is the header followed by
//! the caller's context (the conversation id and the attachment id, 16 bytes each); the others
//! have none. Here so the tests upload real sealed blobs, and open what they download.

#![allow(dead_code)]

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::aead::{KeyInit, Payload};
use aes_gcm::Aes256Gcm;

const CHUNK: usize = 64 * 1024;
const HEADER: usize = 13;

/// The associated data context a client binds a blob to: the conversation id and then the
/// attachment id, as their 16 bytes each.
pub fn context(conversation: &[u8; 16], attachment: &[u8; 16]) -> Vec<u8> {
    [conversation.as_slice(), attachment.as_slice()].concat()
}

/// Seals `plain` with `key`, binding the first chunk to `context`.
pub fn seal(key: &[u8; 32], context: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut prefix = [0u8; 7];
    getrandom::fill(&mut prefix).expect("random");
    let mut out = b"TNYA1".to_vec();
    out.push(16);
    out.extend_from_slice(&prefix);
    let first_aad = [out.as_slice(), context].concat();
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let mut encryptor = EncryptorBE32::from_aead(cipher, GenericArray::from_slice(&prefix));
    let chunks: Vec<&[u8]> = if plain.is_empty() {
        vec![&[]]
    } else {
        plain.chunks(CHUNK).collect()
    };
    let last = chunks.len() - 1;
    for (index, chunk) in chunks.iter().enumerate() {
        let aad: &[u8] = if index == 0 { &first_aad } else { &[] };
        let payload = Payload { msg: chunk, aad };
        if index == last {
            out.extend(encryptor.encrypt_last(payload).expect("seal"));
            break;
        }
        out.extend(encryptor.encrypt_next(payload).expect("seal"));
    }
    out
}

/// Opens a blob `seal` made, or `None` if any check fails.
pub fn open(key: &[u8; 32], context: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < HEADER || &blob[..5] != b"TNYA1" || blob[5] != 16 {
        return None;
    }
    let header = &blob[..HEADER];
    let first_aad = [header, context].concat();
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let mut decryptor = DecryptorBE32::from_aead(cipher, GenericArray::from_slice(&blob[6..13]));
    let chunks: Vec<&[u8]> = blob[HEADER..].chunks(CHUNK + 16).collect();
    let last = chunks.len().checked_sub(1)?;
    let mut out = Vec::new();
    for (index, chunk) in chunks.iter().enumerate() {
        let aad: &[u8] = if index == 0 { &first_aad } else { &[] };
        let payload = Payload { msg: chunk, aad };
        if index == last {
            out.extend(decryptor.decrypt_last(payload).ok()?);
            break;
        }
        out.extend(decryptor.decrypt_next(payload).ok()?);
    }
    Some(out)
}

/// Bytes with the shape of a sealed blob and nothing inside: the header, then `body` as if it
/// were one chunk's ciphertext, then a tag of zeros. For tests of size, rate and storage, where
/// what is inside does not matter.
pub fn framed(body: &[u8]) -> Vec<u8> {
    assert!(body.len() <= CHUNK, "one chunk only");
    let mut out = b"TNYA1".to_vec();
    out.push(16);
    out.extend_from_slice(&[0x5a; 7]);
    out.extend_from_slice(body);
    out.extend_from_slice(&[0; 16]);
    out
}
