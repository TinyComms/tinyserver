//! Signed media URLs: HMAC-SHA256 query `ex`/`is`/`hm` beside Bearer.

use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// 32-byte key as lowercase hex. Unit tests pass it to `mint`/`verify`; the HTTP
/// harness sets `TINYSERVER_MEDIA_HMAC_SECRET` to the same value.
pub const TEST_SECRET_HEX: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const TTL_SECS: i64 = 86_400;
const BLOCK: usize = 64;

/// `/v1/media/{id}?ex={now+ttl}&is={now}&hm={hex}`.
pub fn mint(secret: &[u8], id: &str, now: i64, ttl_secs: i64) -> String {
    let ex = now.saturating_add(ttl_secs);
    let issued = now;
    let hm = hex_encode(&mac(secret, id, ex, issued));
    format!("/v1/media/{id}?ex={ex}&is={issued}&hm={hm}")
}

pub fn verify(secret: &[u8], id: &str, ex: i64, issued: i64, hm: &str, now: i64) -> bool {
    if now > ex || issued > ex || issued > now {
        return false;
    }
    let expected = mac(secret, id, ex, issued);
    match decode_hex_mac(hm) {
        Some(got) => bool::from(got.ct_eq(&expected)),
        None => false,
    }
}

pub(crate) fn load_secret() -> Option<Vec<u8>> {
    let hex = std::env::var("TINYSERVER_MEDIA_HMAC_SECRET").ok()?;
    decode_hex32(&hex)
}

pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

pub(crate) fn overlay(value: &mut Value) {
    let Some(secret) = load_secret() else {
        return;
    };
    overlay_with(value, &secret, unix_now());
}

fn overlay_with(value: &mut Value, secret: &[u8], now: i64) {
    match value {
        Value::Array(items) => {
            for item in items {
                overlay_with(item, secret, now);
            }
        }
        Value::Object(map) => {
            let attachment = map.get("id").and_then(Value::as_str).is_some()
                && map.contains_key("mime")
                && map.contains_key("kind");
            if attachment {
                if let Some(id) = map.get("id").and_then(Value::as_str).map(str::to_string) {
                    map.insert(
                        "url".into(),
                        Value::String(mint(secret, &id, now, TTL_SECS)),
                    );
                }
            }
            for key in ["attachments", "last_message", "message"] {
                if let Some(child) = map.get_mut(key) {
                    overlay_with(child, secret, now);
                }
            }
        }
        _ => {}
    }
}

fn mac(secret: &[u8], id: &str, ex: i64, issued: i64) -> [u8; 32] {
    let canonical = format!("v1\n{ex}\n{issued}\n/v1/media/{id}");
    hmac_sha256(secret, canonical.as_bytes())
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0_u8; BLOCK];
    if key.len() > BLOCK {
        let hashed = Sha256::digest(key);
        key_block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36_u8; BLOCK];
    let mut opad = [0x5c_u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let digest = outer.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn decode_hex32(hex: &str) -> Option<Vec<u8>> {
    decode_hex_mac(hex).map(|bytes| bytes.to_vec())
}

fn decode_hex_mac(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = [0_u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = from_hex(bytes[i * 2])?;
        let lo = from_hex(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Vec<u8> {
        decode_hex32(TEST_SECRET_HEX).expect("test secret")
    }

    fn parse_url(url: &str) -> (i64, i64, String) {
        let query = url.split_once('?').expect("query").1;
        let mut ex = 0;
        let mut issued = 0;
        let mut hm = String::new();
        for part in query.split('&') {
            let (key, value) = part.split_once('=').expect("pair");
            match key {
                "ex" => ex = value.parse().expect("ex"),
                "is" => issued = value.parse().expect("is"),
                "hm" => hm = value.to_string(),
                _ => {}
            }
        }
        (ex, issued, hm)
    }

    #[test]
    fn mint_binds_id_expiry_and_hmac() {
        let url = mint(
            &secret(),
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            1_700_000_000,
            86_400,
        );
        assert!(
            url.starts_with("/v1/media/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee?"),
            "{url}"
        );
        assert!(url.contains("ex=1700086400"), "{url}");
        assert!(url.contains("is=1700000000"), "{url}");
        assert!(url.contains("hm="), "{url}");
        let (_, _, hm) = parse_url(&url);
        assert_eq!(hm.len(), 64, "{hm}");
    }

    #[test]
    fn verify_accepts_a_fresh_mint() {
        let now = 1_700_000_000;
        let url = mint(&secret(), "id-1", now, 60);
        let (ex, issued, hm) = parse_url(&url);
        assert!(verify(&secret(), "id-1", ex, issued, &hm, now));
        assert!(verify(&secret(), "id-1", ex, issued, &hm, now + 59));
    }

    #[test]
    fn verify_rejects_wrong_hmac_expired_or_other_id() {
        let now = 1_700_000_000;
        let url = mint(&secret(), "id-1", now, 60);
        let (ex, issued, hm) = parse_url(&url);
        assert!(!verify(&secret(), "id-1", ex, issued, "00", now));
        assert!(!verify(
            &secret(),
            "id-1",
            ex,
            issued,
            &hm,
            now.saturating_add(61)
        ));
        assert!(!verify(&secret(), "id-2", ex, issued, &hm, now));
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_1() {
        let key = [0x0b_u8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex_encode(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn overlay_writes_url_on_attachment_objects() {
        let mut value = serde_json::json!({
            "attachments": [{
                "id": "id-1",
                "name": "doc.pdf",
                "mime": "application/pdf",
                "kind": "file"
            }]
        });
        overlay_with(&mut value, &secret(), 1_700_000_000);
        let url = value["attachments"][0]["url"].as_str().expect("url");
        assert!(url.starts_with("/v1/media/id-1?"), "{url}");
        let (ex, issued, hm) = parse_url(url);
        assert_eq!(ex, 1_700_086_400);
        assert_eq!(issued, 1_700_000_000);
        assert!(verify(&secret(), "id-1", ex, issued, &hm, 1_700_000_000));
    }
}
