//! Signed public generation bindings. Private creator state is never accepted here.
use super::{canonical_uuid, mls, Server};
use crate::messages::{lift, member, Error};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::{Extension, Json};
use base64::{engine::general_purpose::STANDARD, Engine};
use db::PgPool;
use openmls::prelude::{OpenMlsCrypto, OpenMlsProvider, SignatureScheme};
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    version: u8,
    conversation_id: String,
    from_generation: u64,
    to_generation: u64,
    from_group_id: String,
    group_id: String,
    from_epoch: u64,
    previous_hash: String,
    server_key_hash: String,
    user_id: String,
    device_id: String,
    signature_key: String,
    signature: String,
}

impl Binding {
    fn bytes(text: &str, len: usize) -> Result<Vec<u8>, Error> {
        let bytes = STANDARD.decode(text).map_err(|_| Error::BadE2ee)?;
        if bytes.len() != len || STANDARD.encode(&bytes) != text {
            return Err(Error::BadE2ee);
        }
        Ok(bytes)
    }
    fn uuid(text: &str) -> Result<[u8; 16], Error> {
        if canonical_uuid(text).as_deref() != Some(text) {
            return Err(Error::BadE2ee);
        }
        mls::uuid_bytes(text).ok_or(Error::BadE2ee)
    }
    pub(super) fn canonical_payload(&self) -> Result<Vec<u8>, Error> {
        if self.version != 1
            || self.from_generation > i64::MAX as u64
            || self.to_generation > i64::MAX as u64
            || self.from_epoch > i64::MAX as u64
            || self.from_generation.checked_add(1) != Some(self.to_generation)
            || self.group_id == self.from_group_id
            || self.group_id == self.conversation_id
        {
            return Err(Error::BadE2ee);
        }
        let mut p = b"tiny-e2ee-v1 group-repair\0".to_vec();
        p.push(1);
        p.extend_from_slice(&Self::uuid(&self.conversation_id)?);
        p.extend_from_slice(&self.from_generation.to_be_bytes());
        p.extend_from_slice(&self.to_generation.to_be_bytes());
        p.extend_from_slice(&Self::uuid(&self.from_group_id)?);
        p.extend_from_slice(&Self::uuid(&self.group_id)?);
        p.extend_from_slice(&self.from_epoch.to_be_bytes());
        p.extend_from_slice(&Self::bytes(&self.previous_hash, 32)?);
        p.extend_from_slice(&Self::bytes(&self.server_key_hash, 32)?);
        p.extend_from_slice(&Self::uuid(&self.user_id)?);
        p.extend_from_slice(&Self::uuid(&self.device_id)?);
        let key = Self::bytes(&self.signature_key, 65)?;
        if key[0] != 4 {
            return Err(Error::BadE2ee);
        }
        p.extend_from_slice(&key);
        Ok(p)
    }
    fn verified_hash(&self) -> Result<Vec<u8>, Error> {
        let p = self.canonical_payload()?;
        let signature = STANDARD
            .decode(&self.signature)
            .map_err(|_| Error::BadE2ee)?;
        if !(8..=72).contains(&signature.len()) || STANDARD.encode(&signature) != self.signature {
            return Err(Error::BadE2ee);
        }
        let key = Self::bytes(&self.signature_key, 65)?;
        OpenMlsRustCrypto::default()
            .crypto()
            .verify_signature(
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                &p,
                &key,
                &signature,
            )
            .map_err(|_| Error::BadE2ee)?;
        Ok(Sha256::digest(&p).to_vec())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RepairBody {
    binding: Binding,
}
#[derive(Deserialize)]
pub(super) struct ChainQuery {
    after: Option<u64>,
    limit: Option<i32>,
}

pub(super) async fn repair(
    State(pool): State<PgPool>,
    Extension(server): Extension<Arc<Server>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<RepairBody>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let caller = member(&pool, &headers).await?;
    server.allow(&caller.user_id)?;
    if id != body.binding.conversation_id || caller.user_id != body.binding.user_id {
        return Err(Error::BadE2ee);
    }
    let hash = body.binding.verified_hash()?;
    let signer = server.signer(&pool).await?;
    if Binding::bytes(&body.binding.server_key_hash, 32)?
        != Sha256::digest(signer.public_key()).as_slice()
    {
        return Err(Error::BadE2ee);
    }
    let binding = serde_json::to_value(&body.binding).map_err(|_| Error::Invalid)?;
    let mut value = db::repair_group(&pool, &caller, &id, &binding, &hash)
        .await
        .map_err(lift)?;
    let created = value
        .get("created")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let Some(o) = value.as_object_mut() {
        o.remove("created");
    }
    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(value),
    ))
}
pub(super) async fn generations(
    State(pool): State<PgPool>,
    Extension(server): Extension<Arc<Server>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<ChainQuery>,
) -> Result<Json<Value>, Error> {
    let caller = member(&pool, &headers).await?;
    let limit = query.limit.unwrap_or(100);
    let after = query.after.unwrap_or(0);
    if !(1..=100).contains(&limit) || after > i64::MAX as u64 {
        return Err(Error::Invalid);
    }
    server.signer(&pool).await?;
    db::generation_chain(&pool, &caller, &id, after, limit)
        .await
        .map(Json)
        .map_err(lift)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_binding_matches_the_independent_engine_vector() {
        let vector: Value =
            serde_json::from_str(include_str!("fixtures/repair-vector.json")).expect("vector");
        let binding: Binding = serde_json::from_value(vector["binding"].clone()).expect("binding");
        let payload = binding
            .canonical_payload()
            .unwrap_or_else(|_| panic!("canonical payload"));
        assert_eq!(payload.len(), 260);
        assert_eq!(STANDARD.encode(&payload), vector["payload_base64"]);
        assert_eq!(
            STANDARD.encode(
                binding
                    .verified_hash()
                    .unwrap_or_else(|_| panic!("signature"))
            ),
            vector["head_hash"]
        );
        let key = STANDARD
            .decode(vector["external_server_key"].as_str().expect("key"))
            .expect("base64");
        let genesis = [
            b"tiny-e2ee-v1 group-genesis\0".as_slice(),
            &mls::uuid_bytes(&binding.conversation_id).expect("uuid"),
            &Sha256::digest(&key),
        ]
        .concat();
        assert_eq!(
            STANDARD.encode(Sha256::digest(genesis)),
            vector["genesis_hash"]
        );
    }
    #[test]
    fn altered_fields_and_noncanonical_encodings_cannot_authorize_repair() {
        let vector: Value =
            serde_json::from_str(include_str!("fixtures/repair-vector.json")).expect("vector");
        for field in [
            "conversation_id",
            "from_group_id",
            "group_id",
            "user_id",
            "device_id",
        ] {
            let mut value = vector["binding"].clone();
            value[field] = serde_json::json!("50000000-0000-4000-8000-000000000005");
            let binding: Binding = serde_json::from_value(value).expect("binding");
            assert!(binding.verified_hash().is_err(), "altered {field}");
        }
        for (field, value) in [
            ("from_generation", serde_json::json!(1)),
            ("to_generation", serde_json::json!(2)),
            ("from_epoch", serde_json::json!(8)),
            ("version", serde_json::json!(2)),
            ("from_epoch", serde_json::json!(u64::MAX)),
            ("previous_hash", serde_json::json!(STANDARD.encode([0; 32]))),
            (
                "server_key_hash",
                serde_json::json!(STANDARD.encode([0; 32])),
            ),
            ("signature", serde_json::json!("AAAA")),
        ] {
            let mut b = vector["binding"].clone();
            b[field] = value;
            let binding: Binding = serde_json::from_value(b).expect("binding");
            assert!(binding.verified_hash().is_err(), "altered {field}");
        }
        let mut b = vector["binding"].clone();
        b["signature_key"] = serde_json::json!(b["signature_key"]
            .as_str()
            .expect("key")
            .trim_end_matches('='));
        let binding: Binding = serde_json::from_value(b).expect("binding");
        assert!(binding.verified_hash().is_err());
    }
}
