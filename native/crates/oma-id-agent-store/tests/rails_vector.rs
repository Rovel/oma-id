//! Cross-language lease contract test: the fixture in
//! `protocol/lease-v1/rails-signs-vector.json` is produced by the Rails
//! issuer suite (`OmaId::LeaseSigningKey`). This test verifies the Rails
//! signature with the agent-side verifier — on every CI run — so encoder or
//! schema drift between the two languages fails loudly.

#![cfg(target_os = "linux")]

use oma_id_agent_store::{issuer_verifying_key, LeasePayload, SignedLease};
use std::path::Path;

#[test]
fn rails_signed_lease_vector_verifies_with_the_agent_verifier() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .join("protocol/lease-v1/rails-signs-vector.json");
    let raw = std::fs::read_to_string(&manifest).unwrap_or_else(|e| panic!("fixture path {}: {e}", manifest.display()));

    let vector: serde_json::Value = serde_json::from_str(&raw).expect("fixture json");
    assert_eq!(vector["contract"], "oma-lease-v1", "fixture contract tag");

    let issuer = issuer_verifying_key(vector["public_key_hex"].as_str().expect("public key"))
        .expect("pinned issuer key parses");
    let payload_payload = &vector["payload"];
    let payload = LeasePayload {
        subject_id: payload_payload["subject_id"].as_str().expect("subject").into(),
        device_id: payload_payload["device_id"].as_str().expect("device").into(),
        not_before: payload_payload["not_before"].as_u64().expect("not_before"),
        expires_at: payload_payload["expires_at"].as_u64().expect("expires_at"),
        revocation_epoch: payload_payload["revocation_epoch"]
            .as_u64()
            .expect("revocation_epoch"),
        operations: payload_payload["operations"]
            .as_array()
            .expect("operations array")
            .iter()
            .map(|op| serde_json::from_value(op.clone()).expect("operation name"))
            .collect(),
    };

    // The Rails canonical encoding must be byte-identical to the agent's.
    let canonical = oma_id_agent_store::canonical_payload_json(&payload);
    assert_eq!(
        std::str::from_utf8(&canonical).expect("utf-8"),
        vector["canonical_encoding"].as_str().expect("canonical encoding"),
        "Rails and agent canonical encodings drifted"
    );

    let signed = SignedLease {
        payload: payload.clone(),
        signature: vector["signature_hex"].as_str().expect("signature").into(),
        key_id: String::new(), // lease-v1 fixture: single-key era
    };
    signed
        .verify(&issuer)
        .expect("Rails signature must verify with the agent verifier");
}

