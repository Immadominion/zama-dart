//! Native FFI to the Zama KMS client crypto (ML-KEM-512 user-decryption).
//!
//! The kms crate's crypto internals are `pub(crate)`, so this drives the *pub*
//! (wasm-bindgen) `js_api` — proven to run natively (see the round-trip test).
//!
//! C ABI:
//! - `zama_kms_keygen`        → ephemeral ML-KEM keypair (pk for the relayer, sk to keep)
//! - `zama_kms_user_decrypt`  → decrypt a relayer `/user-decrypt` response to cleartext
//!
//! Mirrors `relayer-sdk` `userDecrypt.ts` + kms `js_api::js_to_resp` exactly.

use std::panic::catch_unwind;
use std::slice;

use alloy_primitives::{Address, Signature};
use kms_grpc::kms::v1::{
    Eip712DomainMsg, TypedPlaintext, UserDecryptionResponse, UserDecryptionResponsePayload,
};
use kms_lib::client::js_api::{
    ml_kem_pke_get_pk, ml_kem_pke_keygen, ml_kem_pke_pk_to_u8vec, ml_kem_pke_sk_to_u8vec,
    new_client, new_server_id_addr, process_user_decryption_resp, u8vec_to_ml_kem_pke_pk,
    u8vec_to_ml_kem_pke_sk,
};
use kms_lib::client::user_decryption_wasm::{CiphertextHandle, ParsedUserDecryptionRequest};

const OK: i32 = 0;
const ERR_NULL: i32 = -1;
const ERR_PANIC: i32 = -2;
const ERR_INPUT: i32 = -3;
const ERR_DECRYPT: i32 = -4;

/// Owned byte buffer handed to Dart. Free with [`zama_kms_bytes_free`].
#[repr(C)]
pub struct ByteBuf {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl ByteBuf {
    fn from_vec(mut v: Vec<u8>) -> Self {
        v.shrink_to_fit();
        let b = ByteBuf { ptr: v.as_mut_ptr(), len: v.len(), cap: v.capacity() };
        std::mem::forget(v);
        b
    }
    fn empty() -> Self {
        ByteBuf { ptr: std::ptr::null_mut(), len: 0, cap: 0 }
    }
}

/// # Safety
/// `buf` must have been produced by this library.
#[no_mangle]
pub unsafe extern "C" fn zama_kms_bytes_free(buf: ByteBuf) {
    if !buf.ptr.is_null() {
        drop(Vec::from_raw_parts(buf.ptr, buf.len, buf.cap));
    }
}

/// Generates an ephemeral ML-KEM-512 keypair. Writes the serialized public key
/// (sent to the relayer / bound into the EIP-712) to `out_pk` and the secret key
/// (kept by the caller, passed back to [`zama_kms_user_decrypt`]) to `out_sk`.
///
/// # Safety
/// `out_pk` / `out_sk` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn zama_kms_keygen(out_pk: *mut ByteBuf, out_sk: *mut ByteBuf) -> i32 {
    if out_pk.is_null() || out_sk.is_null() {
        return ERR_NULL;
    }
    let r = catch_unwind(|| -> Result<(Vec<u8>, Vec<u8>), ()> {
        let sk = ml_kem_pke_keygen();
        let pk = ml_kem_pke_get_pk(&sk);
        let pk_bytes = ml_kem_pke_pk_to_u8vec(&pk).map_err(|_| ())?;
        let sk_bytes = ml_kem_pke_sk_to_u8vec(&sk).map_err(|_| ())?;
        Ok((pk_bytes, sk_bytes))
    });
    match r {
        Ok(Ok((pk, sk))) => {
            *out_pk = ByteBuf::from_vec(pk);
            *out_sk = ByteBuf::from_vec(sk);
            OK
        }
        Ok(Err(())) => {
            *out_pk = ByteBuf::empty();
            *out_sk = ByteBuf::empty();
            ERR_INPUT
        }
        Err(_) => ERR_PANIC,
    }
}

/// Decrypts a relayer `/user-decrypt` response. `request_json` is a UTF-8 JSON
/// object (see [`run_user_decrypt`]); writes a JSON array
/// `[{"bytes":"<hex>","fheType":<int>}]` of cleartexts to `out`.
///
/// # Safety
/// `request_json` must point to `len` valid bytes; `out` must be valid.
#[no_mangle]
pub unsafe extern "C" fn zama_kms_user_decrypt(
    request_json: *const u8,
    len: usize,
    out: *mut ByteBuf,
) -> i32 {
    if request_json.is_null() || out.is_null() {
        return ERR_NULL;
    }
    let req = slice::from_raw_parts(request_json, len).to_vec();
    let r = catch_unwind(move || run_user_decrypt(&req));
    match r {
        Ok(Ok(bytes)) => {
            *out = ByteBuf::from_vec(bytes);
            OK
        }
        // On failure, return the error/panic message in `out` so Dart can show it.
        Ok(Err(msg)) => {
            *out = ByteBuf::from_vec(msg.into_bytes());
            ERR_DECRYPT
        }
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "panic".to_string());
            *out = ByteBuf::from_vec(msg.into_bytes());
            ERR_PANIC
        }
    }
}

fn hexd(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| e.to_string())
}

fn addr(s: &str) -> Result<Address, String> {
    let b = hexd(s)?;
    if b.len() != 20 {
        return Err(format!("address must be 20 bytes, got {}", b.len()));
    }
    Ok(Address::from_slice(&b))
}

/// Builds the typed args and runs `process_user_decryption_resp`. Request JSON:
/// ```json
/// { "userAddress","verifyingContract","gatewayChainId","signature","encPk",
///   "encSk","handles":[..],"extraData","verify",
///   "kmsSigners":[{"id":int,"address":"0x.."}],
///   "responses":[{"payload":"<hex>","signature":"<hex>"}] }
/// ```
fn run_user_decrypt(req: &[u8]) -> Result<Vec<u8>, String> {
    let v: serde_json::Value = serde_json::from_slice(req).map_err(|e| e.to_string())?;

    let user_address = v["userAddress"].as_str().ok_or("userAddress")?;
    let verifying_contract = v["verifyingContract"].as_str().ok_or("verifyingContract")?;
    let gateway_chain_id = v["gatewayChainId"].as_u64().ok_or("gatewayChainId")? as u32;
    let verify = v["verify"].as_bool().unwrap_or(true);
    let extra_data = hexd(v["extraData"].as_str().unwrap_or("0x00"))?;

    // Ephemeral ML-KEM keys.
    let enc_pk_bytes = hexd(v["encPk"].as_str().ok_or("encPk")?)?;
    let enc_sk_bytes = hexd(v["encSk"].as_str().ok_or("encSk")?)?;
    let enc_pk = u8vec_to_ml_kem_pke_pk(&enc_pk_bytes).map_err(|_| "bad encPk")?;
    let enc_sk = u8vec_to_ml_kem_pke_sk(&enc_sk_bytes).map_err(|_| "bad encSk")?;

    // KMS server identities (for threshold signature verification when verify=true).
    let mut server_addrs = Vec::new();
    if let Some(arr) = v["kmsSigners"].as_array() {
        for s in arr {
            let id = s["id"].as_u64().ok_or("signer.id")? as u32;
            let a = s["address"].as_str().ok_or("signer.address")?;
            server_addrs
                .push(new_server_id_addr(id, a.to_string()).map_err(|_| "bad signer")?);
        }
    }
    let mut client =
        new_client(server_addrs, user_address, "default").map_err(|_| "new_client")?;

    // Parsed request (binds the user's EIP-712 signature to the handles).
    let sig_bytes = hexd(v["signature"].as_str().ok_or("signature")?)?;
    let signature = Signature::try_from(sig_bytes.as_slice()).map_err(|e| e.to_string())?;
    let mut handles = Vec::new();
    for h in v["handles"].as_array().ok_or("handles")? {
        handles.push(CiphertextHandle::new(hexd(h.as_str().ok_or("handle")?)?));
    }
    let request = ParsedUserDecryptionRequest::new(
        Some(signature),
        addr(user_address)?,
        enc_pk_bytes.clone(),
        handles,
        addr(verifying_contract)?,
        extra_data.clone(),
    );

    // EIP-712 domain (gateway chain id as 32-byte big-endian).
    let mut chain_id = vec![0u8; 32];
    chain_id[28..32].copy_from_slice(&gateway_chain_id.to_be_bytes());
    let eip712_domain = Eip712DomainMsg {
        name: "Decryption".to_string(),
        version: "1".to_string(),
        chain_id,
        verifying_contract: verifying_contract.to_string(),
        salt: None,
    };

    // Per-node re-encrypted responses (mirror js_to_resp).
    let mut responses = Vec::new();
    for item in v["responses"].as_array().ok_or("responses")? {
        let payload_hex = item["payload"].as_str().ok_or("response.payload")?;
        let sig_hex = item["signature"].as_str().ok_or("response.signature")?;
        let payload_bytes = hexd(payload_hex)?;
        let payload =
            bc2wrap::deserialize_safe::<UserDecryptionResponsePayload>(&payload_bytes)
                .map_err(|e| e.to_string())?;
        responses.push(UserDecryptionResponse {
            signature: vec![],
            external_signature: hexd(sig_hex)?,
            payload: Some(payload),
            extra_data: extra_data.clone(),
        });
    }

    let plaintexts: Vec<TypedPlaintext> = process_user_decryption_resp(
        &mut client,
        Some(request),
        Some(eip712_domain),
        responses,
        &enc_pk,
        &enc_sk,
        verify,
    )
    .map_err(|_| "process_user_decryption_resp failed".to_string())?;

    let out: Vec<serde_json::Value> = plaintexts
        .iter()
        .map(|p| serde_json::json!({ "bytes": hex::encode(&p.bytes), "fheType": p.fhe_type }))
        .collect();
    serde_json::to_vec(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use kms_lib::client::js_api::{
        ml_kem_pke_decrypt, ml_kem_pke_encrypt, ml_kem_pke_get_pk, ml_kem_pke_keygen,
        ml_kem_pke_pk_to_u8vec, u8vec_to_ml_kem_pke_pk,
    };

    #[test]
    fn ml_kem_hybrid_roundtrip_on_native() {
        let sk = ml_kem_pke_keygen();
        let pk = ml_kem_pke_get_pk(&sk);
        let pk_bytes = match ml_kem_pke_pk_to_u8vec(&pk) {
            Ok(v) => v,
            Err(_) => panic!("pk serialize failed"),
        };
        assert!(pk_bytes.len() > 800, "pk bytes len = {}", pk_bytes.len());
        if u8vec_to_ml_kem_pke_pk(&pk_bytes).is_err() {
            panic!("pk deserialize failed");
        }
        let msg = b"hello zama from dart native ffi".to_vec();
        let ct = ml_kem_pke_encrypt(&msg, &pk);
        let out = ml_kem_pke_decrypt(&ct, &sk);
        assert_eq!(out, msg, "ML-KEM hybrid round-trip mismatch");
    }
}
