//! `zama_fhe_native` — the native crypto core behind the Dart FFI backend.
//!
//! Narrow, panic-safe C ABI (bytes in / bytes out) over `tfhe-rs`:
//! - build a context from the network public key + CRS (or generate one for tests),
//! - `encrypt` typed values into a proven compact ciphertext list (the relayer
//!   `inputProof` blob), using `ZkComputeLoad::Verify` like the JS SDK,
//! - a test-only verify+decrypt to prove the round-trip across the boundary.
//!
//! Values are passed as a flat buffer of 32-byte big-endian integers plus a
//! parallel array of FHE type ids (0=ebool, 2=u8, 3=u16, 4=u32, 5=u64, 6=u128,
//! 7=eaddress/160-bit, 8=euint256). Values up to `u128` only use the low 16
//! bytes; eaddress/euint256 use the full 32.

use std::panic::catch_unwind;
use std::slice;

use tfhe::integer::U256;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};
use tfhe::{
    set_server_key, ClientKey, CompactPublicKey, ConfigBuilder, ProvenCompactCiphertextList,
    ServerKey,
};

const SER_LIMIT: u64 = 1 << 30; // 1 GiB safe-(de)serialization cap

/// Status codes returned across the ABI. 0 = success.
const OK: i32 = 0;
const ERR_NULL: i32 = -1;
const ERR_PANIC: i32 = -2;
const ERR_ENCRYPT: i32 = -3;
const ERR_DESERIALIZE: i32 = -4;
const ERR_VERIFY: i32 = -5;
const ERR_TYPE: i32 = -6;
const ERR_CAPACITY: i32 = -7;

/// An owned byte buffer handed to Dart. Free it with [`zama_bytes_free`].
#[repr(C)]
pub struct ByteBuf {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl ByteBuf {
    fn from_vec(mut v: Vec<u8>) -> Self {
        v.shrink_to_fit();
        let b = ByteBuf {
            ptr: v.as_mut_ptr(),
            len: v.len(),
            cap: v.capacity(),
        };
        std::mem::forget(v);
        b
    }
    fn empty() -> Self {
        ByteBuf {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// Opaque context: the material needed to encrypt + prove. `client_key` /
/// `server_key` are populated only by the test/dev generator.
pub struct ZamaCtx {
    public_key: CompactPublicKey,
    crs: CompactPkeCrs,
    client_key: Option<ClientKey>,
    server_key: Option<ServerKey>,
}

/// Frees a context created by `zama_ctx_new*`.
///
/// # Safety
/// `ctx` must be a pointer returned by this library, or null.
#[no_mangle]
pub unsafe extern "C" fn zama_ctx_free(ctx: *mut ZamaCtx) {
    if !ctx.is_null() {
        drop(Box::from_raw(ctx));
    }
}

/// Frees a [`ByteBuf`] returned by this library.
///
/// # Safety
/// `buf` must have been produced by this library.
#[no_mangle]
pub unsafe extern "C" fn zama_bytes_free(buf: ByteBuf) {
    if !buf.ptr.is_null() {
        drop(Vec::from_raw_parts(buf.ptr, buf.len, buf.cap));
    }
}

/// Test/dev helper: generate keys + a CRS sized for `max_bits` and return a
/// fully populated context (including the client key for verification).
#[no_mangle]
pub extern "C" fn zama_ctx_new_generated(max_bits: usize) -> *mut ZamaCtx {
    catch_unwind(|| {
        let params = tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let cpk_params =
            tfhe::shortint::parameters::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let casting_params =
            tfhe::shortint::parameters::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let config = ConfigBuilder::with_custom_parameters(params)
            .use_dedicated_compact_public_key_parameters((cpk_params, casting_params))
            .build();

        let crs = CompactPkeCrs::from_config(config, max_bits).unwrap();
        let client_key = ClientKey::generate(config);
        let server_key = ServerKey::new(&client_key);
        let public_key = CompactPublicKey::try_new(&client_key).unwrap();

        Box::into_raw(Box::new(ZamaCtx {
            public_key,
            crs,
            client_key: Some(client_key),
            server_key: Some(server_key),
        }))
    })
    .unwrap_or(std::ptr::null_mut())
}

/// Production constructor: build a context from a safe-serialized
/// `CompactPublicKey` and `CompactPkeCrs` (as served by the relayer `/keyurl`).
///
/// # Safety
/// The pointers must reference valid buffers of the given lengths.
#[no_mangle]
pub unsafe extern "C" fn zama_ctx_new(
    pk: *const u8,
    pk_len: usize,
    crs: *const u8,
    crs_len: usize,
) -> *mut ZamaCtx {
    if pk.is_null() || crs.is_null() {
        return std::ptr::null_mut();
    }
    let pk_bytes = slice::from_raw_parts(pk, pk_len).to_vec();
    let crs_bytes = slice::from_raw_parts(crs, crs_len).to_vec();
    catch_unwind(move || {
        let public_key: CompactPublicKey =
            match safe_deserialize(pk_bytes.as_slice(), SER_LIMIT) {
                Ok(v) => v,
                Err(_) => return std::ptr::null_mut(),
            };
        let crs: CompactPkeCrs = match safe_deserialize(crs_bytes.as_slice(), SER_LIMIT) {
            Ok(v) => v,
            Err(_) => return std::ptr::null_mut(),
        };
        Box::into_raw(Box::new(ZamaCtx {
            public_key,
            crs,
            client_key: None,
            server_key: None,
        }))
    })
    .unwrap_or(std::ptr::null_mut())
}

/// Encrypts `n` typed values into a proven compact ciphertext list and writes
/// the safe-serialized blob (the relayer `inputProof`) into `out`.
///
/// # Safety
/// All pointers must reference valid buffers of the indicated sizes.
#[no_mangle]
pub unsafe extern "C" fn zama_encrypt(
    ctx: *const ZamaCtx,
    values_be32: *const u8,
    type_ids: *const u8,
    n: usize,
    metadata: *const u8,
    metadata_len: usize,
    out: *mut ByteBuf,
) -> i32 {
    if ctx.is_null() || values_be32.is_null() || type_ids.is_null() || out.is_null() {
        return ERR_NULL;
    }
    let ctx = &*ctx;
    let values = slice::from_raw_parts(values_be32, n * 32).to_vec();
    let types = slice::from_raw_parts(type_ids, n).to_vec();
    let meta = if metadata.is_null() {
        Vec::new()
    } else {
        slice::from_raw_parts(metadata, metadata_len).to_vec()
    };

    let result = catch_unwind(move || {
        let mut builder = ProvenCompactCiphertextList::builder(&ctx.public_key);
        for i in 0..n {
            let be32 = &values[i * 32..i * 32 + 32];
            let v = u128_from_be32(be32);
            match types[i] {
                0 => builder.push(v != 0),
                2 => builder.push(v as u8),
                3 => builder.push(v as u16),
                4 => builder.push(v as u32),
                5 => builder.push(v as u64),
                6 => builder.push(v),
                // eaddress is a 160-bit value carried in a U256.
                7 => {
                    builder
                        .push_with_num_bits(u256_from_be32(be32), 160)
                        .map_err(|_| ERR_ENCRYPT)?;
                    &mut builder
                }
                8 => builder.push(u256_from_be32(be32)),
                _ => return Err(ERR_TYPE),
            };
        }
        let proven = builder
            .build_with_proof_packed(&ctx.crs, &meta, ZkComputeLoad::Verify)
            .map_err(|_| ERR_ENCRYPT)?;
        let mut buf = Vec::new();
        safe_serialize(&proven, &mut buf, SER_LIMIT).map_err(|_| ERR_ENCRYPT)?;
        Ok(buf)
    });

    match result {
        Ok(Ok(buf)) => {
            *out = ByteBuf::from_vec(buf);
            OK
        }
        Ok(Err(code)) => {
            *out = ByteBuf::empty();
            code
        }
        Err(_) => {
            *out = ByteBuf::empty();
            ERR_PANIC
        }
    }
}

/// Test-only: verify a proven blob against the context CRS/public key and
/// decrypt each slot, writing the cleartext `u128`s into `out_vals`.
/// Returns the number of values written, or a negative error code.
///
/// # Safety
/// All pointers must reference valid buffers of the indicated sizes.
#[no_mangle]
pub unsafe extern "C" fn zama_test_verify_decrypt(
    ctx: *const ZamaCtx,
    blob: *const u8,
    blob_len: usize,
    type_ids: *const u8,
    n: usize,
    metadata: *const u8,
    metadata_len: usize,
    out_vals: *mut u8,
    out_cap: usize,
) -> i32 {
    if ctx.is_null() || blob.is_null() || type_ids.is_null() || out_vals.is_null() {
        return ERR_NULL;
    }
    if out_cap < n {
        return ERR_CAPACITY;
    }
    let ctx = &*ctx;
    let client_key = match &ctx.client_key {
        Some(k) => k.clone(),
        None => return ERR_VERIFY,
    };
    let server_key = match &ctx.server_key {
        Some(k) => k.clone(),
        None => return ERR_VERIFY,
    };
    let blob_bytes = slice::from_raw_parts(blob, blob_len).to_vec();
    let types = slice::from_raw_parts(type_ids, n).to_vec();
    let meta = if metadata.is_null() {
        Vec::new()
    } else {
        slice::from_raw_parts(metadata, metadata_len).to_vec()
    };
    let out = slice::from_raw_parts_mut(out_vals, n * 32);

    let result = catch_unwind(move || -> Result<Vec<[u8; 32]>, i32> {
        let proven: ProvenCompactCiphertextList =
            safe_deserialize(blob_bytes.as_slice(), SER_LIMIT).map_err(|_| ERR_DESERIALIZE)?;
        set_server_key(server_key);
        let expander = proven
            .verify_and_expand(&ctx.crs, &ctx.public_key, &meta)
            .map_err(|_| ERR_VERIFY)?;

        // Decrypt a `u128`-or-smaller slot and widen it into a 32-byte BE buffer.
        macro_rules! dec {
            ($t:ty, $clear:ty, $i:expr) => {{
                let ct: $t = expander.get($i).map_err(|_| ERR_TYPE)?.ok_or(ERR_TYPE)?;
                let c: $clear = ct.decrypt(&client_key);
                u128_to_be32(c as u128)
            }};
        }

        let mut vals: Vec<[u8; 32]> = Vec::with_capacity(n);
        for i in 0..n {
            let v: [u8; 32] = match types[i] {
                0 => {
                    let b: tfhe::FheBool = expander.get(i).map_err(|_| ERR_TYPE)?.ok_or(ERR_TYPE)?;
                    u128_to_be32(if b.decrypt(&client_key) { 1 } else { 0 })
                }
                2 => dec!(tfhe::FheUint8, u8, i),
                3 => dec!(tfhe::FheUint16, u16, i),
                4 => dec!(tfhe::FheUint32, u32, i),
                5 => dec!(tfhe::FheUint64, u64, i),
                6 => dec!(tfhe::FheUint128, u128, i),
                7 => {
                    let ct: tfhe::FheUint160 =
                        expander.get(i).map_err(|_| ERR_TYPE)?.ok_or(ERR_TYPE)?;
                    u256_to_be32(ct.decrypt(&client_key))
                }
                8 => {
                    let ct: tfhe::FheUint256 =
                        expander.get(i).map_err(|_| ERR_TYPE)?.ok_or(ERR_TYPE)?;
                    u256_to_be32(ct.decrypt(&client_key))
                }
                _ => return Err(ERR_TYPE),
            };
            vals.push(v);
        }
        Ok(vals)
    });

    match result {
        Ok(Ok(vals)) => {
            for (i, v) in vals.iter().enumerate() {
                out[i * 32..i * 32 + 32].copy_from_slice(v);
            }
            n as i32
        }
        Ok(Err(code)) => code,
        Err(_) => ERR_PANIC,
    }
}

/// Read the low 128 bits of a 32-byte big-endian buffer.
fn u128_from_be32(b: &[u8]) -> u128 {
    let mut v: u128 = 0;
    for &byte in &b[16..32] {
        v = (v << 8) | byte as u128;
    }
    v
}

/// Build a `U256` from a 32-byte big-endian buffer.
fn u256_from_be32(b: &[u8]) -> U256 {
    let mut high = [0u8; 16];
    let mut low = [0u8; 16];
    high.copy_from_slice(&b[0..16]);
    low.copy_from_slice(&b[16..32]);
    U256::from((u128::from_be_bytes(low), u128::from_be_bytes(high)))
}

/// Serialize a `u128` into a 32-byte big-endian buffer (high bytes zero).
fn u128_to_be32(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&v.to_be_bytes());
    out
}

/// Serialize a `U256` into a 32-byte big-endian buffer.
fn u256_to_be32(v: U256) -> [u8; 32] {
    let (low, high) = v.to_low_high_u128();
    let mut out = [0u8; 32];
    out[0..16].copy_from_slice(&high.to_be_bytes());
    out[16..32].copy_from_slice(&low.to_be_bytes());
    out
}
