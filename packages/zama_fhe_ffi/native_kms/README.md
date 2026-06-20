# `zama_kms_ffi` — native KMS client for user (private) decryption

This is the Rust source for the native KMS FFI wrapper behind
[`ZamaKms`](../lib/zama_kms.dart) / `KmsNativeBackend`. It exposes a small C ABI
(`zama_kms_keygen`, `zama_kms_user_decrypt`, `zama_kms_bytes_free`) over Zama's
`kms` crate to do ML-KEM-512 ephemeral keypair generation and the
ML-KEM-512 + AES-256-GCM hybrid decryption of a `/user-decrypt` response.

## Why it isn't built in CI here

It links Zama's `kms` crate, whose client-side crypto is only reachable through
the crate's `pub` wasm-bindgen `js_api` (the rest is `pub(crate)`), and a loose
`git` dependency does **not** resolve (a duplicate `winnow` is pulled in via
`alloy-dyn-abi`). So it must build **as a workspace member inside a vendored
checkout of `kms` v0.13.10**, against that repo's pinned `Cargo.lock` and Rust
**1.94.0**.

## Build setup

```bash
# 1. Vendor the KMS repo (pin the exact tag).
git clone --depth 1 --branch v0.13.10 https://github.com/zama-ai/kms native/kms

# 2. Drop this crate inside it and register it as a workspace member.
cp -r packages/zama_fhe_ffi/native_kms native/kms/zama_kms_ffi
#   then add "zama_kms_ffi" to the `members = [...]` list in native/kms/Cargo.toml

# 3. Build (uses the repo's rust-toolchain 1.94.0 + Cargo.lock).
cd native/kms && cargo build --release -p zama_kms_ffi
#   → target/release/libzama_kms_ffi.{dylib,so}; point ZAMA_KMS_LIB at it.
```

The encrypt crate (`../rust`, tfhe 1.5.4 / Rust 1.91.1) and this KMS crate use
**different Rust toolchains**, so they are built separately.

> Verified live on Sepolia: this wrapper performed the M2 private user-decrypt
> (ML-KEM keygen on-device, hybrid decrypt of the relayer response), with the
> KMS threshold-signature check done in pure Dart (`KmsResponseVerifier`).
