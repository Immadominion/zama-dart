# zama_fhe_ffi

The **native crypto backend** for the Zama Protocol Dart SDK. Binds the
`zama_fhe_native` Rust library (tfhe-rs) via `dart:ffi` to do the heavy client
operation — TFHE compact-PKE encryption + a ZK proof (`ZkComputeLoad::Verify`,
same as the JS SDK) — and returns the relayer `inputProof` blob plus the derived
[`FhevmHandle`]s.

This is the mobile/desktop half of the SDK's "one API, two backends" design
(the web half reuses Zama's WASM via JS interop).

## Status — accepted by the LIVE Zama relayer ✅

- `encrypt([euint64(42), euint32(7), ebool(true)])` → valid proof blob + 3
  correctly-typed handles; `verify_and_expand` round-trips the values (host test).
- **The live Sepolia relayer accepts our natively-generated proof** — full path:
  fetch real key+CRS → native encrypt → `/input-proof` → `accepted=true` +
  coprocessor signature → assembled on-chain `inputProof`. (Run with
  `ZAMA_NETWORK_TESTS=1 dart test -t network`.)

On-device performance (same Rust code) is ~650–700 ms/proof on a mid-range
Android phone — see [`../../spike/zk-bench/RESULTS.md`](../../spike/zk-bench/RESULTS.md).

## ⚠️ Version pinning is load-bearing

The coprocessor verifier **rejects proofs from the wrong tfhe version.** This crate
pins **`tfhe = 1.5.4` + `tfhe-zk-pok = 0.8.0`** (what the official JS SDK ships /
the network verifies) — a 1.6.x proof is rejected. Build gotchas:

- tfhe 1.5.4's MSRV is 1.91.1 and its `tfhe-versionable 0.7.0` derive does **not**
  compile on Rust 1.95+, so `rust-toolchain.toml` pins **Rust 1.91.1**.
- Cargo auto-upgrades `tfhe-zk-pok` to 0.8.2, which drags in a second
  `tfhe-versionable` and breaks the `Versionize` derive — hence the exact `=0.8.0` pin.

## Layout

```
rust/                 zama_fhe_native crate (cdylib + staticlib), C ABI
  src/lib.rs          ctx_new / ctx_new_generated / encrypt / verify / free
lib/
  src/bindings.dart   raw dart:ffi signatures
  zama_fhe_ffi.dart   ZamaNative / ZamaContext high-level wrapper
test/                 encrypt + round-trip FFI test
```

## C ABI (current)

| Fn | Purpose |
|---|---|
| `zama_ctx_new(pk, crs)` | build context from relayer-served public key + CRS |
| `zama_ctx_new_generated(max_bits)` | test/dev: generate keys + CRS |
| `zama_encrypt(ctx, values, types, n, meta, out)` | → proven `inputProof` blob |
| `zama_test_verify_decrypt(...)` | test-only verify + decrypt |
| `zama_ctx_free` / `zama_bytes_free` | memory management |

Values are passed as 16-byte big-endian `u128` + a type id per value
(0=ebool, 2=u8…6=u128). `euint256`/`eaddress` (U256) are a follow-up.

## Build & test (desktop)

```bash
cd rust && cargo build --release           # produces lib/.dylib/.so/.dll
cd .. && dart pub get
ZAMA_NATIVE_LIB=rust/target/release/libzama_fhe_native.dylib dart test
```

Cross-compile for Android/iOS uses the same crate (NDK clang / xcframework);
that packaging lands with the Flutter integration phase. The `encrypt` call is
synchronous here — the Flutter layer runs it in a background isolate.

## License

BSD-3-Clause-Clear (matching upstream Zama). Patents reserved — commercial use
of Zama's FHE methods requires Zama's patent license.
