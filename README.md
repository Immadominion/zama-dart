# zama-dart — Dart/Flutter SDK for the Zama Protocol (fhEVM)

An open-source SDK giving **Dart & Flutter developers** everything they need to
build confidential applications on the [Zama Protocol](https://docs.zama.org/protocol):
encrypt inputs, call confidential contracts, and decrypt results — publicly or
privately — from a phone.

The full confidential lifecycle has been **verified live on Sepolia**: native
TFHE encryption → relayer-accepted input proof → on-chain transaction → public
decryption (**M1**) and private, threshold-verified user decryption (**M2**).
Encryption also runs in a real Flutter app on an Android device.

> The heavy crypto is **not** reimplemented in Dart — it binds Zama's own Rust
> crates (`tfhe`, `tfhe-zk-pok`, `kms`) via FFI on native, and reuses Zama's
> WASM on web. See the architecture section below.

## Quickstart

One object — `FhevmInstance` — wires the crypto backend, the relayer, and the
pure-Dart protocol glue together. You never touch key material, the 92-byte aux
metadata, or proof assembly by hand.

```dart
import 'package:zama_fhe/zama_fhe.dart';
import 'package:zama_fhe_ffi/zama_fhe_ffi.dart';

final instance = FhevmInstance(
  network: FhevmNetworkConfig.sepolia,
  backend: NativeFhevmBackend(ZamaNative.openDefault()),
);

// 1 — Encrypt inputs for a contract call. Returns the bytes32 handles + the
//     assembled inputProof, ready to pass straight to the contract method.
final enc = await instance
    .createEncryptedInput(contractAddress: counter, userAddress: me)
    .add32(5)            // also: addBool, add8/16/64/128/256, addAddress
    .encrypt();

await contract.send('increment', [enc.handle, enc.inputProof], credentials: creds);

// 2 — Public decryption (handles marked FHE.makePubliclyDecryptable on-chain).
final pub = await instance.publicDecrypt([countHandleHex]);
print(pub.values[countHandleHex]); // BigInt / bool / address, decoded by type

// 3 — Private (user) decryption of your own value. Generates an ephemeral
//     ML-KEM keypair, has your wallet sign the EIP-712 request, calls the
//     relayer, VERIFIES the KMS threshold signatures, then decrypts.
final clears = await instance.userDecrypt(
  pairs: [HandleContractPair(handle: h, contractAddress: counter)],
  contractAddresses: [counter],
  userAddress: me,
  signer: (digest) async => walletSign(digest), // returns a 65-byte signature
  kms: KmsNativeBackend(ZamaKms.openDefault()),
  kmsSigners: kmsSigners, // from KMSVerifier.getKmsSigners()
  threshold: threshold,   // from KMSVerifier.getThreshold()
);
print(clears.single.asBigInt);
```

A returned user-decrypted value is always threshold-verified: `userDecrypt`
throws unless at least `threshold` response signatures recover to a known KMS
signer.

## Architecture — one Dart API, two crypto backends

```
zama_flutter        Flutter widgets · wallet (reown_appkit) · secure keypair vault   [planned]
      │
zama_fhe            Pure-Dart protocol layer  ── the public API lives here
      │             FhevmInstance · EncryptedInputBuilder · configs · handle
      │             computation · EIP-712 · relayer HTTP · KMS sig verification
   ┌──┴───────────────────────────┐
native backend                  web backend
zama_fhe_ffi                    zama_fhe_web                                          [planned]
dart:ffi → tfhe-rs +            dart:js_interop over
tfhe-zk-pok + kms               @zama-fhe/relayer-sdk WASM
(encrypt + ZK proof, ML-KEM)
```

The cryptographically heavy operations (TFHE encryption + a ZK proof over
BLS12-446, and ML-KEM-512 user decryption) are **not** reimplemented in Dart —
they bind Zama's own Rust crates via FFI (native) or reuse Zama's WASM (web).
The entire public API (`FhevmInstance`, the builder, decryption) is portable
pure Dart in `zama_fhe`; a backend just satisfies the `FhevmBackend` /
`KmsBackend` interfaces, so the same app code runs on every platform.

## Status

| Area | Status |
|---|---|
| Technical research & feasibility | ✅ done |
| `zama_fhe` pure-Dart protocol layer | ✅ built, 45 tests (incl. reference known-answer vectors) |
| `zama_fhe_ffi` native encrypt backend (tfhe-rs via `dart:ffi`) | ✅ built & verified host + Android device |
| Native KMS user-decrypt backend (ML-KEM + AES-GCM) | ✅ built & verified live (host dylib) |
| **M1** — confidential tx + public decrypt, live on Sepolia | ✅ **done** |
| **M2** — private user decrypt (threshold-verified), live on Sepolia | ✅ **done** |
| High-level API (`FhevmInstance` + builder + `userDecrypt`) | ✅ done, host-tested |
| FHE type system: ebool, euint8–256, eaddress | ✅ done (euint256/eaddress host round-trip) |
| iOS xcframework + Flutter plugin packaging | ⏳ |
| `zama_fhe_web` JS-interop backend | ⏳ |
| `zama_flutter` widgets + confidential-token helpers | ⏳ |

Platform support today: **Android & desktop (macOS/Linux)** via the native
backend; **iOS** needs the xcframework packaging; **web** needs the JS-interop
backend. The protocol layer is platform-independent.

## Packages

- **[`packages/zama_fhe`](packages/zama_fhe)** — pure-Dart core: `FhevmInstance`,
  `EncryptedInputBuilder`, network configs, ciphertext handle computation, the
  FHE type system, EIP-712 builders, relayer HTTP client, KMS signature
  verification, keccak/hex.
- **[`packages/zama_fhe_ffi`](packages/zama_fhe_ffi)** — native backend:
  `NativeFhevmBackend` (encrypt + ZK proof) and `KmsNativeBackend` (user
  decryption), binding the `zama_fhe_native` and `zama_kms_ffi` Rust libraries.
- **[`example`](example)** — a Flutter app running native FHE encryption on
  device.

## Develop

```bash
cd packages/zama_fhe && dart pub get && dart test       # pure-Dart, no native lib
cd ../zama_fhe_ffi  && dart pub get
# Build the desktop native lib, then run the FFI round-trip tests:
(cd rust && cargo build --release)
ZAMA_NATIVE_LIB=rust/target/release/libzama_fhe_native.dylib dart test
```

### Cross-compiling the native library

The crypto crate (`packages/zama_fhe_ffi/rust`) pins **tfhe 1.5.4 / tfhe-zk-pok
0.8.0** on **Rust 1.91.1** (the versions the Zama network verifies). Two
build-environment notes that aren't obvious:

```bash
# Android (arm64) — blake3's NEON C path needs a C compiler; the Cargo.toml
# forces blake3's pure-Rust path for Android so only the Rust toolchain is
# needed. LTO is left off for the cross-build (fat LTO links the 157 MB bitcode
# rlibs in one shot and is very memory-hungry):
NDK=$ANDROID_NDK/toolchains/llvm/prebuilt/<host>/bin
CARGO_PROFILE_RELEASE_LTO=false \
  cargo build --release --lib --target aarch64-linux-android
# → target/aarch64-linux-android/release/libzama_fhe_native.so  (bundle in jniLibs/arm64-v8a)

# iOS (device + simulator) → an xcframework:
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
CARGO_PROFILE_RELEASE_LTO=false cargo build --release --lib --target aarch64-apple-ios
CARGO_PROFILE_RELEASE_LTO=false cargo build --release --lib --target aarch64-apple-ios-sim
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libzama_fhe_native.a \
  -library target/aarch64-apple-ios-sim/release/libzama_fhe_native.a \
  -output ios/libzama_fhe_native.xcframework
```

On iOS the static lib is linked into the app and its symbols resolved via
`DynamicLibrary.process()`, so it must be `-force_load`ed (see the example's
`ios/Flutter/Debug.xcconfig`) to survive dead-stripping.

Live on-chain tests (M1/M2) are opt-in and gated behind `ZAMA_NETWORK_TESTS=1`
plus a funded Sepolia key and deployed contracts — see each test's header.

## License

BSD-3-Clause-Clear (matching upstream Zama). Commercial use of Zama's patented
FHE methods requires Zama's patent license — see the feasibility study.
