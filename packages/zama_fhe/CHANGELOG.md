# Changelog

## 0.0.1

Initial public preview of `zama_fhe` — the pure-Dart core of the first
Dart/Flutter SDK for the Zama Protocol (fhEVM).

- `FhevmInstance` — wires a crypto backend, the relayer, and the protocol glue
  into one entry point (`createEncryptedInput`, `publicDecrypt`, `userDecrypt`).
- `EncryptedInputBuilder` — typed input assembly (`addBool`, `add8`/`16`/`32`/
  `64`/`128`/`256`, `addAddress`) with range validation.
- FHE type system: `ebool`, `euint8`–`euint256`, `eaddress`.
- Ciphertext handle computation, 92-byte auxiliary input metadata, EIP-712
  typed-data builders for user/public decryption.
- Relayer HTTP client with content-addressed key-material caching.
- KMS threshold-signature verification (a user-decrypted value is rejected
  unless at least `threshold` responses recover to a known KMS signer).
- Pluggable `FhevmBackend` / `KmsBackend` interfaces — the cryptographically
  heavy work (TFHE encryption + ZK proof, ML-KEM user decryption) is supplied by
  separate native (`zama_fhe_ffi`) or web backends, so the same app code is
  portable across platforms.

The full confidential lifecycle (encrypt → ZK input proof → on-chain tx →
public decryption and private threshold-verified user decryption) has been
verified live on Sepolia, including on-device encryption in a Flutter app on
Android and iOS.
