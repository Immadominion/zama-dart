# zama_fhe

The **public Dart API** for the Zama Protocol (fhEVM) plus all the pure-Dart
protocol glue behind it. No Flutter, no native, no web dependency — the same code
runs on every platform; a crypto backend (`zama_fhe_ffi` native, or web JS
interop) just satisfies the `FhevmBackend` / `KmsBackend` interfaces.

It is a faithful, **test-verified** port of the client half of
[`@zama-fhe/relayer-sdk`](https://github.com/zama-ai/relayer-sdk).

## What's in here

| Area | Status | Notes |
|---|---|---|
| **High-level client (`FhevmInstance`)** | ✅ | one object: `createEncryptedInput`, `publicDecrypt`, `userDecrypt`, lazy key fetch |
| **Encrypted-input builder (`EncryptedInputBuilder`)** | ✅ | fluent `.addBool/.add8..256/.addAddress` → `.encrypt()` → `{handles, inputProof}` |
| **User-decrypt orchestration** | ✅ | keygen → EIP-712 → sign → relayer → **threshold verify** → decrypt, in one call |
| Backend interfaces (`FhevmBackend`, `KmsBackend`) | ✅ | pluggable native/web crypto; `FheInputValue`, `EncryptedPayload`, `DecryptedValue` |
| Network configs (`FhevmNetworkConfig`) | ✅ | Sepolia + mainnet addresses, chain ids, gateway ids, relayer URLs |
| FHE type system (`FheType`) | ✅ | `ebool`, `euint8..256`, `eaddress` with on-chain type ids |
| Ciphertext handle computation (`FhevmHandle`) | ✅ | client-side keccak derivation + exact 32-byte layout |
| EIP-712 typed data (`Eip712TypedData`, `KmsEip712`) | ✅ | user / delegated / public decryption authorization |
| Relayer client (`RelayerClient`) | ✅ | `/keyurl`, `/input-proof`, `/public-decrypt`, `/user-decrypt` — async POST/poll, Retry-After, typed errors. **Accepted live by Sepolia.** |
| `inputProof` assembly + public-decrypt decode | ✅ | byte assembly; cleartext decode (`ebool`/`eaddress`/`euintX`) |
| KMS threshold-signature verification (`KmsResponseVerifier`) | ✅ | recovers each response sig vs on-chain `getKmsSigners()` ≥ `getThreshold()` |
| On-chain calls (`ConfidentialContract`) | ✅ | web3dart wrapper: maps handles→bytes32, encodes/sends `{handle, inputProof}`, reads state |
| keccak256 + hex utils | ✅ | Ethereum keccak (via pointycastle) |
| TFHE encryption + ZK proof | ⛔ native backend | heavy crypto; provided by `zama_fhe_ffi` (Rust FFI) / WASM backend |
| ML-KEM user-decryption unwrap | ⛔ native backend | the `kms` client crypto; provided by `zama_fhe_ffi` (`KmsNativeBackend`) |

Proven end-to-end on **live Sepolia**: encrypt → relayer accepts → on-chain
`increment` → public-decrypt (**M1**) and private threshold-verified user-decrypt
(**M2**). See `../../ROADMAP.md`.

## Verification

The handle computation is checked against the **exact reference test vectors**
shipped in `@zama-fhe/relayer-sdk` (`input-proof-payload-*.json`): real proven
ciphertext blobs and the handles the official SDK derived from them, across
multiple FHE types and multi-input proofs. The EIP-712 implementation is checked
against the canonical EIP-712 "Mail" domain-separator and signing-digest vectors.

```bash
dart pub get
dart test      # 45 passing, incl. reference handle vectors + EIP-712 vectors
```

## Example

The everyday path uses `FhevmInstance` (see the repo root README for the full
encrypt → on-chain → decrypt quickstart). The lower-level primitives are also
public when you need them:

```dart
import 'package:zama_fhe/zama_fhe.dart';

const net = FhevmNetworkConfig.sepolia;

// Compute handles client-side from a proven blob (never trust the relayer):
final handles = FhevmHandle.computeInputHandles(
  ciphertextWithZkProof: provenBlob,        // from the crypto backend
  aclContractAddress: net.aclContractAddress,
  chainId: BigInt.from(net.chainId),
  encryptionBits: [32],                      // one euint32 input
);

// Build EIP-712 typed data for a private user decryption; hand `.toJson()`
// to a wallet for `eth_signTypedData_v4`:
final typedData = KmsEip712.fromNetwork(net).createUserDecrypt(
  publicKey: ephemeralMlKemPublicKeyHex,
  contractAddresses: [contractAddress],
  startTimestamp: nowSeconds,
  durationDays: 7,
);
```

## License

BSD-3-Clause-Clear (matching the upstream Zama crates). Note: Zama's FHE methods
are patented; commercial use requires Zama's patent license.
