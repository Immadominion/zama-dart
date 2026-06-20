/// Pure-Dart client primitives for the Zama Protocol (fhEVM).
///
/// This library has no Flutter or native dependency. It provides the protocol
/// glue that is identical across native (FFI) and web (JS interop) crypto
/// backends:
///
/// - [FhevmNetworkConfig] — network configs (Sepolia, mainnet).
/// - [FheType] — the encrypted type system.
/// - [FhevmHandle] — client-side ciphertext handle computation.
/// - [KmsEip712] / [Eip712TypedData] — typed data for user/public decryption.
/// - keccak256 / hex helpers.
library;

export 'src/config/networks.dart';
export 'src/evm/confidential_contract.dart';
export 'src/instance/aux_metadata.dart';
export 'src/instance/encrypted_input.dart';
export 'src/instance/fhevm_backend.dart';
export 'src/instance/fhevm_instance.dart';
export 'src/instance/key_cache.dart';
export 'src/instance/kms_backend.dart';
export 'src/kms/kms_response_verifier.dart';
export 'src/relayer/input_proof.dart';
export 'src/relayer/key_material.dart';
export 'src/relayer/public_decrypt.dart';
export 'src/relayer/relayer_client.dart';
export 'src/relayer/user_decrypt.dart';
export 'src/eip712/eip712.dart';
export 'src/eip712/kms_eip712.dart';
export 'src/handle/fhevm_handle.dart';
export 'src/types/fhe_type.dart';
export 'src/utils/hex.dart' show hexToBytes, bytesToHex, strip0x, ensure0x;
export 'src/utils/keccak.dart';
