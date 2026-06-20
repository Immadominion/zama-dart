import 'dart:async';
import 'dart:typed_data';

import '../handle/fhevm_handle.dart';
import '../types/fhe_type.dart';

/// A single cleartext value to encrypt, tagged with its FHE type.
///
/// The numeric [value] is an unsigned magnitude (0 ≤ value < 2^bits). For an
/// `eaddress` it is the 160-bit address as an integer.
class FheInputValue {
  const FheInputValue(this.value, this.type);

  final BigInt value;
  final FheType type;

  @override
  String toString() => 'FheInputValue(${type.typeName}: $value)';
}

/// The output of a backend encryption: the proven ciphertext blob (the relayer
/// `inputProof` input) plus the client-computed [FhevmHandle]s for each value.
class EncryptedPayload {
  const EncryptedPayload({required this.inputProof, required this.handles});

  /// The safe-serialized proven compact ciphertext list.
  final Uint8List inputProof;

  /// One handle per input, in order.
  final List<FhevmHandle> handles;
}

/// A pluggable crypto backend behind [FhevmInstance].
///
/// Two implementations are planned: native (FFI over `tfhe-rs`, for
/// mobile/desktop) and web (JS interop over `@zama-fhe/relayer-sdk`). The
/// backend owns the heavy TFHE primitives; everything else (relayer HTTP, handle
/// computation, EIP-712) is shared pure-Dart code.
abstract class FhevmBackend {
  /// Supplies the network key material (public key + CRS) the backend needs to
  /// encrypt. Idempotent — a backend that already holds a context ignores this.
  void useKeyMaterial({required Uint8List publicKey, required Uint8List crs});

  /// Whether key material is loaded and the backend can [encrypt].
  bool get isReady;

  /// Encrypts [inputs] into a proven compact ciphertext list and computes the
  /// corresponding handles. [metadata] is the 92-byte protocol aux blob
  /// (`contract|user|acl|chainId`); [aclContractAddress] and [chainId] feed
  /// handle computation.
  ///
  /// Returns a [FutureOr] so a backend may compute synchronously (direct FFI) or
  /// asynchronously (e.g. on a background isolate to keep the UI responsive).
  FutureOr<EncryptedPayload> encrypt({
    required List<FheInputValue> inputs,
    required Uint8List metadata,
    required String aclContractAddress,
    required BigInt chainId,
  });

  /// Releases any native resources held by the backend.
  void dispose();
}
