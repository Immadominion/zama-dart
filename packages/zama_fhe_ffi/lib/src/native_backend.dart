import 'dart:typed_data';

import 'package:zama_fhe/zama_fhe.dart';

import '../zama_fhe_ffi.dart';

/// The native ([dart:ffi] / `tfhe-rs`) implementation of [FhevmBackend].
///
/// Wraps a [ZamaNative] library handle; builds a [ZamaContext] from the network
/// key material on first use and reuses it for every encryption. Suitable for
/// mobile (Android/iOS) and desktop targets where the native crypto library is
/// available.
///
/// ```dart
/// final instance = FhevmInstance(
///   network: FhevmNetworkConfig.sepolia,
///   backend: NativeFhevmBackend(ZamaNative.openDefault()),
/// );
/// ```
class NativeFhevmBackend implements FhevmBackend {
  /// Creates a backend over a loaded native library [native]. The context is
  /// built lazily from key material via [useKeyMaterial].
  NativeFhevmBackend(ZamaNative native) : _native = native;

  /// Creates a backend over a pre-built [context] (e.g. a test-generated one).
  /// [useKeyMaterial] becomes a no-op since the context already holds keys.
  NativeFhevmBackend.withContext(ZamaContext context)
      : _native = null,
        _ctx = context;

  final ZamaNative? _native;
  ZamaContext? _ctx;

  @override
  bool get isReady => _ctx != null;

  @override
  void useKeyMaterial({required Uint8List publicKey, required Uint8List crs}) {
    if (_ctx != null) return; // already have a context
    final native = _native;
    if (native == null) {
      throw StateError('NativeFhevmBackend has no library to build a context');
    }
    _ctx = native.contextFromArtifacts(publicKey, crs);
  }

  @override
  EncryptedPayload encrypt({
    required List<FheInputValue> inputs,
    required Uint8List metadata,
    required String aclContractAddress,
    required BigInt chainId,
  }) {
    final ctx = _ctx;
    if (ctx == null) {
      throw StateError(
          'NativeFhevmBackend is not ready: call useKeyMaterial first');
    }
    final result = ctx.encrypt(
      inputs: [for (final i in inputs) ClearInput(i.value, i.type)],
      metadata: metadata,
      aclContractAddress: aclContractAddress,
      chainId: chainId,
    );
    return EncryptedPayload(
      inputProof: result.inputProof,
      handles: result.handles,
    );
  }

  @override
  void dispose() {
    _ctx?.dispose();
    _ctx = null;
  }
}
