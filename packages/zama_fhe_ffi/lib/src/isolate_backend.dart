import 'dart:isolate';
import 'dart:typed_data';

import 'package:zama_fhe/zama_fhe.dart';

import '../zama_fhe_ffi.dart';

/// A [FhevmBackend] that runs the CPU-heavy native encryption (TFHE encrypt +
/// ZK proof, hundreds of ms) on a **background isolate** so the Flutter UI
/// thread stays responsive.
///
/// The network key material (public key + CRS) is supplied via [useKeyMaterial]
/// and shipped to the worker isolate per encryption; the native library is
/// opened inside the isolate. Use this in Flutter apps; the synchronous
/// [NativeFhevmBackend] is fine for CLI/server code or when you already manage
/// your own threading.
///
/// ```dart
/// final instance = FhevmInstance(
///   network: FhevmNetworkConfig.sepolia,
///   backend: IsolateFhevmBackend(),
/// );
/// final enc = await instance        // encrypt() now runs off the UI thread
///     .createEncryptedInput(contractAddress: c, userAddress: me)
///     .add64(1000)
///     .encrypt();
/// ```
class IsolateFhevmBackend implements FhevmBackend {
  /// [libPath] is an explicit path to the native library; when null the worker
  /// isolate calls [ZamaNative.openDefault] (Android loads `libzama_fhe_native.so`
  /// by name; desktop reads the `ZAMA_NATIVE_LIB` env var or build dirs).
  IsolateFhevmBackend({this.libPath});

  final String? libPath;
  Uint8List? _publicKey;
  Uint8List? _crs;

  @override
  bool get isReady => _publicKey != null && _crs != null;

  @override
  void useKeyMaterial({required Uint8List publicKey, required Uint8List crs}) {
    _publicKey = publicKey;
    _crs = crs;
  }

  @override
  Future<EncryptedPayload> encrypt({
    required List<FheInputValue> inputs,
    required Uint8List metadata,
    required String aclContractAddress,
    required BigInt chainId,
  }) {
    final pk = _publicKey;
    final crs = _crs;
    if (pk == null || crs == null) {
      throw StateError(
          'IsolateFhevmBackend is not ready: call useKeyMaterial first');
    }
    final path = libPath;
    // Only sendable values are captured (bytes, BigInt, enum, String).
    return Isolate.run(() => _encryptInIsolate(
          libPath: path,
          publicKey: pk,
          crs: crs,
          inputs: inputs,
          metadata: metadata,
          aclContractAddress: aclContractAddress,
          chainId: chainId,
        ));
  }

  @override
  void dispose() {
    _publicKey = null;
    _crs = null;
  }
}

/// Top-level worker run inside the spawned isolate: open the library, build a
/// context from the artifacts, encrypt, and return the (sendable) result.
EncryptedPayload _encryptInIsolate({
  required String? libPath,
  required Uint8List publicKey,
  required Uint8List crs,
  required List<FheInputValue> inputs,
  required Uint8List metadata,
  required String aclContractAddress,
  required BigInt chainId,
}) {
  final native =
      libPath != null ? ZamaNative.open(libPath) : ZamaNative.openDefault();
  final ctx = native.contextFromArtifacts(publicKey, crs);
  try {
    final res = ctx.encrypt(
      inputs: [for (final i in inputs) ClearInput(i.value, i.type)],
      metadata: metadata,
      aclContractAddress: aclContractAddress,
      chainId: chainId,
    );
    return EncryptedPayload(inputProof: res.inputProof, handles: res.handles);
  } finally {
    ctx.dispose();
  }
}
