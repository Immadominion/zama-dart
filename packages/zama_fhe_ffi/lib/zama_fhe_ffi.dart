/// Native (FFI) crypto backend for the Zama Protocol Dart SDK.
///
/// Binds `zama_fhe_native` (tfhe-rs) for TFHE encryption + ZK proof generation.
/// The heavy call (`encrypt`, ~hundreds of ms) is synchronous here; the Flutter
/// integration runs it in a background isolate so the UI stays responsive.
library;

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:zama_fhe/zama_fhe.dart';

import 'src/bindings.dart';

export 'src/bindings.dart' show NativeByteBuf;
export 'src/isolate_backend.dart';
export 'src/kms_native_backend.dart';
export 'src/native_backend.dart';

/// A cleartext value paired with the FHE type it should be encrypted as.
class ClearInput {
  const ClearInput(this.value, this.type);

  /// Unsigned magnitude, up to 256-bit (the marshalled width is 32 bytes).
  final BigInt value;
  final FheType type;

  /// Convenience for values that fit in a Dart int.
  factory ClearInput.ofInt(int value, FheType type) =>
      ClearInput(BigInt.from(value), type);

  /// Convenience for booleans (`ebool`).
  factory ClearInput.ofBool(bool value) =>
      ClearInput(value ? BigInt.one : BigInt.zero, FheType.ebool);

  /// Convenience for a `euint256` from a [BigInt] (0 ≤ value < 2^256).
  factory ClearInput.ofUint256(BigInt value) =>
      ClearInput(value, FheType.euint256);

  /// Convenience for an `eaddress` from a `0x`-prefixed 20-byte hex address.
  factory ClearInput.ofAddress(String hexAddress) {
    final h = hexAddress.startsWith('0x') || hexAddress.startsWith('0X')
        ? hexAddress.substring(2)
        : hexAddress;
    if (h.length != 40) {
      throw ArgumentError.value(
          hexAddress, 'hexAddress', 'expected a 20-byte (40 hex char) address');
    }
    return ClearInput(BigInt.parse(h, radix: 16), FheType.eaddress);
  }
}

/// Loads and owns the native library.
class ZamaNative {
  ZamaNative._(this._b);

  final ZamaNativeBindings _b;

  /// Opens the native library at [path].
  factory ZamaNative.open(String path) =>
      ZamaNative._(ZamaNativeBindings(DynamicLibrary.open(path)));

  /// Opens the library from `ZAMA_NATIVE_LIB` or a few common build locations.
  factory ZamaNative.openDefault() {
    // On Android the .so is packaged in the APK and loaded by name.
    if (Platform.isAndroid) {
      return ZamaNative.open('libzama_fhe_native.so');
    }
    // On iOS the staticlib is linked into the app binary (symbols in-process).
    if (Platform.isIOS) {
      return ZamaNative._(ZamaNativeBindings(DynamicLibrary.process()));
    }
    final fromEnv = Platform.environment['ZAMA_NATIVE_LIB'];
    final candidates = <String>[
      if (fromEnv != null) fromEnv,
      _platformLib('rust/target/release'),
      _platformLib('packages/zama_fhe_ffi/rust/target/release'),
      _platformLib('../zama_fhe_ffi/rust/target/release'),
    ];
    for (final c in candidates) {
      if (File(c).existsSync()) return ZamaNative.open(c);
    }
    throw StateError(
        'Could not locate libzama_fhe_native. Set ZAMA_NATIVE_LIB or build the '
        'rust crate. Tried:\n${candidates.join('\n')}');
  }

  static String _platformLib(String dir) {
    final name = Platform.isWindows
        ? 'zama_fhe_native.dll'
        : Platform.isMacOS
            ? 'libzama_fhe_native.dylib'
            : 'libzama_fhe_native.so';
    return '$dir/$name';
  }

  /// Builds a context from the network public key + CRS (relayer artifacts).
  ZamaContext contextFromArtifacts(Uint8List publicKey, Uint8List crs) {
    final pk = _toNative(publicKey);
    final crsP = _toNative(crs);
    try {
      final ctx = _b.ctxNew(pk, publicKey.length, crsP, crs.length);
      if (ctx == nullptr) {
        throw StateError('zama_ctx_new failed (bad public key or CRS)');
      }
      return ZamaContext._(_b, ctx);
    } finally {
      calloc.free(pk);
      calloc.free(crsP);
    }
  }

  /// Test/dev: generate a context (keys + CRS sized for [maxBits]).
  ZamaContext generatedContext({int maxBits = 256}) {
    final ctx = _b.ctxNewGenerated(maxBits);
    if (ctx == nullptr) throw StateError('zama_ctx_new_generated failed');
    return ZamaContext._(_b, ctx);
  }
}

/// A native context (public key + CRS). Dispose when done.
class ZamaContext {
  ZamaContext._(this._b, this._ctx);

  final ZamaNativeBindings _b;
  Pointer<Void> _ctx;

  /// Encrypts [inputs] into a proven compact ciphertext list (the relayer
  /// `inputProof` blob) and computes the corresponding [FhevmHandle]s.
  ///
  /// [metadata] is the protocol aux data (contract|user|acl|chainId).
  EncryptResult encrypt({
    required List<ClearInput> inputs,
    required Uint8List metadata,
    required String aclContractAddress,
    required BigInt chainId,
  }) {
    final n = inputs.length;
    final values = calloc<Uint8>(n * 32);
    final types = calloc<Uint8>(n);
    final meta = _toNative(metadata);
    final out = calloc<NativeByteBuf>();
    try {
      for (var i = 0; i < n; i++) {
        _writeBe32(values, i * 32, inputs[i].value);
        types[i] = inputs[i].type.id;
      }
      final rc = _b.encrypt(_ctx, values, types, n, meta, metadata.length, out);
      if (rc != 0) {
        throw StateError('zama_encrypt failed (code $rc)');
      }
      final blob = _copyByteBuf(out.ref);
      _b.bytesFree(out.ref);

      final handles = FhevmHandle.computeInputHandles(
        ciphertextWithZkProof: blob,
        aclContractAddress: aclContractAddress,
        chainId: chainId,
        encryptionBits: [for (final i in inputs) i.type.encryptionBits],
      );
      return EncryptResult(inputProof: blob, handles: handles);
    } finally {
      calloc.free(values);
      calloc.free(types);
      calloc.free(meta);
      calloc.free(out);
    }
  }

  /// Test-only: verify a proven blob and decrypt its values (requires a
  /// generated context that holds the client key).
  List<BigInt> testVerifyDecrypt({
    required Uint8List blob,
    required List<FheType> types,
    required Uint8List metadata,
  }) {
    final n = types.length;
    final blobP = _toNative(blob);
    final typesP = calloc<Uint8>(n);
    final meta = _toNative(metadata);
    final outVals = calloc<Uint8>(n * 32);
    try {
      for (var i = 0; i < n; i++) {
        typesP[i] = types[i].id;
      }
      final rc = _b.verifyDecrypt(
          _ctx, blobP, blob.length, typesP, n, meta, metadata.length, outVals, n);
      if (rc < 0) {
        throw StateError('zama_test_verify_decrypt failed (code $rc)');
      }
      return [for (var i = 0; i < n; i++) _readBe32(outVals, i * 32)];
    } finally {
      calloc.free(blobP);
      calloc.free(typesP);
      calloc.free(meta);
      calloc.free(outVals);
    }
  }

  void dispose() {
    if (_ctx != nullptr) {
      _b.ctxFree(_ctx);
      _ctx = nullptr;
    }
  }

  Uint8List _copyByteBuf(NativeByteBuf b) {
    final out = Uint8List(b.len);
    final src = b.ptr.asTypedList(b.len);
    out.setAll(0, src);
    return out;
  }
}

/// Result of an encryption: the proof blob + the derived handles.
class EncryptResult {
  const EncryptResult({required this.inputProof, required this.handles});
  final Uint8List inputProof;
  final List<FhevmHandle> handles;
}

Pointer<Uint8> _toNative(Uint8List bytes) {
  final p = calloc<Uint8>(bytes.length);
  p.asTypedList(bytes.length).setAll(0, bytes);
  return p;
}

void _writeBe32(Pointer<Uint8> base, int offset, BigInt v) {
  final mask = BigInt.from(0xff);
  var x = v;
  for (var j = 31; j >= 0; j--) {
    base[offset + j] = (x & mask).toInt();
    x = x >> 8;
  }
}

BigInt _readBe32(Pointer<Uint8> base, int offset) {
  var v = BigInt.zero;
  for (var j = 0; j < 32; j++) {
    v = (v << 8) | BigInt.from(base[offset + j]);
  }
  return v;
}
