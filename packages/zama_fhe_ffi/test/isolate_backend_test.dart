import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:zama_fhe/zama_fhe.dart';
import 'package:zama_fhe_ffi/zama_fhe_ffi.dart';
import 'package:test/test.dart';

/// Verifies the off-main-thread encryption path that keeps a Flutter UI
/// responsive: the native dylib loads and runs inside a spawned `Isolate.run`,
/// and the (sendable) results come back across the isolate boundary.
///
/// Requires the native dylib (set ZAMA_NATIVE_LIB or build the rust crate).
void main() {
  final libPath = _resolveLib();

  test('native encrypt + verify runs inside a background isolate', () async {
    final clears = await Isolate.run(() {
      final native = ZamaNative.open(libPath);
      final ctx = native.generatedContext(maxBits: 256);
      try {
        final meta = Uint8List(92);
        final res = ctx.encrypt(
          inputs: [
            ClearInput.ofInt(42, FheType.euint64),
            ClearInput.ofBool(true),
          ],
          metadata: meta,
          aclContractAddress: '0x${'a1' * 20}',
          chainId: BigInt.from(11155111),
        );
        return ctx.testVerifyDecrypt(
          blob: res.inputProof,
          types: [FheType.euint64, FheType.ebool],
          metadata: meta,
        );
      } finally {
        ctx.dispose();
      }
    });

    // BigInt results survived the isolate hop.
    expect(clears, [BigInt.from(42), BigInt.one]);
  });

  group('IsolateFhevmBackend', () {
    test('is not ready until key material is supplied', () {
      final backend = IsolateFhevmBackend(libPath: libPath);
      expect(backend.isReady, isFalse);
      backend.useKeyMaterial(
          publicKey: Uint8List(4), crs: Uint8List(4));
      expect(backend.isReady, isTrue);
      backend.dispose();
      expect(backend.isReady, isFalse);
    });

    test('encrypt before useKeyMaterial throws', () {
      final backend = IsolateFhevmBackend(libPath: libPath);
      expect(
        () => backend.encrypt(
          inputs: const [],
          metadata: Uint8List(92),
          aclContractAddress: '0x${'a1' * 20}',
          chainId: BigInt.from(11155111),
        ),
        throwsStateError,
      );
    });
  });
}

String _resolveLib() {
  final env = Platform.environment['ZAMA_NATIVE_LIB'];
  final candidates = <String>[
    if (env != null && env.isNotEmpty) env,
    'rust/target/release/libzama_fhe_native.dylib',
    'rust/target/release/libzama_fhe_native.so',
  ];
  for (final c in candidates) {
    if (File(c).existsSync()) return File(c).absolute.path;
  }
  throw StateError('set ZAMA_NATIVE_LIB or build the rust crate to run this test');
}
