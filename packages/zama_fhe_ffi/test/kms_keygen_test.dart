import 'dart:io';

import 'package:zama_fhe_ffi/zama_kms.dart';
import 'package:test/test.dart';

/// Verifies the native KMS FFI keygen over the boundary.
///   ZAMA_KMS_LIB=native/kms/target/debug/libzama_kms_ffi.dylib dart test test/kms_keygen_test.dart
final _enabled = Platform.environment['ZAMA_KMS_LIB'] != null;

void main() {
  group('ZamaKms.generateKeypair (native FFI)', () {
    test('produces an ML-KEM-512 keypair of the expected sizes', () {
      final kms = ZamaKms.openDefault();
      final kp = kms.generateKeypair();
      // ML-KEM-512 pk ~800 bytes + safe-serialization framing.
      expect(kp.publicKey.length, greaterThan(800));
      // sk is larger (decapsulation key).
      expect(kp.secretKey.length, greaterThan(1000));
      // Two keygens differ (fresh randomness).
      final kp2 = kms.generateKeypair();
      expect(kp2.publicKey, isNot(equals(kp.publicKey)));
    });
  }, skip: _enabled ? false : 'set ZAMA_KMS_LIB to run the native KMS keygen test');
}
