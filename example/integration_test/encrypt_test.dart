import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:zama_fhe/zama_fhe.dart';
import 'package:zama_fhe_ffi/zama_fhe_ffi.dart';

/// Runs the native FHE encrypt + verify round-trip ON THE DEVICE, inside a real
/// Flutter app, loading the bundled `libzama_fhe_native.so` via dart:ffi.
///
///   flutter test integration_test/encrypt_test.dart -d `device`
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('native FHE encrypt + verify on device', (tester) async {
    final native = ZamaNative.openDefault(); // loads libzama_fhe_native.so
    final ctx = native.generatedContext(maxBits: 256);
    try {
      final res = ctx.encrypt(
        inputs: [
          ClearInput.ofInt(42, FheType.euint64),
          ClearInput.ofInt(7, FheType.euint32),
          ClearInput.ofBool(true),
        ],
        metadata: Uint8List(92),
        aclContractAddress: '0x${'00' * 20}',
        chainId: BigInt.from(11155111),
      );

      expect(res.handles.length, 3);
      expect(res.handles[0].fheType, FheType.euint64);
      expect(res.handles[1].fheType, FheType.euint32);
      expect(res.handles[2].fheType, FheType.ebool);
      expect(res.inputProof.length, greaterThan(1000));

      final decoded = ctx.testVerifyDecrypt(
        blob: res.inputProof,
        types: const [FheType.euint64, FheType.euint32, FheType.ebool],
        metadata: Uint8List(92),
      );
      expect(decoded, [BigInt.from(42), BigInt.from(7), BigInt.one]);
    } finally {
      ctx.dispose();
    }
  }, timeout: const Timeout(Duration(minutes: 3)));
}
