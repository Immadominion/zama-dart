import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:zama_fhe/zama_fhe.dart';
import 'package:zama_fhe_ffi/zama_fhe_ffi.dart';
import 'package:test/test.dart';

/// Proves the full client stack with REAL crypto but no network: the high-level
/// [FhevmInstance] + [EncryptedInputBuilder] driving a [NativeFhevmBackend]
/// (tfhe-rs via FFI), with the relayer's `/input-proof` round-trip mocked.
///
/// Requires the native dylib (set ZAMA_NATIVE_LIB or build the rust crate).
void main() {
  const net = FhevmNetworkConfig.sepolia;
  final contract = '0x${'a1' * 20}';
  final me = '0x${'b2' * 20}';

  late ZamaNative native;
  late ZamaContext ctx;

  setUpAll(() {
    native = ZamaNative.openDefault();
    ctx = native.generatedContext(maxBits: 256);
  });

  tearDownAll(() => ctx.dispose());

  test('builder -> native backend -> assembled inputProof, values verify',
      () async {
    final big = (BigInt.one << 200) | BigInt.from(0xabcdef);

    // Mock /input-proof: capture the raw proof blob the client uploaded, return
    // KMS handles + a signature so the builder can assemble the on-chain proof.
    String? uploadedBlobHex;
    final mock = MockClient((req) async {
      final body = jsonDecode(req.body) as Map<String, dynamic>;
      uploadedBlobHex = body['ciphertextWithInputVerification'] as String;
      return http.Response(
        jsonEncode({
          'result': {
            'accepted': true,
            'handles': ['0x${'11' * 32}', '0x${'22' * 32}'],
            'signatures': ['0x${'ab' * 65}'],
            'extraData': '0x00',
          }
        }),
        200,
      );
    });

    // The backend wraps the generated context directly (no key fetch needed).
    final backend = NativeFhevmBackend.withContext(ctx);
    final instance =
        FhevmInstance(network: net, backend: backend, httpClient: mock);

    final enc = await instance
        .createEncryptedInput(contractAddress: contract, userAddress: me)
        .add64(42)
        .add256(big)
        .encrypt();

    // Two real handles, correct type tags, each bytes32.
    expect(enc.handles.length, 2);
    expect(enc.typedHandles[0].fheType, FheType.euint64);
    expect(enc.typedHandles[1].fheType, FheType.euint256);
    for (final h in enc.handles) {
      expect(h.length, 32);
    }

    // The blob uploaded to the relayer is a REAL tfhe proof — verify+decrypt it
    // back through the native context to confirm the encrypted values.
    final blob = hexToBytes(uploadedBlobHex!);
    final clears = ctx.testVerifyDecrypt(
      blob: blob,
      types: [FheType.euint64, FheType.euint256],
      metadata: buildInputMetadata(
          contractAddress: contract, userAddress: me, network: net),
    );
    expect(clears, [BigInt.from(42), big]);

    // The assembled on-chain proof is well-formed (2 handles + 1 signature).
    final parsed = InputProof.parse(enc.inputProof);
    expect(parsed.handles.length, 2);
    expect(parsed.signatures.single, '0x${'ab' * 65}');

    instance.relayer.close();
  });
}
