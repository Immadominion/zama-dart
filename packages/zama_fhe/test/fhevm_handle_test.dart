import 'dart:convert';
import 'dart:io';

import 'package:zama_fhe/zama_fhe.dart';
import 'package:test/test.dart';

/// End-to-end known-answer tests: the fixtures are the exact
/// `input-proof-payload-*.json` assets from `@zama-fhe/relayer-sdk`, each
/// containing a real proven ciphertext blob and the handles the reference SDK
/// computed from it. If our keccak + byte layout matches theirs, the handles
/// match exactly.
void main() {
  group('FhevmHandle.computeInputHandles (reference vectors)', () {
    for (final n in [1, 2, 3, 4]) {
      test('input-proof-payload-$n', () {
        final json = jsonDecode(
          File('test/fixtures/input-proof-payload-$n.json').readAsStringSync(),
        ) as Map<String, dynamic>;

        final blob = hexToBytes(json['ciphertextWithInputVerification'] as String);
        final acl = json['aclAddress'] as String;
        final chainId = BigInt.from(json['chainId'] as int);
        final bits = (json['fheTypeEncryptionBitwidths'] as List).cast<int>();
        final version = json['ciphertextVersion'] as int;
        // Some fixtures carry expected handles at the top level, others only in
        // the captured relayer response — both are the reference's values.
        final expected = ((json['handles'] ??
                (json['fetch_json']['response']['handles'])) as List)
            .cast<String>();

        final handles = FhevmHandle.computeInputHandles(
          ciphertextWithZkProof: blob,
          aclContractAddress: acl,
          chainId: chainId,
          encryptionBits: bits,
          version: version,
        );

        expect(handles.length, expected.length);
        for (var i = 0; i < handles.length; i++) {
          expect(handles[i].toBytes32Hex(), expected[i],
              reason: 'handle[$i] mismatch');
        }
      });
    }
  });

  group('FhevmHandle round-trip & layout', () {
    const sample =
        '0x20244f826737772a0b7f1254c1cc982d83094d65ec000000000000aa36a70400';

    test('parses byte layout correctly', () {
      final h = FhevmHandle.fromBytes32Hex(sample);
      expect(h.index, 0);
      expect(h.computed, false);
      expect(h.chainId, BigInt.from(11155111)); // 0xaa36a7 Sepolia
      expect(h.fheType, FheType.euint32); // id 4
      expect(h.version, 0);
    });

    test('fromBytes32Hex -> toBytes32Hex is identity', () {
      expect(FhevmHandle.fromBytes32Hex(sample).toBytes32Hex(), sample);
    });

    test('computed handle sets index byte 0xff', () {
      final h = FhevmHandle.fromComponents(
        hash21: FhevmHandle.fromBytes32Hex(sample).hash21,
        chainId: BigInt.from(11155111),
        fheType: FheType.euint64,
        computed: true,
      );
      expect(h.toBytes32()[21], 255);
      expect(h.toBytes32()[30], FheType.euint64.id);
    });
  });
}
