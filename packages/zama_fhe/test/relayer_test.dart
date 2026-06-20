import 'dart:convert';
import 'dart:io';

import 'package:zama_fhe/zama_fhe.dart';
import 'package:test/test.dart';

void main() {
  group('KeyUrlResponse parser (real Sepolia /keyurl fixture)', () {
    late KeyUrlResponse parsed;

    setUpAll(() {
      final json = jsonDecode(
        File('test/fixtures/keyurl-sepolia.json').readAsStringSync(),
      ) as Map<String, dynamic>;
      parsed = KeyUrlResponse.fromJson(json);
    });

    test('extracts the public key entry', () {
      expect(parsed.publicKey.dataId, isNotEmpty);
      expect(parsed.publicKey.urls, isNotEmpty);
      expect(parsed.publicKey.urls.first, startsWith('https://'));
    });

    test('extracts the 2048-bit CRS entry', () {
      expect(parsed.crs.containsKey('2048'), isTrue);
      expect(parsed.crs['2048']!.urls.first, startsWith('https://'));
    });
  });

  group('InputProof assemble/parse', () {
    test('assembles to the correct length and round-trips', () {
      // 1 handle + 1 signature from the reference input-proof fixture.
      final fixture = jsonDecode(
        File('test/fixtures/input-proof-payload-1.json').readAsStringSync(),
      ) as Map<String, dynamic>;
      final handles =
          (fixture['handles'] as List).cast<String>(); // 1 bytes32
      final signatures = (fixture['fetch_json']['response']['signatures'] as List)
          .cast<String>(); // 1 bytes65
      const extraData = '0x00';

      final bytes = InputProof.assemble(
          handles: handles, signatures: signatures, extraData: extraData);

      // 2 header bytes + 32 (handle) + 65 (sig) + 1 (extraData)
      expect(bytes.length, 2 + 32 + 65 + 1);
      expect(bytes[0], 1); // numHandles
      expect(bytes[1], 1); // numSignatures

      final parsed = InputProof.parse(bytes);
      expect(parsed.handles, handles);
      expect(parsed.signatures, signatures);
      expect(parsed.extraData, extraData);
    });

    test('rejects oversized handle lists', () {
      expect(
        () => InputProof.assemble(
            handles: List.filled(256, '0x${'00' * 32}'),
            signatures: const [],
            extraData: '0x'),
        throwsArgumentError,
      );
    });
  });

  // Copy the input-proof fixture for this test.
  group('KeyUrlResponse parser (snake_case tolerance)', () {
    test('parses snake_case field names', () {
      final json = {
        'response': {
          'fhe_key_info': [
            {
              'fhe_public_key': {
                'data_id': 'pk-1',
                'urls': ['https://example/pk'],
              },
            },
          ],
          'crs': {
            '2048': {
              'data_id': 'crs-1',
              'urls': ['https://example/crs'],
            },
          },
        },
      };
      final r = KeyUrlResponse.fromJson(json);
      expect(r.publicKey.dataId, 'pk-1');
      expect(r.crs['2048']!.dataId, 'crs-1');
    });
  });
}
