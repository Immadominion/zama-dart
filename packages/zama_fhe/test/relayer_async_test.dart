import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:zama_fhe/zama_fhe.dart';
import 'package:test/test.dart';

const _net = FhevmNetworkConfig.sepolia;
final _fastPoll = const Duration(milliseconds: 1);

// 32-byte handle with a given FheType id at byte 30.
String _handle(int typeId) =>
    '0x${'00' * 30}${typeId.toRadixString(16).padLeft(2, '0')}00';

// 32-byte word holding [value] big-endian (last bytes).
String _word(BigInt value) {
  final b = Uint8List(32);
  var v = value;
  for (var i = 31; i >= 0 && v > BigInt.zero; i--) {
    b[i] = (v & BigInt.from(0xff)).toInt();
    v >>= 8;
  }
  return bytesToHex(b, prefix: false);
}

void main() {
  group('submitInputProof async state machine', () {
    test('POST 202 (queued) → GET 202 → GET 200 accepted', () async {
      var posts = 0, gets = 0;
      final mock = MockClient((req) async {
        if (req.method == 'POST') {
          posts++;
          return http.Response(
              jsonEncode({'status': 'queued', 'result': {'jobId': 'j1'}}), 202);
        }
        gets++;
        if (gets == 1) {
          return http.Response(jsonEncode({'status': 'queued'}), 202);
        }
        return http.Response(
            jsonEncode({
              'status': 'succeeded',
              'result': {
                'accepted': true,
                'handles': ['0x${'11' * 32}'],
                'signatures': ['0x${'22' * 65}'],
                'extraData': '0x00',
              }
            }),
            200);
      });
      final c = RelayerClient(_net, client: mock);
      final r = await c.submitInputProof(
        contractAddress: '0x${'a1' * 20}',
        userAddress: '0x${'b2' * 20}',
        ciphertextWithZkProof: Uint8List.fromList([1, 2, 3]),
        chainId: _net.chainId,
        pollInterval: _fastPoll,
      );
      expect(r.accepted, isTrue);
      expect(r.handles.single, '0x${'11' * 32}');
      expect(r.signatures.single, '0x${'22' * 65}');
      expect(posts, 1);
      expect(gets, 2); // one queued poll, one success
    });

    test('GET 200 accepted=false → InputProofRejectedException', () async {
      final mock = MockClient((req) async {
        if (req.method == 'POST') {
          return http.Response(
              jsonEncode({'result': {'jobId': 'j1'}}), 202);
        }
        return http.Response(
            jsonEncode({'result': {'accepted': false, 'extraData': '0x00'}}),
            200);
      });
      final c = RelayerClient(_net, client: mock);
      expect(
        () => c.submitInputProof(
          contractAddress: '0x${'a1' * 20}',
          userAddress: '0x${'b2' * 20}',
          ciphertextWithZkProof: Uint8List.fromList([1]),
          chainId: _net.chainId,
          pollInterval: _fastPoll,
        ),
        throwsA(isA<InputProofRejectedException>()),
      );
    });

    test('POST 400 → typed RelayerException with label', () async {
      final mock = MockClient((req) async => http.Response(
          jsonEncode({
            'error': {'label': 'invalid_input', 'message': 'bad ciphertext'}
          }),
          400));
      final c = RelayerClient(_net, client: mock);
      try {
        await c.submitInputProof(
          contractAddress: '0x${'a1' * 20}',
          userAddress: '0x${'b2' * 20}',
          ciphertextWithZkProof: Uint8List.fromList([1]),
          chainId: _net.chainId,
          pollInterval: _fastPoll,
        );
        fail('expected throw');
      } on RelayerException catch (e) {
        expect(e.statusCode, 400);
        expect(e.label, 'invalid_input');
        expect(e.message, 'bad ciphertext');
      }
    });
  });

  group('publicDecrypt', () {
    test('decodes euint32 / ebool / eaddress from KMS cleartext', () async {
      final hEuint32 = _handle(FheType.euint32.id);
      final hEbool = _handle(FheType.ebool.id);
      final hEaddr = _handle(FheType.eaddress.id);
      // 3 words: 42, true(1), address(0xab*20 in low 20 bytes)
      final addrWord = '${'00' * 12}${'ab' * 20}';
      final decryptedValue =
          _word(BigInt.from(42)) + _word(BigInt.one) + addrWord;

      final mock = MockClient((req) async {
        if (req.method == 'POST') {
          return http.Response(jsonEncode({'result': {'jobId': 'j1'}}), 202);
        }
        return http.Response(
            jsonEncode({
              'result': {
                'decryptedValue': decryptedValue, // no 0x prefix
                'signatures': ['33' * 65],
                'extraData': '0x00',
              }
            }),
            200);
      });
      final c = RelayerClient(_net, client: mock);
      final r = await c.publicDecrypt([hEuint32, hEbool, hEaddr],
          pollInterval: _fastPoll);

      expect(r.values[hEuint32], BigInt.from(42));
      expect(r.values[hEbool], true);
      expect(r.values[hEaddr], '0x${'ab' * 20}');
      expect(r.signatures.single, '0x${'33' * 65}');
      expect(r.decryptedValue, '0x$decryptedValue');
    });
  });

  group('userDecrypt', () {
    test('builds payload and parses re-encrypted items (result.result)', () async {
      Map<String, dynamic>? sentBody;
      final mock = MockClient((req) async {
        if (req.method == 'POST') {
          sentBody = jsonDecode(req.body) as Map<String, dynamic>;
          return http.Response(jsonEncode({'result': {'jobId': 'j1'}}), 202);
        }
        return http.Response(
            jsonEncode({
              'status': 'succeeded',
              'result': {
                'result': [
                  {'payload': 'aa', 'signature': 'bb', 'extraData': '0x00'},
                  {'payload': 'cc', 'signature': 'dd', 'extraData': '0x00'},
                ]
              }
            }),
            200);
      });
      final c = RelayerClient(_net, client: mock);
      final r = await c.userDecrypt(
        handleContractPairs: [
          HandleContractPair(
              handle: _handle(FheType.euint32.id), contractAddress: '0x${'c1' * 20}'),
        ],
        contractAddresses: ['0x${'c1' * 20}'],
        userAddress: '0x${'b2' * 20}',
        signature: '0xdeadbeef',
        publicKey: '0x2000',
        startTimestamp: 1722334455,
        durationDays: 7,
        chainId: _net.chainId,
        pollInterval: _fastPoll,
      );

      // request payload shape
      expect(sentBody!['contractsChainId'], _net.chainId.toString());
      expect((sentBody!['requestValidity'] as Map)['durationDays'], '7');
      expect(sentBody!['signature'], 'deadbeef'); // 0x stripped
      expect(sentBody!['publicKey'], '2000');
      expect((sentBody!['handleContractPairs'] as List).length, 1);

      // parsed response
      expect(r.items.length, 2);
      expect(r.items.first.payload, '0xaa');
      expect(r.items.first.signature, '0xbb');
    });
  });

  group('PublicDecryptResult.decode (unit)', () {
    test('maps words to typed values by handle', () {
      final h = _handle(FheType.euint64.id);
      final values = PublicDecryptResult.decode([h], '0x${_word(BigInt.from(123456789))}');
      expect(values[h], BigInt.from(123456789));
    });

    test('throws on short cleartext', () {
      expect(
        () => PublicDecryptResult.decode([_handle(FheType.euint32.id)], '0x00'),
        throwsA(isA<FormatException>()),
      );
    });
  });
}
