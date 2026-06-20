import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:zama_fhe/zama_fhe.dart';
import 'package:test/test.dart';

const _net = FhevmNetworkConfig.sepolia;

String _handle(int typeId) =>
    '0x${'00' * 30}${typeId.toRadixString(16).padLeft(2, '0')}00';

/// Records the args it was driven with and returns canned cleartexts.
class _FakeKms implements KmsBackend {
  int keypairCalls = 0;
  String? decSignature;
  List<String>? decHandles;
  final List<DecryptedValue> Function(List<String> handles)? decoder;

  _FakeKms({this.decoder});

  @override
  UserDecryptKeypair generateKeypair() {
    keypairCalls++;
    return UserDecryptKeypair(
      publicKey: Uint8List.fromList(List.filled(800, 0x22)),
      secretKey: Uint8List.fromList(List.filled(1600, 0x33)),
    );
  }

  @override
  List<DecryptedValue> decrypt({
    required String userAddress,
    required String verifyingContract,
    required int gatewayChainId,
    required String signature,
    required UserDecryptKeypair keypair,
    required List<String> handles,
    required List<UserDecryptItem> responses,
  }) {
    decSignature = signature;
    decHandles = handles;
    return decoder?.call(handles) ?? const [];
  }

  @override
  void dispose() {}
}

MockClient _userDecryptMock({
  required List<Map<String, String>> items,
  void Function(Map<String, dynamic> body)? onPost,
}) {
  return MockClient((req) async {
    onPost?.call(jsonDecode(req.body) as Map<String, dynamic>);
    return http.Response(
      jsonEncode({
        'result': {'result': items}
      }),
      200,
    );
  });
}

Future<Uint8List> _fakeSigner(Uint8List digest) async =>
    Uint8List.fromList(List.filled(65, 0xab));

void main() {
  final me = '0x${'b2' * 20}';
  final contract = '0x${'c1' * 20}';

  group('FhevmInstance.userDecrypt', () {
    test('drives keypair → sign → relayer → verify → decrypt and maps values',
        () async {
      Map<String, dynamic>? sent;
      final h = _handle(FheType.euint32.id);
      final mock = _userDecryptMock(
        items: [
          {'payload': 'aa', 'signature': 'bb', 'extraData': '0x00'},
        ],
        onPost: (b) => sent = b,
      );
      // threshold 0 → verification trivially satisfied (we test the wiring;
      // the verify crypto itself is covered by kms_verify_test + live M2).
      final kms = _FakeKms(decoder: (handles) => [
            DecryptedValue(
              handle: handles.single,
              bytes: Uint8List.fromList([42, 0, 0, 0]), // little-endian 42
              type: FheType.euint32,
            ),
          ]);
      final inst = FhevmInstance(
          network: _net, backend: _NoopBackend(), httpClient: mock);

      final clears = await inst.userDecrypt(
        pairs: [HandleContractPair(handle: h, contractAddress: contract)],
        contractAddresses: [contract],
        userAddress: me,
        signer: _fakeSigner,
        kms: kms,
        kmsSigners: const [],
        threshold: 0,
      );

      // Relayer received the ephemeral public key + the user's signature.
      expect(sent!['userAddress'], me);
      expect(sent!['publicKey'], '22' * 800); // strip0x of the fake pk
      expect(sent!['signature'], 'ab' * 65);
      expect((sent!['handleContractPairs'] as List).length, 1);

      // The KMS was handed the same signature it authorized with.
      expect(kms.keypairCalls, 1);
      expect(kms.decSignature, '0x${'ab' * 65}');
      expect(kms.decHandles, [h]);

      // Decoded value.
      expect(clears.single.type, FheType.euint32);
      expect(clears.single.asBigInt, BigInt.from(42));
    });

    test('throws when fewer than `threshold` signatures are valid', () async {
      final h = _handle(FheType.euint32.id);
      final mock = _userDecryptMock(items: [
        {'payload': '0xbeef', 'signature': '0x${'11' * 65}', 'extraData': '0x00'},
      ]);
      final inst = FhevmInstance(
          network: _net, backend: _NoopBackend(), httpClient: mock);

      // A bogus signature won't recover to the (nonexistent-but-set) signer, so
      // 0 valid < threshold 1 → must throw before decrypting.
      final kms = _FakeKms(decoder: (_) {
        fail('decrypt must not run when threshold is unmet');
      });
      await expectLater(
        inst.userDecrypt(
          pairs: [HandleContractPair(handle: h, contractAddress: contract)],
          contractAddresses: [contract],
          userAddress: me,
          signer: _fakeSigner,
          kms: kms,
          kmsSigners: const ['0x000000000000000000000000000000000000dEaD'],
          threshold: 1,
        ),
        throwsStateError,
      );
    });

    test('rejects a signer that returns a non-65-byte signature', () async {
      final h = _handle(FheType.euint32.id);
      final inst = FhevmInstance(
          network: _net,
          backend: _NoopBackend(),
          httpClient: _userDecryptMock(items: const []));
      await expectLater(
        inst.userDecrypt(
          pairs: [HandleContractPair(handle: h, contractAddress: contract)],
          contractAddresses: [contract],
          userAddress: me,
          signer: (_) async => Uint8List(10),
          kms: _FakeKms(),
          kmsSigners: const [],
          threshold: 0,
        ),
        throwsArgumentError,
      );
    });
  });
}

/// An encrypt backend that is never used by these decryption tests.
class _NoopBackend implements FhevmBackend {
  @override
  bool get isReady => true;
  @override
  void useKeyMaterial({required Uint8List publicKey, required Uint8List crs}) {}
  @override
  EncryptedPayload encrypt({
    required List<FheInputValue> inputs,
    required Uint8List metadata,
    required String aclContractAddress,
    required BigInt chainId,
  }) =>
      throw UnimplementedError();
  @override
  void dispose() {}
}
