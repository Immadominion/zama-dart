import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:zama_fhe/zama_fhe.dart';
import 'package:test/test.dart';

const _net = FhevmNetworkConfig.sepolia;

/// A backend stand-in that records what it was asked to encrypt and computes
/// real handles from a dummy proof blob (so the FhevmHandle path is exercised).
class _FakeBackend implements FhevmBackend {
  _FakeBackend({this.ready = true});

  bool ready;
  int useKeyCalls = 0;
  List<FheInputValue>? lastInputs;
  Uint8List? lastMetadata;
  String? lastAcl;
  BigInt? lastChainId;

  @override
  bool get isReady => ready;

  @override
  void useKeyMaterial({required Uint8List publicKey, required Uint8List crs}) {
    useKeyCalls++;
    ready = true;
  }

  @override
  EncryptedPayload encrypt({
    required List<FheInputValue> inputs,
    required Uint8List metadata,
    required String aclContractAddress,
    required BigInt chainId,
  }) {
    lastInputs = inputs;
    lastMetadata = metadata;
    lastAcl = aclContractAddress;
    lastChainId = chainId;
    final blob = Uint8List.fromList(List.generate(64, (i) => (i * 7) & 0xff));
    final handles = FhevmHandle.computeInputHandles(
      ciphertextWithZkProof: blob,
      aclContractAddress: aclContractAddress,
      chainId: chainId,
      encryptionBits: [for (final i in inputs) i.type.encryptionBits],
    );
    return EncryptedPayload(inputProof: blob, handles: handles);
  }

  @override
  void dispose() {}
}

MockClient _inputProofMock({
  required List<String> handles,
  required List<String> signatures,
  void Function(Map<String, dynamic> body)? onPost,
}) {
  return MockClient((req) async {
    onPost?.call(jsonDecode(req.body) as Map<String, dynamic>);
    // POST 200 → synchronous terminal result (no polling).
    return http.Response(
      jsonEncode({
        'result': {
          'accepted': true,
          'handles': handles,
          'signatures': signatures,
          'extraData': '0x00',
        }
      }),
      200,
    );
  });
}

void main() {
  final contract = '0x${'a1' * 20}';
  final me = '0x${'b2' * 20}';

  group('buildInputMetadata', () {
    test('lays out contract|user|acl|chainId in 92 bytes', () {
      final m = buildInputMetadata(
        contractAddress: contract,
        userAddress: me,
        network: _net,
      );
      expect(m.length, 92);
      expect(bytesToHex(m.sublist(0, 20), prefix: false),
          strip0x(contract).toLowerCase());
      expect(bytesToHex(m.sublist(20, 40), prefix: false),
          strip0x(me).toLowerCase());
      expect(bytesToHex(m.sublist(40, 60), prefix: false),
          strip0x(_net.aclContractAddress).toLowerCase());
      // chainId big-endian in the trailing 32-byte word.
      final cid = m.sublist(60, 92);
      var v = 0;
      for (final b in cid) {
        v = (v << 8) | b;
      }
      expect(v, _net.chainId);
    });

    test('rejects a non-20-byte address', () {
      expect(
        () => buildInputMetadata(
            contractAddress: '0x1234', userAddress: me, network: _net),
        throwsArgumentError,
      );
    });
  });

  group('EncryptedInputBuilder.encrypt', () {
    test('accumulates typed inputs, encrypts, assembles the input proof',
        () async {
      Map<String, dynamic>? sentBody;
      final mock = _inputProofMock(
        handles: ['0x${'11' * 32}', '0x${'22' * 32}', '0x${'33' * 32}'],
        signatures: ['0x${'ab' * 65}'],
        onPost: (b) => sentBody = b,
      );
      final backend = _FakeBackend();
      final inst =
          FhevmInstance(network: _net, backend: backend, httpClient: mock);

      final enc = await inst
          .createEncryptedInput(contractAddress: contract, userAddress: me)
          .add64(1000)
          .addBool(true)
          .addAddress('0x${'cd' * 20}')
          .encrypt();

      // Inputs reached the backend with the right types/values.
      expect(backend.lastInputs!.map((i) => i.type).toList(),
          [FheType.euint64, FheType.ebool, FheType.eaddress]);
      expect(backend.lastInputs![0].value, BigInt.from(1000));
      expect(backend.lastInputs![1].value, BigInt.one);
      expect(backend.lastInputs![2].value,
          BigInt.parse('cd' * 20, radix: 16));

      // Metadata bound the call's contract + user.
      expect(backend.lastMetadata!.length, 92);
      expect(bytesToHex(backend.lastMetadata!.sublist(0, 20), prefix: false),
          strip0x(contract).toLowerCase());

      // Handles are the client-computed ones (3 × bytes32, correct type tags).
      expect(enc.handles.length, 3);
      for (final h in enc.handles) {
        expect(h.length, 32);
      }
      expect(enc.typedHandles[0].fheType, FheType.euint64);
      expect(enc.typedHandles[2].fheType, FheType.eaddress);

      // The assembled inputProof carries the relayer's handles + signature.
      final parsed = InputProof.parse(enc.inputProof);
      expect(parsed.handles.length, 3);
      expect(parsed.signatures.single, '0x${'ab' * 65}');

      // The relayer request carried the contract/user.
      expect(sentBody!['contractAddress'], contract);
      expect(sentBody!['userAddress'], me);
    });

    test('rejects values that would overflow their FHE type', () {
      EncryptedInputBuilder builder() => FhevmInstance(
              network: _net,
              backend: _FakeBackend(),
              httpClient: _inputProofMock(handles: const [], signatures: const []))
          .createEncryptedInput(contractAddress: contract, userAddress: me);

      // Boundaries are accepted...
      expect(() => builder().add8(255), returnsNormally);
      expect(() => builder().add16(65535), returnsNormally);
      expect(() => builder().add256((BigInt.one << 256) - BigInt.one),
          returnsNormally);
      expect(() => builder().addAddress('0x${'ff' * 20}'), returnsNormally);

      // ...one past the boundary throws (instead of silently wrapping).
      expect(() => builder().add8(256), throwsArgumentError);
      expect(() => builder().add16(65536), throwsArgumentError);
      expect(() => builder().add(BigInt.two, FheType.ebool), throwsArgumentError);
      expect(() => builder().add256(BigInt.one << 256), throwsArgumentError);
      expect(() => builder().add(BigInt.one << 160, FheType.eaddress),
          throwsArgumentError);
      expect(() => builder().add(BigInt.from(-1), FheType.euint32),
          throwsArgumentError);
    });

    test('empty builder throws', () async {
      final inst = FhevmInstance(
          network: _net, backend: _FakeBackend(), httpClient: _inputProofMock(handles: [], signatures: []));
      expect(
        () => inst
            .createEncryptedInput(contractAddress: contract, userAddress: me)
            .encrypt(),
        throwsStateError,
      );
    });

    test('ensureReady fetches key material when backend is not ready',
        () async {
      // Backend starts not-ready; ensureReady must call the relayer /keyurl.
      var keyUrlHit = false;
      final mock = MockClient((req) async {
        if (req.url.path.contains('keyurl')) {
          keyUrlHit = true;
          // Minimal keyurl payload is complex to fake; assert the attempt only.
          return http.Response('{"error":{"message":"stub"}}', 500);
        }
        return http.Response('{}', 200);
      });
      final backend = _FakeBackend(ready: false);
      final inst =
          FhevmInstance(network: _net, backend: backend, httpClient: mock);
      await expectLater(inst.ensureReady(), throwsA(isA<Object>()));
      expect(keyUrlHit, isTrue);
      expect(backend.isReady, isFalse); // never loaded (fetch failed)
    });

    test('ensureReady is a no-op when backend already ready', () async {
      final backend = _FakeBackend(ready: true);
      final inst = FhevmInstance(
          network: _net,
          backend: backend,
          httpClient: MockClient((_) async =>
              http.Response('should not be called', 500)));
      await inst.ensureReady();
      expect(backend.useKeyCalls, 0);
    });
  });
}
