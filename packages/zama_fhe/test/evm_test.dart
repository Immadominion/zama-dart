import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:web3dart/web3dart.dart' as web3;
import 'package:zama_fhe/zama_fhe.dart';
import 'package:test/test.dart';

// A confidential setter: setValue(externalEuint32 handle, bytes inputProof).
const _abi = '''
[{"type":"function","name":"setValue","stateMutability":"nonpayable",
  "inputs":[{"name":"handle","type":"bytes32"},{"name":"inputProof","type":"bytes"}],
  "outputs":[]}]
''';

void main() {
  group('ConfidentialContract.encodeCall', () {
    final cc = ConfidentialContract(
      abiJson: _abi,
      name: 'Demo',
      address: '0x${'cd' * 20}',
      // unused for pure encoding; a mock client satisfies the constructor.
      client: web3.Web3Client('http://localhost', MockClient((_) async => http.Response('{}', 200))),
      chainId: 11155111,
    );

    const handleHex =
        '0x20244f826737772a0b7f1254c1cc982d83094d65ec000000000000aa36a70400';
    final inputProof = Uint8List.fromList(List<int>.generate(100, (i) => i & 0xff));

    test('selector + bytes32 handle are encoded correctly', () {
      final handle = FhevmHandle.fromBytes32Hex(handleHex);
      final data = cc.encodeCall('setValue', [handle, inputProof]);

      // 4-byte selector = keccak256("setValue(bytes32,bytes)")[:4]
      final selector =
          keccak256(ascii.encode('setValue(bytes32,bytes)')).sublist(0, 4);
      expect(data.sublist(0, 4), selector);

      // First static arg (bytes32 handle) occupies calldata[4:36] verbatim.
      expect(bytesToHex(data.sublist(4, 36)), handleHex);

      // Dynamic `bytes inputProof` is appended; calldata carries its bytes.
      expect(data.length, greaterThan(4 + 32 + 32)); // selector + handle + offset + ...
    });

    test('accepts a raw Uint8List handle too', () {
      final handle = FhevmHandle.fromBytes32Hex(handleHex);
      final viaHandle = cc.encodeCall('setValue', [handle, inputProof]);
      final viaBytes = cc.encodeCall('setValue', [handle.toBytes32(), inputProof]);
      expect(viaBytes, viaHandle);
    });
  });
}
