import 'dart:convert';

import 'package:zama_fhe/zama_fhe.dart';
import 'package:test/test.dart';

void main() {
  group('keccak256', () {
    test('empty input matches canonical vector', () {
      expect(
        keccak256Hex([]),
        '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
      );
    });

    test('"hello" matches canonical vector', () {
      expect(
        keccak256Hex(ascii.encode('hello')),
        '0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8',
      );
    });
  });

  group('FheType', () {
    test('ids match the protocol enum', () {
      expect(FheType.ebool.id, 0);
      expect(FheType.euint8.id, 2);
      expect(FheType.euint32.id, 4);
      expect(FheType.euint64.id, 5);
      expect(FheType.eaddress.id, 7);
      expect(FheType.euint256.id, 8);
    });

    test('euint4 (id 1) is not a valid id', () {
      expect(FheType.isValidId(1), false);
      expect(() => FheType.fromId(1), throwsArgumentError);
    });

    test('encryption bit widths', () {
      expect(FheType.ebool.encryptionBits, 2);
      expect(FheType.eaddress.encryptionBits, 160);
      expect(FheType.fromEncryptionBits(64), FheType.euint64);
    });
  });

  group('hex round-trip', () {
    test('bytesToHex(hexToBytes(x)) == x', () {
      const x = '0xdeadbeef00ff';
      expect(bytesToHex(hexToBytes(x)), x);
    });
  });

  group('networks', () {
    test('sepolia config', () {
      const c = FhevmNetworkConfig.sepolia;
      expect(c.chainId, 11155111);
      expect(c.gatewayChainId, 10901);
      expect(c.relayerUrlV2, 'https://relayer.testnet.zama.org/v2');
    });

    test('mainnet config', () {
      const c = FhevmNetworkConfig.mainnet;
      expect(c.chainId, 1);
      expect(c.gatewayChainId, 261131);
    });
  });
}
