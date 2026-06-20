import 'package:zama_fhe/zama_fhe.dart';
import 'package:test/test.dart';

void main() {
  group('KmsResponseVerifier.countValidSigners', () {
    final handle =
        '0x20244f826737772a0b7f1254c1cc982d83094d65ec000000000000aa36a70400';

    test('rejects responses whose signatures do not recover to a known signer',
        () {
      // A well-formed-but-bogus 65-byte signature recovers to *some* address,
      // which is not in the trusted signer set → 0 valid.
      final bogus = '0x${'11' * 65}';
      final valid = KmsResponseVerifier.countValidSigners(
        publicKey: '0x${'22' * 32}',
        ctHandles: [handle],
        gatewayChainId: 10901,
        verifyingContract: FhevmNetworkConfig.sepolia.verifyingContractAddressDecryption,
        responses: [
          UserDecryptItem(payload: '0xdead', signature: bogus, extraData: '0x00'),
        ],
        kmsSigners: const ['0x000000000000000000000000000000000000dEaD'],
      );
      expect(valid, 0);
    });

    test('ignores malformed (wrong-length) signatures', () {
      final valid = KmsResponseVerifier.countValidSigners(
        publicKey: '0x2222',
        ctHandles: [handle],
        gatewayChainId: 10901,
        verifyingContract: FhevmNetworkConfig.sepolia.verifyingContractAddressDecryption,
        responses: [
          UserDecryptItem(payload: '0xbeef', signature: '0x1234', extraData: '0x00'),
        ],
        kmsSigners: const ['0x000000000000000000000000000000000000dEaD'],
      );
      expect(valid, 0);
    });
  });
}
