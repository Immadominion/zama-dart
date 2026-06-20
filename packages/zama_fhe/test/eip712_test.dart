import 'package:zama_fhe/zama_fhe.dart';
import 'package:test/test.dart';

void main() {
  // Canonical EIP-712 example from the spec / MetaMask docs. Exercises nested
  // structs (Person within Mail), encodeType dependency ordering, string +
  // address encoding, and the final 0x1901 digest. The expected values are the
  // well-known reference hashes for this exact payload.
  group('EIP-712 canonical "Mail" vector', () {
    final mail = Eip712TypedData(
      types: {
        'EIP712Domain': const [
          Eip712Field('name', 'string'),
          Eip712Field('version', 'string'),
          Eip712Field('chainId', 'uint256'),
          Eip712Field('verifyingContract', 'address'),
        ],
        'Person': const [
          Eip712Field('name', 'string'),
          Eip712Field('wallet', 'address'),
        ],
        'Mail': const [
          Eip712Field('from', 'Person'),
          Eip712Field('to', 'Person'),
          Eip712Field('contents', 'string'),
        ],
      },
      primaryType: 'Mail',
      domain: const {
        'name': 'Ether Mail',
        'version': '1',
        'chainId': 1,
        'verifyingContract': '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
      },
      message: const <String, Object?>{
        'from': <String, Object?>{
          'name': 'Cow',
          'wallet': '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        'to': <String, Object?>{
          'name': 'Bob',
          'wallet': '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        'contents': 'Hello, Bob!',
      },
    );

    test('domain separator matches reference', () {
      expect(
        bytesToHex(mail.domainSeparator()),
        '0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f',
      );
    });

    test('signing digest matches reference', () {
      expect(
        mail.digestHex(),
        '0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2',
      );
    });
  });

  group('KmsEip712 builders', () {
    final kms = KmsEip712.fromNetwork(FhevmNetworkConfig.sepolia);

    test('uses host chainId and decryption verifying contract', () {
      expect(kms.chainId, BigInt.from(11155111)); // host chain id
      expect(kms.verifyingContractAddressDecryption,
          FhevmNetworkConfig.sepolia.verifyingContractAddressDecryption);
    });

    test('user-decrypt typed data has correct shape & domain', () {
      final td = kms.createUserDecrypt(
        publicKey: '0x2000000000000000',
        contractAddresses: const ['0x9aF5773d8dC3d9A57c92e08EF024804eC39FD3b3'],
        startTimestamp: 1722334455,
        durationDays: 10,
      );
      expect(td.primaryType, 'UserDecryptRequestVerification');
      expect(td.domain['name'], 'Decryption');
      expect(td.domain['version'], '1');
      expect(td.domain['chainId'], BigInt.from(11155111));
      // Digest is deterministic and 32 bytes.
      expect(td.digest().length, 32);
      // Same inputs -> same digest.
      final td2 = kms.createUserDecrypt(
        publicKey: '0x2000000000000000',
        contractAddresses: const ['0x9aF5773d8dC3d9A57c92e08EF024804eC39FD3b3'],
        startTimestamp: 1722334455,
        durationDays: 10,
      );
      expect(td.digestHex(), td2.digestHex());
    });

    test('public-decrypt typed data shape', () {
      final td = kms.createPublicDecrypt(
        ctHandles: const [
          '0x20244f826737772a0b7f1254c1cc982d83094d65ec000000000000aa36a70400'
        ],
        decryptedResult: '0x2a',
      );
      expect(td.primaryType, 'PublicDecryptVerification');
      expect(td.digest().length, 32);
    });
  });
}
