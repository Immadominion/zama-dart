import '../config/networks.dart';
import 'eip712.dart';

/// Builds the EIP-712 typed data the KMS expects for decryption authorization.
///
/// Port of `@zama-fhe/relayer-sdk` `src/sdk/kms/KmsEIP712.ts`.
///
/// **Important:** the domain `chainId` is the **gateway** chain id (not the host
/// chain id), and `verifyingContract` is the gateway's decryption contract.
class KmsEip712 {
  KmsEip712({
    required this.chainId,
    required this.verifyingContractAddressDecryption,
  });

  /// Builds the KMS EIP-712 helper for the **user-decryption request signature**.
  ///
  /// The domain `chainId` is the **host** chain id (what the FhevmInstance signs
  /// with — see relayer-sdk `index.ts createEIP712`), and `verifyingContract` is
  /// the gateway decryption contract. (Note: the *KMS response* signature
  /// verification uses the **gateway** chain id instead — a separate concern.)
  factory KmsEip712.fromNetwork(FhevmNetworkConfig network) => KmsEip712(
        chainId: BigInt.from(network.chainId),
        verifyingContractAddressDecryption:
            network.verifyingContractAddressDecryption,
      );

  /// Chain id used in the EIP-712 domain (host chain id for the user-decryption
  /// request signature).
  final BigInt chainId;

  /// The gateway decryption contract (EIP-712 `verifyingContract`).
  final String verifyingContractAddressDecryption;

  static const _domainFields = [
    Eip712Field('name', 'string'),
    Eip712Field('version', 'string'),
    Eip712Field('chainId', 'uint256'),
    Eip712Field('verifyingContract', 'address'),
  ];

  Map<String, Object?> get _domain => {
        'name': 'Decryption',
        'version': '1',
        'chainId': chainId,
        'verifyingContract': verifyingContractAddressDecryption,
      };

  /// EIP-712 for a private user-decryption request.
  ///
  /// - [publicKey]: hex of the user's ephemeral ML-KEM public key.
  /// - [contractAddresses]: contracts whose handles may be decrypted.
  /// - [startTimestamp]: unix seconds the grant starts.
  /// - [durationDays]: validity window (1..365).
  Eip712TypedData createUserDecrypt({
    required String publicKey,
    required List<String> contractAddresses,
    required int startTimestamp,
    required int durationDays,
    String extraData = '0x00',
  }) {
    return Eip712TypedData(
      types: {
        'EIP712Domain': _domainFields,
        'UserDecryptRequestVerification': const [
          Eip712Field('publicKey', 'bytes'),
          Eip712Field('contractAddresses', 'address[]'),
          Eip712Field('startTimestamp', 'uint256'),
          Eip712Field('durationDays', 'uint256'),
          Eip712Field('extraData', 'bytes'),
        ],
      },
      primaryType: 'UserDecryptRequestVerification',
      domain: _domain,
      message: {
        'publicKey': publicKey,
        'contractAddresses': contractAddresses,
        'startTimestamp': BigInt.from(startTimestamp),
        'durationDays': BigInt.from(durationDays),
        'extraData': extraData,
      },
    );
  }

  /// EIP-712 for a delegated user-decryption request (decryption on behalf of
  /// [delegatorAddress]).
  Eip712TypedData createDelegatedUserDecrypt({
    required String publicKey,
    required List<String> contractAddresses,
    required String delegatorAddress,
    required int startTimestamp,
    required int durationDays,
    String extraData = '0x00',
  }) {
    return Eip712TypedData(
      types: {
        'EIP712Domain': _domainFields,
        'DelegatedUserDecryptRequestVerification': const [
          Eip712Field('publicKey', 'bytes'),
          Eip712Field('contractAddresses', 'address[]'),
          Eip712Field('delegatorAddress', 'address'),
          Eip712Field('startTimestamp', 'uint256'),
          Eip712Field('durationDays', 'uint256'),
          Eip712Field('extraData', 'bytes'),
        ],
      },
      primaryType: 'DelegatedUserDecryptRequestVerification',
      domain: _domain,
      message: {
        'publicKey': publicKey,
        'contractAddresses': contractAddresses,
        'delegatorAddress': delegatorAddress,
        'startTimestamp': BigInt.from(startTimestamp),
        'durationDays': BigInt.from(durationDays),
        'extraData': extraData,
      },
    );
  }

  /// EIP-712 used to verify KMS signatures over a public-decryption result.
  Eip712TypedData createPublicDecrypt({
    required List<String> ctHandles,
    required String decryptedResult,
    String extraData = '0x00',
  }) {
    return Eip712TypedData(
      types: {
        'EIP712Domain': _domainFields,
        'PublicDecryptVerification': const [
          Eip712Field('ctHandles', 'bytes32[]'),
          Eip712Field('decryptedResult', 'bytes'),
          Eip712Field('extraData', 'bytes'),
        ],
      },
      primaryType: 'PublicDecryptVerification',
      domain: _domain,
      message: {
        'ctHandles': ctHandles,
        'decryptedResult': decryptedResult,
        'extraData': extraData,
      },
    );
  }
}
