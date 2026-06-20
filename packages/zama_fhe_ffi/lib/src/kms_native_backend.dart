import 'package:zama_fhe/zama_fhe.dart';

import '../zama_kms.dart';

/// The native ([dart:ffi] / `zama_kms_ffi`) implementation of [KmsBackend].
///
/// Wraps a [ZamaKms] handle (ML-KEM-512 keygen + ML-KEM/AES-GCM hybrid decrypt).
/// Threshold-signature verification is done in pure Dart by
/// [FhevmInstance.userDecrypt] (the native `verify=true` path panics off-wasm),
/// so this backend always calls the native decrypt with `verify: false`.
///
/// ```dart
/// final clears = await instance.userDecrypt(
///   pairs: pairs,
///   contractAddresses: [contract],
///   userAddress: me,
///   signer: mySigner,
///   kms: KmsNativeBackend(ZamaKms.openDefault()),
///   kmsSigners: signers,   // from on-chain KMSVerifier.getKmsSigners()
///   threshold: threshold,  // from KMSVerifier.getThreshold()
/// );
/// ```
class KmsNativeBackend implements KmsBackend {
  KmsNativeBackend(ZamaKms kms) : _kms = kms;

  final ZamaKms _kms;

  @override
  UserDecryptKeypair generateKeypair() {
    final k = _kms.generateKeypair();
    return UserDecryptKeypair(publicKey: k.publicKey, secretKey: k.secretKey);
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
    final out = _kms.userDecrypt(
      userAddress: userAddress,
      verifyingContract: verifyingContract,
      gatewayChainId: gatewayChainId,
      signature: signature,
      keypair:
          KmsKeypair(publicKey: keypair.publicKey, secretKey: keypair.secretKey),
      handles: handles,
      responses: [
        for (final r in responses)
          KmsResponseItem(payload: r.payload, signature: r.signature)
      ],
      verify: false, // threshold verify is done in Dart, see class doc
    );
    if (out.length != handles.length) {
      throw StateError(
          'KMS returned ${out.length} values for ${handles.length} handles');
    }
    return [
      for (var i = 0; i < out.length; i++)
        DecryptedValue(
          handle: handles[i],
          bytes: out[i].bytes,
          type: FheType.fromId(out[i].fheType),
        )
    ];
  }

  @override
  void dispose() {}
}
