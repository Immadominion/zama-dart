import 'dart:typed_data';

import 'package:web3dart/web3dart.dart' as web3;

import '../eip712/eip712.dart';
import '../relayer/user_decrypt.dart';
import '../utils/hex.dart';

/// Client-side verification of KMS user-decryption responses (integrity).
///
/// Each per-node response carries an `external_signature` over the
/// `UserDecryptResponseVerification` EIP-712 struct
/// (`bytes publicKey, bytes32[] ctHandles, bytes userDecryptedShare, bytes extraData`)
/// under the **gateway-chainId** decryption domain. Recovering those signatures
/// and requiring a threshold of known KMS signers prevents a malicious relayer
/// from returning a re-encryption of a *wrong* value.
///
/// This runs in pure Dart (web3dart `ecRecover`), avoiding the native
/// wasm-bindgen `verify=true` path which panics off-wasm.
class KmsResponseVerifier {
  /// Returns the number of **distinct** valid KMS signers among [responses].
  /// Compare against the KMSVerifier threshold to decide acceptance.
  ///
  /// - [publicKey]: the ephemeral ML-KEM public key (hex; same bytes sent to the relayer).
  /// - [ctHandles]: the requested handles (`0x`-prefixed bytes32 hex).
  /// - [kmsSigners]: the KMS signer addresses from `KMSVerifier.getKmsSigners()`.
  static int countValidSigners({
    required String publicKey,
    required List<String> ctHandles,
    required int gatewayChainId,
    required String verifyingContract,
    required List<UserDecryptItem> responses,
    required List<String> kmsSigners,
  }) {
    final signers = {for (final a in kmsSigners) strip0x(a).toLowerCase()};
    final found = <String>{};
    for (final r in responses) {
      final sig = hexToBytes(r.signature);
      if (sig.length != 65) continue;
      final digest = _typedData(
        publicKey: publicKey,
        ctHandles: ctHandles,
        userDecryptedShare: r.payload,
        extraData: r.extraData,
        gatewayChainId: gatewayChainId,
        verifyingContract: verifyingContract,
      ).digest();
      // Recovery id encoding varies (0/1 vs 27/28); try both, accept the one
      // that recovers to a known signer.
      for (final v in const [27, 28]) {
        final addr = _recover(digest, sig, v);
        if (addr != null && signers.contains(addr)) {
          found.add(addr);
          break;
        }
      }
    }
    return found.length;
  }

  static Eip712TypedData _typedData({
    required String publicKey,
    required List<String> ctHandles,
    required String userDecryptedShare,
    required String extraData,
    required int gatewayChainId,
    required String verifyingContract,
  }) =>
      Eip712TypedData(
        types: const {
          'EIP712Domain': [
            Eip712Field('name', 'string'),
            Eip712Field('version', 'string'),
            Eip712Field('chainId', 'uint256'),
            Eip712Field('verifyingContract', 'address'),
          ],
          'UserDecryptResponseVerification': [
            Eip712Field('publicKey', 'bytes'),
            Eip712Field('ctHandles', 'bytes32[]'),
            Eip712Field('userDecryptedShare', 'bytes'),
            Eip712Field('extraData', 'bytes'),
          ],
        },
        primaryType: 'UserDecryptResponseVerification',
        domain: {
          'name': 'Decryption',
          'version': '1',
          'chainId': BigInt.from(gatewayChainId),
          'verifyingContract': verifyingContract,
        },
        message: {
          'publicKey': publicKey,
          'ctHandles': ctHandles,
          'userDecryptedShare': userDecryptedShare,
          'extraData': extraData,
        },
      );

  static String? _recover(Uint8List digest, Uint8List sig65, int v) {
    try {
      final pub = web3.ecRecover(
        digest,
        web3.MsgSignature(_be(sig65.sublist(0, 32)), _be(sig65.sublist(32, 64)), v),
      );
      return strip0x(bytesToHex(web3.publicKeyToAddress(pub))).toLowerCase();
    } catch (_) {
      return null;
    }
  }

  static BigInt _be(Uint8List b) {
    var v = BigInt.zero;
    for (final x in b) {
      v = (v << 8) | BigInt.from(x);
    }
    return v;
  }
}
