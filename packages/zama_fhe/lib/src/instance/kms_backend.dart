import 'dart:typed_data';

import '../relayer/user_decrypt.dart';
import '../types/fhe_type.dart';

/// An ephemeral asymmetric keypair (ML-KEM-512) for one user-decryption
/// session: the public key is bound into the EIP-712 request + sent to the
/// relayer, the secret key decrypts the re-encrypted shares that come back.
class UserDecryptKeypair {
  const UserDecryptKeypair({required this.publicKey, required this.secretKey});

  final Uint8List publicKey;
  final Uint8List secretKey;
}

/// A decrypted handle's cleartext.
class DecryptedValue {
  const DecryptedValue({
    required this.handle,
    required this.bytes,
    required this.type,
  });

  /// The `0x` handle this value was decrypted for.
  final String handle;

  /// Raw cleartext bytes, **little-endian** (the native KMS byte order).
  final Uint8List bytes;

  /// The FHE type, derived from the handle's type tag.
  final FheType type;

  /// The value as an unsigned integer (little-endian decode). For `ebool`
  /// this is 0 or 1; for `eaddress` it is the 160-bit address as an integer.
  BigInt get asBigInt {
    var v = BigInt.zero;
    for (var i = bytes.length - 1; i >= 0; i--) {
      v = (v << 8) | BigInt.from(bytes[i]);
    }
    return v;
  }

  /// The value as a bool (`ebool`).
  bool get asBool => asBigInt != BigInt.zero;

  /// The value as a `0x`-prefixed checksum-less 20-byte address (`eaddress`).
  String get asAddress =>
      '0x${asBigInt.toRadixString(16).padLeft(40, '0')}';

  @override
  String toString() => 'DecryptedValue(${type.typeName} @ $handle = $asBigInt)';
}

/// Signs a 32-byte EIP-712 digest, returning a 65-byte `r||s||v` signature.
///
/// Wire this to the user's wallet (WalletConnect/reown, an injected provider,
/// or a local key). For web3dart: `(d) async => _sigBytes(sign(d, privKey))`.
typedef Eip712Signer = Future<Uint8List> Function(Uint8List digest);

/// A pluggable KMS backend: ephemeral ML-KEM keypair generation + hybrid
/// (ML-KEM-512 + AES-256-GCM) decryption of the relayer's `/user-decrypt`
/// response. The native implementation lives in `zama_fhe_ffi`.
abstract class KmsBackend {
  /// Generates a fresh ephemeral keypair for one decryption session.
  UserDecryptKeypair generateKeypair();

  /// Decrypts the relayer's re-encrypted [responses] (one per KMS node) for the
  /// requested [handles], in handle order. [signature] is the user's EIP-712
  /// authorization; [keypair] is the one from [generateKeypair].
  List<DecryptedValue> decrypt({
    required String userAddress,
    required String verifyingContract,
    required int gatewayChainId,
    required String signature,
    required UserDecryptKeypair keypair,
    required List<String> handles,
    required List<UserDecryptItem> responses,
  });

  /// Releases any native resources.
  void dispose();
}
