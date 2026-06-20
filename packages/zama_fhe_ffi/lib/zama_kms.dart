/// Dart FFI binding to `zama_kms_ffi` — the native KMS client for user
/// (private) decryption: ML-KEM-512 ephemeral keypair generation and decryption
/// of the relayer's `/user-decrypt` response.
///
/// Separate from `zama_fhe_native` (the encrypt/ZK-proof lib) because the KMS
/// crate pins a different Rust toolchain (1.94.0 vs 1.91.1).
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'src/bindings.dart' show NativeByteBuf;

typedef _KeygenC = Int32 Function(
    Pointer<NativeByteBuf> outPk, Pointer<NativeByteBuf> outSk);
typedef _KeygenDart = int Function(
    Pointer<NativeByteBuf> outPk, Pointer<NativeByteBuf> outSk);
typedef _UserDecryptC = Int32 Function(
    Pointer<Uint8> req, Size len, Pointer<NativeByteBuf> out);
typedef _UserDecryptDart = int Function(
    Pointer<Uint8> req, int len, Pointer<NativeByteBuf> out);
typedef _BytesFreeC = Void Function(NativeByteBuf buf);
typedef _BytesFreeDart = void Function(NativeByteBuf buf);

/// An ephemeral ML-KEM-512 keypair for one user-decryption session.
class KmsKeypair {
  const KmsKeypair({required this.publicKey, required this.secretKey});

  /// Serialized public key — hand to the relayer / bind into the EIP-712.
  final Uint8List publicKey;

  /// Serialized secret key — keep private; pass back to [ZamaKms.userDecrypt].
  final Uint8List secretKey;
}

/// One re-encrypted item from a `/user-decrypt` response.
class KmsResponseItem {
  const KmsResponseItem({required this.payload, required this.signature});
  final String payload; // hex (0x optional)
  final String signature; // hex
}

/// Native KMS client.
class ZamaKms {
  ZamaKms._(this._keygen, this._userDecrypt, this._bytesFree);

  final _KeygenDart _keygen;
  final _UserDecryptDart _userDecrypt;
  final _BytesFreeDart _bytesFree;

  factory ZamaKms.open(String path) {
    final lib = DynamicLibrary.open(path);
    return ZamaKms._(
      lib.lookupFunction<_KeygenC, _KeygenDart>('zama_kms_keygen'),
      lib.lookupFunction<_UserDecryptC, _UserDecryptDart>('zama_kms_user_decrypt'),
      lib.lookupFunction<_BytesFreeC, _BytesFreeDart>('zama_kms_bytes_free'),
    );
  }

  /// Loads from `ZAMA_KMS_LIB` (desktop) or by name (Android).
  factory ZamaKms.openDefault() {
    if (Platform.isAndroid) return ZamaKms.open('libzama_kms_ffi.so');
    final p = Platform.environment['ZAMA_KMS_LIB'];
    if (p == null) {
      throw StateError('set ZAMA_KMS_LIB to libzama_kms_ffi.{dylib,so}');
    }
    return ZamaKms.open(p);
  }

  /// Generates a fresh ephemeral ML-KEM-512 keypair.
  KmsKeypair generateKeypair() {
    final outPk = calloc<NativeByteBuf>();
    final outSk = calloc<NativeByteBuf>();
    try {
      final rc = _keygen(outPk, outSk);
      if (rc != 0) throw StateError('zama_kms_keygen failed (code $rc)');
      final pk = _copy(outPk.ref);
      final sk = _copy(outSk.ref);
      _bytesFree(outPk.ref);
      _bytesFree(outSk.ref);
      return KmsKeypair(publicKey: pk, secretKey: sk);
    } finally {
      calloc.free(outPk);
      calloc.free(outSk);
    }
  }

  /// Decrypts a `/user-decrypt` response to typed cleartext values.
  ///
  /// Returns a list of `(bytes, fheType)` cleartexts in handle order.
  List<({Uint8List bytes, int fheType})> userDecrypt({
    required String userAddress,
    required String verifyingContract,
    required int gatewayChainId,
    required String signature,
    required KmsKeypair keypair,
    required List<String> handles,
    required List<KmsResponseItem> responses,
    String extraData = '0x00',
    bool verify = true,
    List<({int id, String address})> kmsSigners = const [],
  }) {
    final request = jsonEncode({
      'userAddress': userAddress,
      'verifyingContract': verifyingContract,
      'gatewayChainId': gatewayChainId,
      'signature': signature,
      'encPk': _hex(keypair.publicKey),
      'encSk': _hex(keypair.secretKey),
      'handles': handles,
      'extraData': extraData,
      'verify': verify,
      'kmsSigners': [
        for (final s in kmsSigners) {'id': s.id, 'address': s.address}
      ],
      'responses': [
        for (final r in responses)
          {'payload': r.payload, 'signature': r.signature}
      ],
    });
    final reqBytes = utf8.encode(request);
    final reqPtr = calloc<Uint8>(reqBytes.length);
    final out = calloc<NativeByteBuf>();
    try {
      reqPtr.asTypedList(reqBytes.length).setAll(0, reqBytes);
      final rc = _userDecrypt(reqPtr, reqBytes.length, out);
      if (rc != 0) {
        final msg = out.ref.ptr == nullptr ? '' : utf8.decode(_copy(out.ref));
        if (out.ref.ptr != nullptr) _bytesFree(out.ref);
        throw StateError('zama_kms_user_decrypt failed (code $rc): $msg');
      }
      final json = jsonDecode(utf8.decode(_copy(out.ref))) as List;
      _bytesFree(out.ref);
      return [
        for (final e in json)
          (
            bytes: _unhex(e['bytes'] as String),
            fheType: e['fheType'] as int,
          ),
      ];
    } finally {
      calloc.free(reqPtr);
      calloc.free(out);
    }
  }

  Uint8List _copy(NativeByteBuf b) {
    final out = Uint8List(b.len);
    out.setAll(0, b.ptr.asTypedList(b.len));
    return out;
  }
}

String _hex(Uint8List b) {
  final sb = StringBuffer();
  for (final x in b) {
    sb.write(x.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

Uint8List _unhex(String s) {
  final h = s.startsWith('0x') ? s.substring(2) : s;
  final out = Uint8List(h.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(h.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
