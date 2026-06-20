import 'dart:typed_data';

import '../handle/fhevm_handle.dart';
import '../types/fhe_type.dart';
import '../utils/hex.dart';

/// Result of a public decryption: cleartext values + the KMS attestation.
class PublicDecryptResult {
  const PublicDecryptResult({
    required this.values,
    required this.signatures,
    required this.decryptedValue,
    required this.extraData,
  });

  /// Cleartext per handle (`0x`-prefixed handle hex → value). Value type:
  /// `bool` for `ebool`, `0x`-address `String` for `eaddress`, else `BigInt`.
  final Map<String, Object> values;

  /// KMS signatures (`0x`-prefixed), to verify on-chain via `FHE.checkSignatures`.
  final List<String> signatures;

  /// Raw ABI-encoded cleartext (`0x`-prefixed) the KMS signed.
  final String decryptedValue;

  /// Echoed extra data (`0x`-prefixed) — the bytes the KMS signed over.
  final String extraData;

  /// Decodes the KMS `decryptedValue` (ABI-encoded static words, one per handle)
  /// into typed clear values keyed by handle.
  ///
  /// All FHE cleartexts are static 32-byte words, so the blob is simply
  /// `n × 32` bytes in handle order.
  static Map<String, Object> decode(
    List<String> handles,
    String decryptedValueHex,
  ) {
    final bytes = hexToBytes(decryptedValueHex);
    if (bytes.length < handles.length * 32) {
      throw FormatException(
          'decryptedValue too short: ${bytes.length} bytes for '
          '${handles.length} handles (need ${handles.length * 32})');
    }
    final out = <String, Object>{};
    for (var i = 0; i < handles.length; i++) {
      final h = FhevmHandle.fromBytes32Hex(handles[i]);
      final word = bytes.sublist(i * 32, i * 32 + 32);
      out[h.toBytes32Hex()] = _interpret(h.fheType, word);
    }
    return out;
  }

  static Object _interpret(FheType type, Uint8List word) {
    switch (type) {
      case FheType.ebool:
        return word.any((b) => b != 0);
      case FheType.eaddress:
        // low 20 bytes
        return bytesToHex(word.sublist(12, 32));
      default:
        var v = BigInt.zero;
        for (final b in word) {
          v = (v << 8) | BigInt.from(b);
        }
        return v;
    }
  }
}
