import 'dart:typed_data';

import '../utils/hex.dart';

/// The relayer's verified result for an input-proof submission.
class InputProofResponse {
  const InputProofResponse({
    required this.accepted,
    required this.handles,
    required this.signatures,
    required this.extraData,
  });

  /// Whether the relayer/coprocessors accepted the proof.
  final bool accepted;

  /// Coprocessor-attested handles (`0x`-prefixed bytes32 hex), in order.
  final List<String> handles;

  /// Coprocessor signatures (`0x`-prefixed 65-byte hex).
  final List<String> signatures;

  /// Echoed extra data (`0x`-prefixed).
  final String extraData;

  /// Assembles the final on-chain `inputProof` bytes from this response.
  Uint8List toInputProofBytes() => InputProof.assemble(
        handles: handles,
        signatures: signatures,
        extraData: extraData,
      );
}

/// Assembles / parses the on-chain `inputProof` byte format.
///
/// Layout (mirrors `@zama-fhe/relayer-sdk` `InputProof`):
/// ```
/// numHandles(1) ‖ numSignatures(1) ‖ handles(32×n) ‖ signatures(65×m) ‖ extraData
/// ```
class InputProof {
  static const handleSize = 32;
  static const signatureSize = 65;

  /// Builds the `inputProof` bytes passed alongside handles to a contract.
  static Uint8List assemble({
    required List<String> handles,
    required List<String> signatures,
    required String extraData,
  }) {
    if (handles.length > 255) {
      throw ArgumentError('too many handles: ${handles.length} (max 255)');
    }
    if (signatures.length > 255) {
      throw ArgumentError('too many signatures: ${signatures.length} (max 255)');
    }
    final b = BytesBuilder();
    b.addByte(handles.length);
    b.addByte(signatures.length);
    for (final h in handles) {
      final hb = hexToBytes(h);
      if (hb.length != handleSize) {
        throw ArgumentError('handle must be 32 bytes, got ${hb.length}');
      }
      b.add(hb);
    }
    for (final s in signatures) {
      final sb = hexToBytes(s);
      if (sb.length != signatureSize) {
        throw ArgumentError('signature must be 65 bytes, got ${sb.length}');
      }
      b.add(sb);
    }
    b.add(hexToBytes(extraData));
    return b.toBytes();
  }

  /// Parses an `inputProof` blob back into its parts (round-trip / validation).
  static ({List<String> handles, List<String> signatures, String extraData})
      parse(Uint8List proof) {
    if (proof.length < 2) {
      throw ArgumentError('inputProof too short');
    }
    final numHandles = proof[0];
    final numSignatures = proof[1];
    var off = 2;
    final handles = <String>[];
    for (var i = 0; i < numHandles; i++) {
      handles.add(bytesToHex(proof.sublist(off, off + handleSize)));
      off += handleSize;
    }
    final signatures = <String>[];
    for (var i = 0; i < numSignatures; i++) {
      signatures.add(bytesToHex(proof.sublist(off, off + signatureSize)));
      off += signatureSize;
    }
    final extraData = bytesToHex(proof.sublist(off));
    return (handles: handles, signatures: signatures, extraData: extraData);
  }
}
