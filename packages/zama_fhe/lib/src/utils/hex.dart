import 'dart:typed_data';

/// Hex <-> bytes helpers, matching the conventions of the reference
/// `@zama-fhe/relayer-sdk` (lowercase, `0x`-prefixed output).

/// Removes an optional leading `0x`/`0X`.
String strip0x(String hex) =>
    (hex.startsWith('0x') || hex.startsWith('0X')) ? hex.substring(2) : hex;

/// Ensures a leading `0x`.
String ensure0x(String hex) => hex.startsWith('0x') ? hex : '0x$hex';

/// Decodes a hex string (with or without `0x`) into bytes.
///
/// Throws [FormatException] for odd-length or non-hex input.
Uint8List hexToBytes(String hex) {
  var s = strip0x(hex);
  if (s.length.isOdd) {
    throw FormatException('Hex string must have an even length', hex);
  }
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    final hi = _hexNibble(s.codeUnitAt(i * 2));
    final lo = _hexNibble(s.codeUnitAt(i * 2 + 1));
    out[i] = (hi << 4) | lo;
  }
  return out;
}

/// Encodes bytes as a lowercase `0x`-prefixed hex string.
String bytesToHex(List<int> bytes, {bool prefix = true}) {
  final sb = StringBuffer(prefix ? '0x' : '');
  for (final b in bytes) {
    sb.write(_hexDigits[(b >> 4) & 0xf]);
    sb.write(_hexDigits[b & 0xf]);
  }
  return sb.toString();
}

/// Concatenates byte chunks into a single [Uint8List].
Uint8List concatBytes(List<List<int>> chunks) {
  var total = 0;
  for (final c in chunks) {
    total += c.length;
  }
  final out = Uint8List(total);
  var offset = 0;
  for (final c in chunks) {
    out.setRange(offset, offset + c.length, c);
    offset += c.length;
  }
  return out;
}

const _hexDigits = '0123456789abcdef';

int _hexNibble(int codeUnit) {
  // 0-9
  if (codeUnit >= 0x30 && codeUnit <= 0x39) return codeUnit - 0x30;
  // a-f
  if (codeUnit >= 0x61 && codeUnit <= 0x66) return codeUnit - 0x61 + 10;
  // A-F
  if (codeUnit >= 0x41 && codeUnit <= 0x46) return codeUnit - 0x41 + 10;
  throw FormatException('Invalid hex character', String.fromCharCode(codeUnit));
}
