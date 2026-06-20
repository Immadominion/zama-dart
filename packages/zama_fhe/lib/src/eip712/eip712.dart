import 'dart:convert';
import 'dart:typed_data';

import '../utils/hex.dart';
import '../utils/keccak.dart';

/// A single typed-data field, e.g. `{name: "publicKey", type: "bytes"}`.
class Eip712Field {
  const Eip712Field(this.name, this.type);
  final String name;
  final String type;

  Map<String, String> toJson() => {'name': name, 'type': type};
}

/// EIP-712 typed structured data, ready to hand to a wallet for signing.
///
/// `toJson()` produces the exact shape expected by `eth_signTypedData_v4`.
class Eip712TypedData {
  const Eip712TypedData({
    required this.types,
    required this.primaryType,
    required this.domain,
    required this.message,
  });

  /// Type definitions, keyed by struct name. Must include `EIP712Domain`.
  final Map<String, List<Eip712Field>> types;

  /// Name of the primary struct being signed.
  final String primaryType;

  /// Domain values (`name`, `version`, `chainId`, `verifyingContract`).
  final Map<String, Object?> domain;

  /// The message values for [primaryType].
  final Map<String, Object?> message;

  /// The 32-byte EIP-712 signing digest:
  /// `keccak256(0x1901 || domainSeparator || hashStruct(primaryType, message))`.
  Uint8List digest() {
    return keccak256(concatBytes([
      [0x19, 0x01],
      _hashStruct('EIP712Domain', domain),
      _hashStruct(primaryType, message),
    ]));
  }

  /// Hex form of [digest].
  String digestHex() => bytesToHex(digest());

  /// The domain separator, `hashStruct("EIP712Domain", domain)`.
  Uint8List domainSeparator() => _hashStruct('EIP712Domain', domain);

  /// JSON shape for `eth_signTypedData_v4`.
  Map<String, Object?> toJson() => {
        'types': {
          for (final e in types.entries)
            e.key: e.value.map((f) => f.toJson()).toList(),
        },
        'primaryType': primaryType,
        'domain': domain,
        'message': message,
      };

  Uint8List _hashStruct(String type, Map<String, Object?> data) =>
      keccak256(concatBytes([_typeHash(type), _encodeData(type, data)]));

  Uint8List _typeHash(String type) =>
      keccak256(ascii.encode(_encodeType(type)));

  /// `PrimaryType(type name,...)` followed by referenced structs in
  /// alphabetical order (standard EIP-712 dependency encoding).
  String _encodeType(String primaryType) {
    final deps = <String>{};
    _collectDeps(primaryType, deps);
    deps.remove(primaryType);
    final ordered = [primaryType, ...(deps.toList()..sort())];
    final sb = StringBuffer();
    for (final t in ordered) {
      final fields = types[t]!;
      sb.write(t);
      sb.write('(');
      sb.write(fields.map((f) => '${f.type} ${f.name}').join(','));
      sb.write(')');
    }
    return sb.toString();
  }

  void _collectDeps(String type, Set<String> found) {
    if (found.contains(type) || !types.containsKey(type)) return;
    found.add(type);
    for (final f in types[type]!) {
      final base = _baseType(f.type);
      if (types.containsKey(base)) _collectDeps(base, found);
    }
  }

  Uint8List _encodeData(String type, Map<String, Object?> data) {
    final fields = types[type]!;
    final parts = <List<int>>[];
    for (final f in fields) {
      parts.add(_encodeField(f.type, data[f.name]));
    }
    return concatBytes(parts);
  }

  /// Encodes a single value to its 32-byte EIP-712 representation.
  Uint8List _encodeField(String type, Object? value) {
    // Arrays: keccak256 of the concatenated encodings of each element.
    if (type.endsWith(']')) {
      final base = _baseType(type);
      final list = value as List;
      return keccak256(
          concatBytes([for (final v in list) _encodeField(base, v)]));
    }
    // Referenced struct: hashStruct.
    if (types.containsKey(type)) {
      return _hashStruct(type, (value as Map).cast<String, Object?>());
    }
    switch (type) {
      case 'bytes':
        return keccak256(_asBytes(value));
      case 'string':
        return keccak256(utf8.encode(value as String));
      case 'address':
        return _padLeft32(hexToBytes(value as String));
      case 'bool':
        return _uintToBytes32(BigInt.from((value as bool) ? 1 : 0));
    }
    if (type.startsWith('uint') || type.startsWith('int')) {
      return _uintToBytes32(_asBigInt(value));
    }
    if (type.startsWith('bytes')) {
      // Fixed-size bytesN, right-padded to 32.
      return _padRight32(_asBytes(value));
    }
    throw ArgumentError.value(type, 'type', 'Unsupported EIP-712 type');
  }

  static String _baseType(String type) {
    final i = type.indexOf('[');
    return i == -1 ? type : type.substring(0, i);
  }

  static Uint8List _asBytes(Object? value) {
    if (value is Uint8List) return value;
    if (value is List<int>) return Uint8List.fromList(value);
    if (value is String) return hexToBytes(value);
    throw ArgumentError.value(value, 'value', 'Expected bytes');
  }

  static BigInt _asBigInt(Object? value) {
    if (value is BigInt) return value;
    if (value is int) return BigInt.from(value);
    if (value is String) {
      return value.startsWith('0x')
          ? BigInt.parse(strip0x(value), radix: 16)
          : BigInt.parse(value);
    }
    throw ArgumentError.value(value, 'value', 'Expected integer');
  }

  static Uint8List _uintToBytes32(BigInt value) {
    final out = Uint8List(32);
    var v = value;
    for (var i = 31; i >= 0 && v > BigInt.zero; i--) {
      out[i] = (v & BigInt.from(0xff)).toInt();
      v >>= 8;
    }
    return out;
  }

  static Uint8List _padLeft32(Uint8List bytes) {
    final out = Uint8List(32);
    out.setRange(32 - bytes.length, 32, bytes);
    return out;
  }

  static Uint8List _padRight32(Uint8List bytes) {
    final out = Uint8List(32);
    out.setRange(0, bytes.length, bytes);
    return out;
  }
}
