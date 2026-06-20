import 'dart:typed_data';

/// A `{ dataId, urls }` entry from the relayer `/keyurl` response.
class KeyUrlEntry {
  const KeyUrlEntry({required this.dataId, required this.urls});
  final String dataId;
  final List<String> urls;
}

/// Parsed `/keyurl` response: where to download the FHE public key and CRS.
///
/// Mirrors `@zama-fhe/relayer-sdk` and tolerates both camelCase (current v2)
/// and snake_case field names.
class KeyUrlResponse {
  const KeyUrlResponse({required this.publicKey, required this.crs});

  /// The compact FHE public key location.
  final KeyUrlEntry publicKey;

  /// CRS locations keyed by bit capacity, e.g. `"2048"`.
  final Map<String, KeyUrlEntry> crs;

  /// Parses the full relayer response envelope (`{ status, response: {...} }`).
  factory KeyUrlResponse.fromJson(Map<String, dynamic> json) {
    final response = (json['response'] ?? json) as Map<String, dynamic>;

    final keyInfoList =
        (response['fheKeyInfo'] ?? response['fhe_key_info']) as List?;
    if (keyInfoList == null || keyInfoList.isEmpty) {
      throw const FormatException('keyurl: missing fheKeyInfo');
    }
    final keyInfo = keyInfoList.first as Map<String, dynamic>;
    final pk =
        (keyInfo['fhePublicKey'] ?? keyInfo['fhe_public_key']) as Map<String, dynamic>;

    final crsMap = response['crs'] as Map<String, dynamic>?;
    if (crsMap == null) throw const FormatException('keyurl: missing crs');

    return KeyUrlResponse(
      publicKey: _entry(pk),
      crs: {
        for (final e in crsMap.entries)
          e.key: _entry(e.value as Map<String, dynamic>),
      },
    );
  }

  static KeyUrlEntry _entry(Map<String, dynamic> m) => KeyUrlEntry(
        dataId: (m['dataId'] ?? m['data_id']) as String,
        urls: (m['urls'] as List).cast<String>(),
      );
}

/// Downloaded FHE key material, ready to hand to the native backend or cache.
class KeyMaterial {
  const KeyMaterial({
    required this.publicKey,
    required this.publicKeyId,
    required this.crs,
    required this.crsId,
    required this.crsBits,
  });

  /// Safe-serialized compact public key bytes.
  final Uint8List publicKey;
  final String publicKeyId;

  /// Safe-serialized CRS bytes.
  final Uint8List crs;
  final String crsId;

  /// CRS bit capacity, e.g. `"2048"`.
  final String crsBits;
}
