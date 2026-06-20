/// The FHE encrypted types supported by the Zama Protocol.
///
/// The numeric [id] is the on-chain type tag stored at byte 30 of every
/// ciphertext handle. Values mirror `@zama-fhe/relayer-sdk` `src/sdk/FheType.ts`.
///
/// `euint4` (id 1) is deprecated and intentionally absent.
enum FheType {
  ebool(0, 'ebool', 2, SolidityType.boolType),
  euint8(2, 'euint8', 8, SolidityType.uint256),
  euint16(3, 'euint16', 16, SolidityType.uint256),
  euint32(4, 'euint32', 32, SolidityType.uint256),
  euint64(5, 'euint64', 64, SolidityType.uint256),
  euint128(6, 'euint128', 128, SolidityType.uint256),
  eaddress(7, 'eaddress', 160, SolidityType.address),
  euint256(8, 'euint256', 256, SolidityType.uint256);

  const FheType(this.id, this.typeName, this.encryptionBits, this.solidityType);

  /// On-chain type tag (byte 30 of a handle).
  final int id;

  /// Canonical name, e.g. `euint64`.
  final String typeName;

  /// Bit width used by TFHE encryption (minimum 2; `ebool` uses 2).
  final int encryptionBits;

  /// The Solidity primitive the cleartext decodes to.
  final SolidityType solidityType;

  /// Looks up a type by its on-chain [id]. Throws [ArgumentError] if unknown
  /// (e.g. the deprecated `euint4` id 1).
  static FheType fromId(int id) {
    for (final t in FheType.values) {
      if (t.id == id) return t;
    }
    throw ArgumentError.value(id, 'id', 'Unknown FheType id');
  }

  /// Looks up a type by its [name], e.g. `euint32`.
  static FheType fromName(String name) {
    for (final t in FheType.values) {
      if (t.typeName == name) return t;
    }
    throw ArgumentError.value(name, 'name', 'Unknown FheType name');
  }

  /// Maps a TFHE encryption bit width back to its type, e.g. 64 -> euint64.
  static FheType fromEncryptionBits(int bits) {
    for (final t in FheType.values) {
      if (t.encryptionBits == bits) return t;
    }
    throw ArgumentError.value(bits, 'bits', 'Unknown encryption bit width');
  }

  /// Whether [id] is a recognized (non-deprecated) FHE type id.
  static bool isValidId(int id) {
    for (final t in FheType.values) {
      if (t.id == id) return true;
    }
    return false;
  }
}

/// The Solidity primitive an FHE type's cleartext decodes to.
enum SolidityType { boolType, uint256, address }
