import 'dart:convert';
import 'dart:typed_data';

import '../types/fhe_type.dart';
import '../utils/hex.dart';
import '../utils/keccak.dart';

/// A 32-byte ciphertext handle — the on-chain identifier for an encrypted value.
///
/// Faithful port of `@zama-fhe/relayer-sdk` `src/sdk/FhevmHandle.ts`. The handle
/// is computed entirely client-side (we never trust the relayer for it).
///
/// Byte layout (`toBytes32`):
/// ```
/// [0..21)  hash21     (21 bytes) truncated keccak of the input hash
/// [21]     index      input index within the proof, or 0xff if "computed"
/// [22..30) chainId    8 bytes, big-endian (low 8 bytes of the uint64)
/// [30]     fheTypeId  the FHE type tag
/// [31]     version    ciphertext version (currently 0)
/// ```
class FhevmHandle {
  FhevmHandle._({
    required this.hash21,
    required this.chainId,
    required this.fheType,
    required this.version,
    required this.computed,
    this.index,
  }) {
    if (chainId < BigInt.zero || chainId > _uint64Max) {
      throw ArgumentError.value(chainId, 'chainId', 'ChainId must be a uint64');
    }
    if (hash21.length != 21) {
      throw ArgumentError.value(
          hash21.length, 'hash21.length', 'Hash21 must be 21 bytes');
    }
  }

  /// Domain separator for the raw-ciphertext blob hash.
  static const rawCtHashDomainSeparator = 'ZK-w_rct';

  /// Domain separator for the per-input handle hash.
  static const handleHashDomainSeparator = 'ZK-w_hdl';

  /// Current ciphertext version tag.
  static const currentCiphertextVersion = 0;

  static final BigInt _uint64Max = (BigInt.one << 64) - BigInt.one;

  /// First 21 bytes of the input hash.
  final Uint8List hash21;

  /// Host chain id encoded into the handle.
  final BigInt chainId;

  /// The FHE type of the encrypted value.
  final FheType fheType;

  /// Ciphertext version tag.
  final int version;

  /// True when this handle is the result of an on-chain FHE op (index byte 0xff)
  /// rather than a fresh user input.
  final bool computed;

  /// Index of this input within the packed proof (null for [computed] handles).
  final int? index;

  Uint8List? _bytes32;

  /// Serializes to the canonical 32-byte handle.
  Uint8List toBytes32() {
    final cached = _bytes32;
    if (cached != null) return cached;

    final out = Uint8List(32);
    out.setRange(0, 21, hash21);
    out[21] = computed ? 255 : index!;
    // Low 8 bytes of the uint64 chainId, big-endian.
    final chainId32 = _uint64ToBytes32(chainId);
    out.setRange(22, 30, chainId32.sublist(24, 32));
    out[30] = fheType.id;
    out[31] = version;

    _bytes32 = out;
    return out;
  }

  /// Serializes to a lowercase `0x`-prefixed 32-byte hex string.
  String toBytes32Hex() => bytesToHex(toBytes32());

  @override
  String toString() => toBytes32Hex();

  /// Builds a handle from its components.
  factory FhevmHandle.fromComponents({
    required Uint8List hash21,
    required BigInt chainId,
    required FheType fheType,
    int version = currentCiphertextVersion,
    bool computed = false,
    int? index,
  }) {
    return FhevmHandle._(
      hash21: hash21,
      chainId: chainId,
      fheType: fheType,
      version: version,
      computed: computed,
      index: index,
    );
  }

  /// Parses a 32-byte handle back into its components.
  factory FhevmHandle.fromBytes32(Uint8List bytes) {
    if (bytes.length != 32) {
      throw ArgumentError.value(
          bytes.length, 'bytes.length', 'Handle must be 32 bytes');
    }
    final indexByte = bytes[21];
    final computed = indexByte == 255;

    var chainId = BigInt.zero;
    for (var i = 22; i < 30; i++) {
      chainId = (chainId << 8) | BigInt.from(bytes[i]);
    }

    final fheType = FheType.fromId(bytes[30]);

    return FhevmHandle._(
      hash21: Uint8List.fromList(bytes.sublist(0, 21)),
      chainId: chainId,
      fheType: fheType,
      version: bytes[31],
      computed: computed,
      index: computed ? null : indexByte,
    );
  }

  /// Parses a `0x`-prefixed 32-byte hex handle.
  factory FhevmHandle.fromBytes32Hex(String hex) =>
      FhevmHandle.fromBytes32(hexToBytes(hex));

  /// Computes all input handles for a proven ciphertext blob, in order.
  ///
  /// This is the client-side handle derivation used after encryption:
  /// ```
  /// blobHash   = keccak256("ZK-w_rct" || ciphertextWithZkProof)
  /// handleHash = keccak256("ZK-w_hdl" || blobHash || index || aclAddr20 || chainId32)
  /// hash21     = handleHash[0..21)
  /// ```
  ///
  /// [encryptionBits] is the per-input TFHE bit width list (e.g. `[32, 64]`),
  /// which determines each handle's [FheType].
  static List<FhevmHandle> computeInputHandles({
    required Uint8List ciphertextWithZkProof,
    required String aclContractAddress,
    required BigInt chainId,
    required List<int> encryptionBits,
    int version = currentCiphertextVersion,
  }) {
    final domainSep = ascii.encode(rawCtHashDomainSeparator);
    final blobHash = keccak256(concatBytes([domainSep, ciphertextWithZkProof]));

    final aclBytes20 = _addressToBytes20(aclContractAddress);
    final chainId32 = _uint64ToBytes32(chainId);

    final handles = <FhevmHandle>[];
    for (var i = 0; i < encryptionBits.length; i++) {
      final hash21 = _computeInputHash21(
        blobHash: blobHash,
        index: i,
        aclBytes20: aclBytes20,
        chainId32: chainId32,
      );
      handles.add(FhevmHandle._(
        hash21: hash21,
        chainId: chainId,
        fheType: FheType.fromEncryptionBits(encryptionBits[i]),
        version: version,
        computed: false,
        index: i,
      ));
    }
    return handles;
  }

  static Uint8List _computeInputHash21({
    required Uint8List blobHash,
    required int index,
    required Uint8List aclBytes20,
    required Uint8List chainId32,
  }) {
    final domainSep = ascii.encode(handleHashDomainSeparator);
    final full = keccak256(concatBytes([
      domainSep,
      blobHash,
      Uint8List.fromList([index]),
      aclBytes20,
      chainId32,
    ]));
    return Uint8List.fromList(full.sublist(0, 21));
  }

  /// 32-byte big-endian encoding of a uint64 (24 leading zero bytes).
  static Uint8List _uint64ToBytes32(BigInt value) {
    if (value < BigInt.zero || value > _uint64Max) {
      throw ArgumentError.value(value, 'value', 'Must fit in uint64');
    }
    final out = Uint8List(32);
    var v = value;
    for (var i = 31; i >= 24; i--) {
      out[i] = (v & BigInt.from(0xff)).toInt();
      v >>= 8;
    }
    return out;
  }

  static Uint8List _addressToBytes20(String address) {
    final bytes = hexToBytes(address);
    if (bytes.length != 20) {
      throw ArgumentError.value(
          address, 'address', 'Address must be 20 bytes');
    }
    return bytes;
  }
}
