import 'dart:typed_data';

import '../handle/fhevm_handle.dart';
import '../relayer/relayer_client.dart';
import '../types/fhe_type.dart';
import 'aux_metadata.dart';
import 'fhevm_backend.dart';
import 'fhevm_instance.dart';

/// The on-chain-ready result of encrypting a batch of inputs: the bytes32
/// handles to pass as the encrypted arguments, plus the assembled `inputProof`.
class EncryptedInput {
  const EncryptedInput({
    required this.handles,
    required this.inputProof,
    required this.typedHandles,
  });

  /// One `bytes32` per input, in the order they were added. Pass these straight
  /// to the contract method (e.g. as `externalEuint64`).
  final List<Uint8List> handles;

  /// The assembled `inputProof` bytes, as the contract expects.
  final Uint8List inputProof;

  /// The rich [FhevmHandle] objects (type, index, version) behind [handles].
  final List<FhevmHandle> typedHandles;

  /// The single handle, when exactly one input was added (convenience).
  Uint8List get handle => handles.single;
}

/// A fluent builder that accumulates cleartext inputs for one contract call,
/// then encrypts them and registers the proof with the relayer in one
/// [encrypt] call. Obtain one via [FhevmInstance.createEncryptedInput].
///
/// ```dart
/// final enc = await instance
///     .createEncryptedInput(contractAddress: c, userAddress: me)
///     .add64(1000)
///     .addBool(true)
///     .encrypt();
/// await contract.send('transfer', [to, enc.handles[0], enc.inputProof]);
/// ```
class EncryptedInputBuilder {
  EncryptedInputBuilder({
    required FhevmInstance instance,
    required this.contractAddress,
    required this.userAddress,
  }) : _instance = instance;

  final FhevmInstance _instance;
  final String contractAddress;
  final String userAddress;
  final List<FheInputValue> _inputs = [];

  /// The inputs added so far (read-only view).
  List<FheInputValue> get inputs => List.unmodifiable(_inputs);

  EncryptedInputBuilder addBool(bool value) =>
      _add(value ? BigInt.one : BigInt.zero, FheType.ebool);

  EncryptedInputBuilder add8(int value) =>
      _add(BigInt.from(value), FheType.euint8);

  EncryptedInputBuilder add16(int value) =>
      _add(BigInt.from(value), FheType.euint16);

  EncryptedInputBuilder add32(int value) =>
      _add(BigInt.from(value), FheType.euint32);

  /// Adds a `euint64`. Accepts an [int] or a [BigInt] (values ≥ 2^63 must use a
  /// BigInt to avoid Dart int overflow).
  EncryptedInputBuilder add64(Object value) =>
      _add(_big(value), FheType.euint64);

  EncryptedInputBuilder add128(Object value) =>
      _add(_big(value), FheType.euint128);

  EncryptedInputBuilder add256(BigInt value) => _add(value, FheType.euint256);

  /// Adds an `eaddress` from a `0x`-prefixed 20-byte hex address.
  EncryptedInputBuilder addAddress(String hexAddress) {
    final h = (hexAddress.startsWith('0x') || hexAddress.startsWith('0X'))
        ? hexAddress.substring(2)
        : hexAddress;
    if (h.length != 40) {
      throw ArgumentError.value(
          hexAddress, 'hexAddress', 'expected a 20-byte (40 hex char) address');
    }
    return _add(BigInt.parse(h, radix: 16), FheType.eaddress);
  }

  /// Adds a value of an arbitrary [FheType] (escape hatch for dynamic code).
  EncryptedInputBuilder add(BigInt value, FheType type) => _add(value, type);

  EncryptedInputBuilder _add(BigInt value, FheType type) {
    if (value.isNegative) {
      throw ArgumentError.value(value, 'value', 'must be non-negative');
    }
    final max = _maxValue(type);
    if (value > max) {
      throw ArgumentError.value(value, 'value',
          'exceeds ${type.typeName} max ($max) — would overflow on encryption');
    }
    _inputs.add(FheInputValue(value, type));
    return this;
  }

  /// Largest value an [FheType] can hold (`ebool` is 0/1; `eaddress` is 160-bit;
  /// `euintN` is `2^N - 1`). `ebool.encryptionBits` is 2 (TFHE minimum) but the
  /// value range is a single bit.
  static BigInt _maxValue(FheType type) {
    final bits = type == FheType.ebool ? 1 : type.encryptionBits;
    return (BigInt.one << bits) - BigInt.one;
  }

  /// Encrypts all accumulated inputs and registers the proof with the relayer.
  /// Returns the bytes32 handles + assembled `inputProof` ready for a contract
  /// call. Throws [InputProofRejectedException] if the relayer rejects the proof.
  Future<EncryptedInput> encrypt() async {
    if (_inputs.isEmpty) {
      throw StateError('EncryptedInputBuilder: no inputs added');
    }
    await _instance.ensureReady();

    final metadata = buildInputMetadata(
      contractAddress: contractAddress,
      userAddress: userAddress,
      network: _instance.network,
    );
    final payload = await _instance.backend.encrypt(
      inputs: _inputs,
      metadata: metadata,
      aclContractAddress: _instance.network.aclContractAddress,
      chainId: BigInt.from(_instance.network.chainId),
    );

    final response = await _instance.relayer.submitInputProof(
      contractAddress: contractAddress,
      userAddress: userAddress,
      ciphertextWithZkProof: payload.inputProof,
      chainId: _instance.network.chainId,
    );

    return EncryptedInput(
      handles: [for (final h in payload.handles) h.toBytes32()],
      inputProof: response.toInputProofBytes(),
      typedHandles: payload.handles,
    );
  }

  static BigInt _big(Object value) {
    if (value is BigInt) return value;
    if (value is int) return BigInt.from(value);
    throw ArgumentError.value(value, 'value', 'expected int or BigInt');
  }
}
