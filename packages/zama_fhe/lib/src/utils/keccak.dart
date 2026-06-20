import 'dart:typed_data';

import 'package:pointycastle/digests/keccak.dart';

import 'hex.dart';

/// Keccak-256 (the Ethereum pre-NIST variant — **not** SHA3-256).
///
/// Mirrors `ethers.keccak256`, which the reference relayer SDK uses for both
/// ciphertext-handle derivation and EIP-712 struct hashing.
Uint8List keccak256(List<int> input) {
  final d = KeccakDigest(256);
  final data = input is Uint8List ? input : Uint8List.fromList(input);
  return d.process(data);
}

/// Keccak-256 returning a lowercase `0x`-prefixed hex string.
String keccak256Hex(List<int> input) => bytesToHex(keccak256(input));
