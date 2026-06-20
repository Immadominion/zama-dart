import 'dart:typed_data';

import '../config/networks.dart';
import '../utils/hex.dart';

/// Builds the 92-byte protocol aux metadata bound into an input proof's ZK
/// associated data:
///
///   contractAddress(20) | userAddress(20) | aclContractAddress(20) | chainId(32, BE)
///
/// This mirrors `@zama-fhe/relayer-sdk` `encrypt.ts` byte-for-byte (verified
/// against the reference source) and is what `build_with_proof_packed` signs, so
/// it must match exactly or the relayer rejects the proof.
Uint8List buildInputMetadata({
  required String contractAddress,
  required String userAddress,
  required FhevmNetworkConfig network,
}) {
  final contract = hexToBytes(contractAddress);
  final user = hexToBytes(userAddress);
  final acl = hexToBytes(network.aclContractAddress);
  _require20(contract, 'contractAddress');
  _require20(user, 'userAddress');
  _require20(acl, 'aclContractAddress');

  final out = Uint8List(92);
  out.setRange(0, 20, contract);
  out.setRange(20, 40, user);
  out.setRange(40, 60, acl);
  // chainId as a 32-byte big-endian word in the trailing slot.
  var v = network.chainId;
  for (var i = 91; i >= 60 && v > 0; i--) {
    out[i] = v & 0xff;
    v >>= 8;
  }
  return out;
}

void _require20(Uint8List bytes, String name) {
  if (bytes.length != 20) {
    throw ArgumentError.value(
        bytes.length, name, 'expected a 20-byte address');
  }
}
