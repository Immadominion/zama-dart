import 'dart:typed_data';

import 'package:web3dart/web3dart.dart' as web3;
// `EthereumAddress` lives in the `wallet` package (web3dart uses it internally
// but does not re-export it from this Celo-compatible fork).
import 'package:wallet/wallet.dart' show EthereumAddress;

import '../handle/fhevm_handle.dart';

/// Thin wrapper over `web3dart` for calling confidential (FHEVM) contracts.
///
/// Handles the one FHE-specific concern: an encrypted argument is an
/// `externalEuintXX` (ABI `bytes32`) handle accompanied by a `bytes inputProof`.
/// Pass a [FhevmHandle] (auto-converted to its 32 bytes) or a raw [Uint8List];
/// everything else (addresses, ints) is forwarded to web3dart unchanged.
///
/// Supports both signing paths:
/// - **embedded key:** [send] signs + broadcasts with a web3dart `Credentials`.
/// - **external wallet (WalletConnect):** [encodeCall] returns the calldata to
///   hand to the wallet for `eth_sendTransaction`.
class ConfidentialContract {
  ConfidentialContract({
    required String abiJson,
    required String name,
    required String address,
    required this.client,
    required this.chainId,
  })  : contract = web3.DeployedContract(
          web3.ContractAbi.fromJson(abiJson, name),
          EthereumAddress.fromHex(address),
        );

  final web3.DeployedContract contract;
  final web3.Web3Client client;
  final int chainId;

  /// ABI-encodes calldata (4-byte selector + args) for [functionName].
  Uint8List encodeCall(String functionName, List<Object?> args) {
    final fn = contract.function(functionName);
    return fn.encodeCall(_mapArgs(args));
  }

  /// Read-only `eth_call`. Returns the decoded output list. [sender] is an
  /// optional `0x`-address used as `msg.sender`.
  Future<List<dynamic>> read(
    String functionName,
    List<Object?> args, {
    String? sender,
  }) {
    final fn = contract.function(functionName);
    return client.call(
      contract: contract,
      function: fn,
      params: _mapArgs(args),
      sender: sender != null ? EthereumAddress.fromHex(sender) : null,
    );
  }

  /// Signs with [credentials] and broadcasts a confidential write. Returns the
  /// transaction hash.
  Future<String> send(
    String functionName,
    List<Object?> args, {
    required web3.Credentials credentials,
    BigInt? maxGas,
  }) {
    final fn = contract.function(functionName);
    return client.sendTransaction(
      credentials,
      web3.Transaction.callContract(
        contract: contract,
        function: fn,
        parameters: _mapArgs(args),
        maxGas: maxGas?.toInt(),
      ),
      chainId: chainId,
    );
  }

  /// Converts FHE-specific Dart types to the values web3dart's ABI codec wants.
  List<dynamic> _mapArgs(List<Object?> args) => [
        for (final a in args)
          if (a is FhevmHandle) a.toBytes32() else a,
      ];
}
