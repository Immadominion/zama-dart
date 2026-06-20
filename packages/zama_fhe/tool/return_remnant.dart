// One-off: return the leftover Sepolia ETH from the throwaway deploy wallet to
// the user's address. Reads SEPOLIA_PRIVATE_KEY + DEST + RPC from the env.
//
//   SEPOLIA_PRIVATE_KEY=0x.. DEST=0x.. RPC=https://.. dart run tool/return_remnant.dart
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:web3dart/web3dart.dart' as web3;
// EthereumAddress + EtherAmount live in the `wallet` package (this web3dart fork
// uses them internally but doesn't re-export them).
import 'package:wallet/wallet.dart' show EthereumAddress, EtherAmount;

Future<void> main() async {
  final env = Platform.environment;
  final key = env['SEPOLIA_PRIVATE_KEY']!;
  final dest = EthereumAddress.fromHex(env['DEST']!);
  final rpc = env['RPC'] ?? 'https://ethereum-sepolia-rpc.publicnode.com';
  const chainId = 11155111;

  final client = web3.Web3Client(rpc, http.Client());
  try {
    final creds = web3.EthPrivateKey.fromHex(key);
    final from = creds.address;
    final balance = await client.getBalance(from);
    final gasPrice = await client.getGasPrice();

    // Bump gas price 25% so the tx can't get stuck; standard transfer = 21000 gas.
    final gasPriceSend = EtherAmount.inWei(
        gasPrice.getInWei * BigInt.from(5) ~/ BigInt.from(4));
    final fee = gasPriceSend.getInWei * BigInt.from(21000);
    final sendWei = balance.getInWei - fee;

    print('from:    ${from.eip55With0x}');
    print('to:      ${dest.eip55With0x}');
    print('balance: ${balance.getInWei} wei (${_eth(balance.getInWei)} ETH)');
    print('gasPrice: ${gasPrice.getInWei} wei → send at ${gasPriceSend.getInWei}');
    print('fee:     $fee wei (21000 gas)');
    print('sending: $sendWei wei (${_eth(sendWei)} ETH)');

    if (sendWei <= BigInt.zero) {
      print('ABORT: balance does not cover the gas fee');
      return;
    }

    final txHash = await client.sendTransaction(
      creds,
      web3.Transaction(
        to: dest,
        value: EtherAmount.inWei(sendWei),
        maxGas: 21000,
        gasPrice: gasPriceSend,
      ),
      chainId: chainId,
    );
    print('TX: $txHash');

    for (var i = 0; i < 60; i++) {
      final r = await client.getTransactionReceipt(txHash);
      if (r != null) {
        print('CONFIRMED in block ${r.blockNumber.blockNum}, status=${r.status}');
        final after = await client.getBalance(from);
        print('remaining in deploy wallet: ${after.getInWei} wei');
        return;
      }
      await Future<void>.delayed(const Duration(seconds: 3));
    }
    print('SUBMITTED but not yet mined — check $txHash');
  } finally {
    client.dispose();
  }
}

String _eth(BigInt wei) => (wei / BigInt.from(10).pow(18)).toStringAsFixed(6);
