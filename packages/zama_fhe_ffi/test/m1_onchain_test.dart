@Tags(['network'])
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:web3dart/web3dart.dart' as web3;
import 'package:zama_fhe/zama_fhe.dart';
import 'package:zama_fhe_ffi/zama_fhe_ffi.dart';
import 'package:test/test.dart';

/// Milestone M1 — the first end-to-end confidential transaction from Dart on
/// Sepolia: native-encrypt an amount → relayer `/input-proof` → `increment(...)`
/// on-chain → read `count()` handle → `publicDecrypt` it → assert it grew.
///
/// Opt-in; needs a funded Sepolia key + a deployed ConfidentialCounter:
///   ZAMA_NETWORK_TESTS=1 ZAMA_NATIVE_LIB=/abs/lib \
///   SEPOLIA_RPC_URL=... SEPOLIA_PRIVATE_KEY=0x... CONFIDENTIAL_COUNTER=0x... \
///   dart test test/m1_onchain_test.dart -t network
const _abi = '''
[{"type":"function","name":"increment","stateMutability":"nonpayable",
  "inputs":[{"name":"inputHandle","type":"bytes32"},{"name":"inputProof","type":"bytes"}],"outputs":[]},
 {"type":"function","name":"count","stateMutability":"view","inputs":[],
  "outputs":[{"name":"","type":"bytes32"}]}]
''';

final _env = Platform.environment;
bool get _enabled =>
    _env['ZAMA_NETWORK_TESTS'] == '1' &&
    (_env['SEPOLIA_RPC_URL']?.isNotEmpty ?? false) &&
    (_env['SEPOLIA_PRIVATE_KEY']?.isNotEmpty ?? false) &&
    (_env['CONFIDENTIAL_COUNTER']?.isNotEmpty ?? false);

void main() {
  group('M1: confidential increment + public decrypt on Sepolia', _run,
      skip: _enabled
          ? false
          : 'set ZAMA_NETWORK_TESTS=1 + SEPOLIA_RPC_URL + SEPOLIA_PRIVATE_KEY '
              '+ CONFIDENTIAL_COUNTER to run M1');
}

void _run() {
  const net = FhevmNetworkConfig.sepolia;
  const amount = 5;

  test('increment by $amount then public-decrypt the total', () async {
    final rpcUrl = _env['SEPOLIA_RPC_URL']!;
    final contractAddr = _env['CONFIDENTIAL_COUNTER']!;
    final creds = web3.EthPrivateKey.fromHex(_env['SEPOLIA_PRIVATE_KEY']!);
    final me = creds.address.eip55With0x;

    final client = web3.Web3Client(rpcUrl, http.Client());
    final cc = ConfidentialContract(
      abiJson: _abi,
      name: 'ConfidentialCounter',
      address: contractAddr,
      client: client,
      chainId: net.chainId,
    );
    // The whole client stack behind one object (the public DX API).
    final instance = FhevmInstance(
      network: net,
      backend: NativeFhevmBackend(ZamaNative.openDefault()),
    );

    try {
      // 1. encrypt the amount + register the proof with the relayer in one call
      //    (key material is fetched + cached lazily on first use).
      final enc = await instance
          .createEncryptedInput(contractAddress: contractAddr, userAddress: me)
          .add32(amount)
          .encrypt();

      // 2. increment(handle, inputProof) on-chain
      final txHash = await cc.send(
        'increment',
        [enc.handle, enc.inputProof],
        credentials: creds,
      );
      final receipt = await _waitReceipt(client, txHash);
      expect(receipt.status, isTrue, reason: 'increment tx reverted');

      // 3. read the (encrypted) count handle, then public-decrypt it
      final countHandle = (await cc.read('count', const [])).single as Uint8List;
      final countHex = bytesToHex(countHandle);
      final pd = await instance.publicDecrypt([countHex]);
      final total = pd.values[FhevmHandle.fromBytes32Hex(countHex).toBytes32Hex()]
          as BigInt;

      expect(total, greaterThanOrEqualTo(BigInt.from(amount)));
      // ignore: avoid_print
      print('M1 ✓  tx=$txHash  count=$total  (added $amount)');
    } finally {
      instance.dispose();
      client.dispose();
    }
  }, timeout: const Timeout(Duration(minutes: 8)));
}

Future<web3.TransactionReceipt> _waitReceipt(web3.Web3Client c, String hash,
    {Duration timeout = const Duration(minutes: 5)}) async {
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    final r = await c.getTransactionReceipt(hash);
    if (r != null) return r;
    await Future<void>.delayed(const Duration(seconds: 3));
  }
  throw StateError('receipt timeout for $hash');
}
