@Tags(['network'])
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:web3dart/web3dart.dart' as web3;
import 'package:zama_fhe/zama_fhe.dart';
import 'package:zama_fhe_ffi/zama_fhe_ffi.dart';
import 'package:zama_fhe_ffi/zama_kms.dart';
import 'package:test/test.dart';

/// Milestone M2 — a user privately (user-)decrypts their own confidential value,
/// end-to-end on live Sepolia, driven entirely through the high-level
/// [FhevmInstance] API: encrypt → on-chain `increment` (grants the handle to
/// msg.sender via FHE.allow) → `instance.userDecrypt` (keypair + EIP-712 sign +
/// `/user-decrypt` + KMS threshold verify + native decrypt) → assert.
///
///   ZAMA_NETWORK_TESTS=1 ZAMA_NATIVE_LIB=... ZAMA_KMS_LIB=... \
///   SEPOLIA_RPC_URL=... SEPOLIA_PRIVATE_KEY=0x... FHE_COUNTER=0x... \
///   dart test test/m2_userdecrypt_test.dart -t network
const _abi = '''
[{"type":"function","name":"increment","stateMutability":"nonpayable",
  "inputs":[{"name":"inputEuint32","type":"bytes32"},{"name":"inputProof","type":"bytes"}],"outputs":[]},
 {"type":"function","name":"getCount","stateMutability":"view","inputs":[],
  "outputs":[{"name":"","type":"bytes32"}]}]
''';

const _kmsVerifierAbi = '''
[{"type":"function","name":"getKmsSigners","stateMutability":"view","inputs":[],
  "outputs":[{"name":"","type":"address[]"}]},
 {"type":"function","name":"getThreshold","stateMutability":"view","inputs":[],
  "outputs":[{"name":"","type":"uint256"}]}]
''';

final _env = Platform.environment;
bool get _enabled =>
    _env['ZAMA_NETWORK_TESTS'] == '1' &&
    (_env['SEPOLIA_RPC_URL']?.isNotEmpty ?? false) &&
    (_env['SEPOLIA_PRIVATE_KEY']?.isNotEmpty ?? false) &&
    (_env['FHE_COUNTER']?.isNotEmpty ?? false) &&
    (_env['ZAMA_KMS_LIB']?.isNotEmpty ?? false);

void main() {
  group('M2: user-decrypt on Sepolia', _run,
      skip: _enabled ? false : 'set ZAMA_NETWORK_TESTS + libs + FHE_COUNTER to run M2');
}

void _run() {
  const net = FhevmNetworkConfig.sepolia;
  const amount = 9;

  test('increment then privately user-decrypt the count', () async {
    final rpcUrl = _env['SEPOLIA_RPC_URL']!;
    final contractAddr = _env['FHE_COUNTER']!;
    final creds = web3.EthPrivateKey.fromHex(_env['SEPOLIA_PRIVATE_KEY']!);
    final me = creds.address.eip55With0x;
    final privKey = _privKeyBytes(_env['SEPOLIA_PRIVATE_KEY']!);

    final client = web3.Web3Client(rpcUrl, http.Client());
    final cc = ConfidentialContract(
      abiJson: _abi, name: 'FHECounter', address: contractAddr,
      client: client, chainId: net.chainId,
    );
    // The whole confidential client stack behind one object.
    final instance = FhevmInstance(
      network: net,
      backend: NativeFhevmBackend(ZamaNative.openDefault()),
    );
    final kmsBackend = KmsNativeBackend(ZamaKms.openDefault());

    try {
      // KMS signers + threshold from the on-chain KMSVerifier (the instance
      // verifies the threshold signatures in Dart before trusting a value).
      final kmsv = ConfidentialContract(
        abiJson: _kmsVerifierAbi, name: 'KMSVerifier',
        address: net.kmsContractAddress, client: client, chainId: net.chainId,
      );
      final signerAddrs = (await kmsv.read('getKmsSigners', const [])).single as List;
      final kmsSigners = [
        for (final a in signerAddrs) (a as dynamic).eip55With0x as String
      ];
      final threshold = ((await kmsv.read('getThreshold', const [])).single as BigInt).toInt();
      expect(kmsSigners, isNotEmpty);
      expect(threshold, greaterThan(0));

      // The user's EIP-712 signer (wraps their wallet key).
      Future<Uint8List> signer(Uint8List digest) async =>
          _sigBytes(web3.sign(digest, privKey));

      // Reads getCount(), then user-decrypts it (threshold-verified internally).
      Future<BigInt> decryptCount() async {
        final handle =
            bytesToHex((await cc.read('getCount', const [])).single as Uint8List);
        final clears = await instance.userDecrypt(
          pairs: [HandleContractPair(handle: handle, contractAddress: contractAddr)],
          contractAddresses: [contractAddr],
          userAddress: me,
          signer: signer,
          kms: kmsBackend,
          kmsSigners: kmsSigners,
          threshold: threshold,
        );
        return clears.single.asBigInt; // bytes are little-endian; asBigInt handles it
      }

      // before
      final before = await decryptCount();

      // increment by `amount` on-chain (grants the new total to me).
      final enc = await instance
          .createEncryptedInput(contractAddress: contractAddr, userAddress: me)
          .add32(amount)
          .encrypt();
      final txHash = await cc.send('increment',
          [enc.handle, enc.inputProof], credentials: creds);
      final receipt = await _waitReceipt(client, txHash);
      expect(receipt.status, isTrue, reason: 'increment reverted');

      // after — the user-decrypted total must have grown by exactly `amount`.
      final after = await decryptCount();
      expect(after - before, BigInt.from(amount), reason: 'user-decrypt delta');
      // ignore: avoid_print
      print('M2 ✓  tx=$txHash  before=$before after=$after (Δ=$amount)');
    } finally {
      instance.dispose();
      client.dispose();
    }
  }, timeout: const Timeout(Duration(minutes: 8)));
}

/// Packs a web3dart signature into the 65-byte `r||s||v` the protocol expects.
Uint8List _sigBytes(web3.MsgSignature sig) {
  final r = _u(sig.r), s = _u(sig.s);
  final v = sig.v < 27 ? sig.v + 27 : sig.v;
  return Uint8List(65)
    ..setRange(0, 32, r)
    ..setRange(32, 64, s)
    ..[64] = v;
}

Uint8List _u(BigInt v) {
  final out = Uint8List(32);
  var x = v;
  for (var i = 31; i >= 0 && x > BigInt.zero; i--) {
    out[i] = (x & BigInt.from(0xff)).toInt();
    x >>= 8;
  }
  return out;
}

Uint8List _privKeyBytes(String hex) {
  final h = hex.startsWith('0x') ? hex.substring(2) : hex;
  final out = Uint8List(32);
  for (var i = 0; i < 32; i++) {
    out[i] = int.parse(h.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
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
