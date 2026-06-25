import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:web3dart/web3dart.dart' as web3;
import 'package:zama_fhe/zama_fhe.dart';
import 'package:zama_fhe_ffi/zama_fhe_ffi.dart';

/// On-chain config, injected at build time so no secret is ever in source:
///   flutter run \
///     --dart-define=SEPOLIA_RPC_URL=https://... \
///     --dart-define=SEPOLIA_PRIVATE_KEY=0x... \
///     --dart-define=CONFIDENTIAL_COUNTER=0x...
/// (the contract is m1-deploy/contracts/ConfidentialCounter.sol, deployed on
///  Sepolia — `increment(externalEuint32, inputProof)` + a publicly-decryptable
///  `count()`). With no config the app runs the local encrypt-only demo.
const _rpcUrl = String.fromEnvironment('SEPOLIA_RPC_URL');
const _privKey = String.fromEnvironment('SEPOLIA_PRIVATE_KEY');
const _counter = String.fromEnvironment('CONFIDENTIAL_COUNTER');
bool get _onchainConfigured =>
    _rpcUrl.isNotEmpty && _privKey.isNotEmpty && _counter.isNotEmpty;

const _abi = '''
[{"type":"function","name":"increment","stateMutability":"nonpayable",
  "inputs":[{"name":"inputHandle","type":"bytes32"},{"name":"inputProof","type":"bytes"}],"outputs":[]},
 {"type":"function","name":"count","stateMutability":"view","inputs":[],
  "outputs":[{"name":"","type":"bytes32"}]}]
''';

void main() => runApp(const ZamaExampleApp());

class ZamaExampleApp extends StatelessWidget {
  const ZamaExampleApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'zama-dart',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(
          colorSchemeSeed: const Color(0xFFFFD200), // Zama yellow
          brightness: Brightness.dark,
          useMaterial3: true,
        ),
        home: const HomePage(),
      );
}

enum StepState { pending, running, done, error }

class LifeStep {
  LifeStep(this.title);
  final String title;
  StepState state = StepState.pending;
  String? detail;
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  int _amount = 5;
  bool _busy = false;
  String? _error;
  BigInt? _total;
  String? _txHash;
  List<LifeStep> _steps = [];

  // ── The full confidential lifecycle, live on Sepolia ─────────────────────
  Future<void> _runOnchain() async {
    final steps = [
      LifeStep('Encrypt $_amount on-device (TFHE + ZK proof)'),
      LifeStep('Submit increment() to Sepolia'),
      LifeStep('Wait for on-chain confirmation'),
      LifeStep('Read the encrypted count handle'),
      LifeStep('Public-decrypt the new total'),
    ];
    setState(() {
      _busy = true;
      _error = null;
      _total = null;
      _txHash = null;
      _steps = steps;
    });

    const net = FhevmNetworkConfig.sepolia;
    final creds = web3.EthPrivateKey.fromHex(_privKey);
    final me = creds.address.eip55With0x;
    final client = web3.Web3Client(_rpcUrl, http.Client());
    final cc = ConfidentialContract(
      abiJson: _abi,
      name: 'ConfidentialCounter',
      address: _counter,
      client: client,
      chainId: net.chainId,
    );
    // The entire confidential client stack behind one object.
    final instance = FhevmInstance(
      network: net,
      backend: NativeFhevmBackend(ZamaNative.openDefault()),
    );

    void mark(int i, StepState s, [String? detail]) => setState(() {
          steps[i].state = s;
          if (detail != null) steps[i].detail = detail;
        });

    try {
      // 1 — native encrypt + register the ZK proof with the relayer.
      mark(0, StepState.running);
      final enc = await instance
          .createEncryptedInput(contractAddress: _counter, userAddress: me)
          .add32(_amount)
          .encrypt();
      mark(0, StepState.done,
          'handle ${_short(bytesToHex(enc.handle))} · proof ${enc.inputProof.length} B');

      // 2 — increment(handle, inputProof) on-chain.
      mark(1, StepState.running);
      final txHash = await cc.send('increment', [enc.handle, enc.inputProof],
          credentials: creds);
      setState(() => _txHash = txHash);
      mark(1, StepState.done, 'tx ${_short(txHash)}');

      // 3 — wait for the receipt.
      mark(2, StepState.running);
      final receipt = await _waitReceipt(client, txHash);
      if (receipt.status != true) throw StateError('increment tx reverted');
      mark(2, StepState.done, 'confirmed in block ${receipt.blockNumber.blockNum}');

      // 4 — read the (still encrypted) count handle.
      mark(3, StepState.running);
      final countHandle = (await cc.read('count', const [])).single as Uint8List;
      final countHex = bytesToHex(countHandle);
      mark(3, StepState.done, _short(countHex));

      // 5 — public-decrypt it (relayer + KMS signatures verified in Dart).
      mark(4, StepState.running);
      final pd = await instance.publicDecrypt([countHex]);
      final total =
          pd.values[FhevmHandle.fromBytes32Hex(countHex).toBytes32Hex()]
              as BigInt;
      mark(4, StepState.done);
      setState(() => _total = total);
    } catch (e) {
      final running = _steps.indexWhere((s) => s.state == StepState.running);
      if (running >= 0) mark(running, StepState.error);
      setState(() => _error = '$e');
    } finally {
      instance.dispose();
      client.dispose();
      setState(() => _busy = false);
    }
  }

  // ── Fallback: local encrypt + verify-decrypt (no network needed) ──────────
  Future<void> _runLocal() async {
    final steps = [LifeStep('Encrypt euint64(42) on-device + verify-decrypt')];
    setState(() {
      _busy = true;
      _error = null;
      _total = null;
      _txHash = null;
      _steps = steps;
      steps[0].state = StepState.running;
    });
    try {
      final native = ZamaNative.openDefault();
      final ctx = native.generatedContext(maxBits: 256);
      final res = ctx.encrypt(
        inputs: [ClearInput.ofInt(42, FheType.euint64)],
        metadata: Uint8List(92),
        aclContractAddress: '0x${'00' * 20}',
        chainId: BigInt.from(11155111),
      );
      final decoded = ctx.testVerifyDecrypt(
        blob: res.inputProof,
        types: const [FheType.euint64],
        metadata: Uint8List(92),
      );
      ctx.dispose();
      setState(() {
        steps[0].state = StepState.done;
        steps[0].detail =
            'handle ${_short(res.handles.single.toBytes32Hex())} · '
            'proof ${res.inputProof.length} B · decrypted ${decoded.single}';
      });
    } catch (e) {
      setState(() {
        steps[0].state = StepState.error;
        _error = '$e';
      });
    } finally {
      setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(
        title: const Text('zama-dart'),
        bottom: const PreferredSize(
          preferredSize: Size.fromHeight(20),
          child: Padding(
            padding: EdgeInsets.only(bottom: 8),
            child: Text('Confidential counter · FHE on a phone',
                style: TextStyle(fontSize: 12, color: Colors.white60)),
          ),
        ),
      ),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          _configCard(cs),
          const SizedBox(height: 20),
          if (_onchainConfigured) _amountRow(cs),
          const SizedBox(height: 12),
          FilledButton.icon(
            onPressed: _busy
                ? null
                : (_onchainConfigured ? _runOnchain : _runLocal),
            icon: _busy
                ? const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.lock),
            label: Text(_busy
                ? 'Working…'
                : (_onchainConfigured
                    ? 'Run confidential increment'
                    : 'Encrypt on-device (local demo)')),
            style: FilledButton.styleFrom(
                minimumSize: const Size.fromHeight(52)),
          ),
          const SizedBox(height: 24),
          ..._steps.map(_stepTile),
          if (_total != null) _resultCard(cs),
          if (_txHash != null) _txCard(cs),
          if (_error != null) _errorCard(cs),
        ],
      ),
    );
  }

  Widget _configCard(ColorScheme cs) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(children: [
                Icon(_onchainConfigured ? Icons.cloud_done : Icons.cloud_off,
                    size: 18, color: cs.primary),
                const SizedBox(width: 8),
                Text(_onchainConfigured ? 'Sepolia · live' : 'Local demo mode',
                    style: const TextStyle(fontWeight: FontWeight.bold)),
              ]),
              const SizedBox(height: 8),
              Text(
                _onchainConfigured
                    ? 'Counter ${_short(_counter)} — encrypt → tx → public-decrypt, '
                        'entirely on this device.'
                    : 'No on-chain config. Pass --dart-define SEPOLIA_RPC_URL / '
                        'SEPOLIA_PRIVATE_KEY / CONFIDENTIAL_COUNTER to run the full '
                        'lifecycle live on Sepolia.',
                style: const TextStyle(fontSize: 12, color: Colors.white70),
              ),
            ],
          ),
        ),
      );

  Widget _amountRow(ColorScheme cs) => Row(
        children: [
          const Text('Increment by', style: TextStyle(color: Colors.white70)),
          const Spacer(),
          IconButton.filledTonal(
            onPressed: _busy || _amount <= 1
                ? null
                : () => setState(() => _amount--),
            icon: const Icon(Icons.remove),
          ),
          SizedBox(
            width: 44,
            child: Text('$_amount',
                textAlign: TextAlign.center,
                style: const TextStyle(
                    fontSize: 22, fontWeight: FontWeight.bold)),
          ),
          IconButton.filledTonal(
            onPressed: _busy ? null : () => setState(() => _amount++),
            icon: const Icon(Icons.add),
          ),
        ],
      );

  Widget _stepTile(LifeStep s) {
    Widget leading;
    switch (s.state) {
      case StepState.pending:
        leading = const Icon(Icons.radio_button_unchecked,
            color: Colors.white24, size: 22);
      case StepState.running:
        leading = const SizedBox(
            width: 20,
            height: 20,
            child: CircularProgressIndicator(strokeWidth: 2.5));
      case StepState.done:
        leading =
            const Icon(Icons.check_circle, color: Colors.greenAccent, size: 22);
      case StepState.error:
        leading = const Icon(Icons.error, color: Colors.redAccent, size: 22);
    }
    return ListTile(
      leading: leading,
      title: Text(s.title, style: const TextStyle(fontSize: 14)),
      subtitle: s.detail == null
          ? null
          : SelectableText(s.detail!,
              style: const TextStyle(
                  fontSize: 12,
                  color: Colors.white60,
                  fontFamily: 'monospace')),
      dense: true,
    );
  }

  Widget _resultCard(ColorScheme cs) => Card(
        color: cs.primaryContainer,
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            children: [
              Text('Encrypted on-chain total',
                  style: TextStyle(color: cs.onPrimaryContainer)),
              const SizedBox(height: 6),
              Text('$_total',
                  style: TextStyle(
                      fontSize: 44,
                      fontWeight: FontWeight.bold,
                      color: cs.onPrimaryContainer)),
              Text('decrypted on this device',
                  style: TextStyle(
                      fontSize: 12,
                      color: cs.onPrimaryContainer.withValues(alpha: 0.7))),
            ],
          ),
        ),
      );

  Widget _txCard(ColorScheme cs) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('Transaction',
                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
              const SizedBox(height: 4),
              SelectableText('sepolia.etherscan.io/tx/$_txHash',
                  style: const TextStyle(
                      fontSize: 12,
                      fontFamily: 'monospace',
                      color: Colors.white70)),
            ],
          ),
        ),
      );

  Widget _errorCard(ColorScheme cs) => Card(
        color: cs.errorContainer,
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: SelectableText('error: $_error',
              style: TextStyle(color: cs.onErrorContainer, fontSize: 12)),
        ),
      );

  static String _short(String hex) {
    if (hex.length <= 14) return hex;
    return '${hex.substring(0, 8)}…${hex.substring(hex.length - 6)}';
  }
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
