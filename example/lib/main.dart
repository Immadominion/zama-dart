import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:zama_fhe/zama_fhe.dart';
import 'package:zama_fhe_ffi/zama_fhe_ffi.dart';

void main() => runApp(const ZamaExampleApp());

class ZamaExampleApp extends StatelessWidget {
  const ZamaExampleApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'Zama FHE (Dart)',
        theme: ThemeData(colorSchemeSeed: Colors.amber, useMaterial3: true),
        home: const HomePage(),
      );
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  String _status = 'Tap to encrypt an euint64 on-device.';
  bool _busy = false;

  Future<void> _run() async {
    setState(() {
      _busy = true;
      _status = 'Generating keys + encrypting...';
    });
    try {
      // Native TFHE encryption + ZK proof via dart:ffi -> libzama_fhe_native.so
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
      setState(() => _status = 'encrypted 42 -> handle\n'
          '${res.handles.single.toBytes32Hex()}\n\n'
          'inputProof: ${res.inputProof.length} bytes\n'
          'verify+decrypt -> ${decoded.single}');
    } catch (e) {
      setState(() => _status = 'error: $e');
    } finally {
      setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text('Zama FHE - Dart SDK')),
        body: Padding(
          padding: const EdgeInsets.all(24),
          child: Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                SelectableText(_status, textAlign: TextAlign.center),
                const SizedBox(height: 24),
                FilledButton(
                  onPressed: _busy ? null : _run,
                  child: Text(_busy ? 'Working...' : 'Encrypt on-device'),
                ),
              ],
            ),
          ),
        ),
      );
}
