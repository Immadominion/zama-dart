@Tags(['network'])
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:zama_fhe/zama_fhe.dart';
import 'package:zama_fhe_ffi/zama_fhe_ffi.dart';
import 'package:test/test.dart';

/// Full client path against LIVE Sepolia: fetch the real FHE public key + CRS,
/// encrypt natively, then submit the proof to the relayer and assemble the
/// on-chain `inputProof` from the coprocessor signatures.
///
/// Opt-in (needs network + the built dylib):
///   ZAMA_NETWORK_TESTS=1 ZAMA_NATIVE_LIB=/abs/lib dart test -t network
final _enabled = Platform.environment['ZAMA_NETWORK_TESTS'] == '1';

const net = FhevmNetworkConfig.sepolia;
// Arbitrary well-formed addresses; must match the encryption metadata + POST.
const contractAddress = '0x9aF5773d8dC3d9A57c92e08EF024804eC39FD3b3';
const userAddress = '0x37AC010c1c566696326813b840319B58Bb5840E4';

void main() {
  group('live Sepolia: relayer + native FFI', _tests,
      skip: _enabled ? false : 'set ZAMA_NETWORK_TESTS=1 to run live tests');
}

void _tests() {
  late ZamaNative native;
  late ZamaContext ctx;

  setUpAll(() async {
    final relayer = RelayerClient(net);
    final km = await relayer.fetchKeyMaterial();
    relayer.close();
    expect(km.publicKey.length, greaterThan(1000));
    expect(km.crs.length, greaterThan(1000000));
    native = ZamaNative.openDefault();
    ctx = native.contextFromArtifacts(km.publicKey, km.crs);
  });

  tearDownAll(() => ctx.dispose());

  test('encrypt euint32 against the real key produces a correct handle', () {
    final res = _encrypt(ctx, 42);
    final h = res.handles.single;
    expect(h.fheType, FheType.euint32);
    expect(h.chainId, BigInt.from(net.chainId));
    expect(h.index, 0);
    expect(res.inputProof.length, greaterThan(1000));
  });

  test('relayer ACCEPTS the proof and returns matching handles + signatures',
      () async {
    final res = _encrypt(ctx, 1234);

    final relayer = RelayerClient(net);
    final InputProofResponse ip;
    try {
      ip = await relayer.submitInputProof(
        contractAddress: contractAddress,
        userAddress: userAddress,
        ciphertextWithZkProof: res.inputProof, // the proven blob
        chainId: net.chainId,
      );
    } finally {
      relayer.close();
    }

    // Accepted by the real coprocessors.
    expect(ip.accepted, isTrue);
    expect(ip.signatures, isNotEmpty);

    // We don't trust the relayer: its handles must equal ours.
    final ours = res.handles.map((h) => h.toBytes32Hex()).toList();
    final theirs = ip.handles.map((h) => h.toLowerCase()).toList();
    expect(theirs, ours);

    // Assemble + round-trip the on-chain inputProof.
    final proofBytes = ip.toInputProofBytes();
    final parsed = InputProof.parse(proofBytes);
    expect(parsed.handles.length, 1);
    expect(parsed.signatures.length, ip.signatures.length);

    // ignore: avoid_print
    print('RELAYER ACCEPTED ✓  handle=${ours.single}  '
        'sigs=${ip.signatures.length}  inputProof=${proofBytes.length}B');
  }, timeout: const Timeout(Duration(minutes: 5)));
}

EncryptResult _encrypt(ZamaContext ctx, int value) => ctx.encrypt(
      inputs: [ClearInput.ofInt(value, FheType.euint32)],
      metadata: _metadata(),
      aclContractAddress: net.aclContractAddress,
      chainId: BigInt.from(net.chainId),
    );

/// 92-byte ZK aux data: contract(20)|user(20)|acl(20)|chainId(32 BE).
Uint8List _metadata() {
  final b = BytesBuilder();
  b.add(hexToBytes(contractAddress));
  b.add(hexToBytes(userAddress));
  b.add(hexToBytes(net.aclContractAddress));
  final cid = Uint8List(32);
  var v = net.chainId;
  for (var i = 31; i >= 0 && v > 0; i--) {
    cid[i] = v & 0xff;
    v >>= 8;
  }
  b.add(cid);
  return b.toBytes();
}
