import 'dart:typed_data';

import 'package:zama_fhe/zama_fhe.dart';
import 'package:zama_fhe_ffi/zama_fhe_ffi.dart';
import 'package:test/test.dart';

/// End-to-end test of the native FFI boundary: encrypt typed values in Rust via
/// dart:ffi, compute handles in pure Dart, then verify+decrypt the proof back
/// through Rust to confirm the round-trip. Requires the native dylib to be
/// built (set ZAMA_NATIVE_LIB or build the rust crate).
void main() {
  late ZamaNative native;
  late ZamaContext ctx;

  // 92-byte protocol-style metadata (contract|user|acl|chainId).
  final metadata = Uint8List.fromList(List<int>.generate(92, (i) => i & 0xff));
  const acl = '0xf0Ffdc93b7E186bC2f8CB3dAA75D86d1930A433D';
  final chainId = BigInt.from(11155111);

  setUpAll(() {
    native = ZamaNative.openDefault();
    // CRS sized for our largest case (64+32+2 < 256 bits).
    ctx = native.generatedContext(maxBits: 256);
  });

  tearDownAll(() => ctx.dispose());

  test('encrypt -> handles structure is correct', () {
    final res = ctx.encrypt(
      inputs: [
        ClearInput.ofInt(42, FheType.euint64),
        ClearInput.ofInt(7, FheType.euint32),
        ClearInput.ofBool(true),
      ],
      metadata: metadata,
      aclContractAddress: acl,
      chainId: chainId,
    );

    expect(res.inputProof.length, greaterThan(1000)); // a real proof blob
    expect(res.handles.length, 3);

    expect(res.handles[0].fheType, FheType.euint64);
    expect(res.handles[1].fheType, FheType.euint32);
    expect(res.handles[2].fheType, FheType.ebool);

    for (var i = 0; i < 3; i++) {
      expect(res.handles[i].index, i);
      expect(res.handles[i].computed, false);
      expect(res.handles[i].chainId, chainId);
      expect(res.handles[i].version, 0);
      expect(res.handles[i].toBytes32().length, 32);
    }
  });

  test('encrypt -> verify_and_expand -> decrypt round-trips the values', () {
    final inputs = [
      ClearInput.ofInt(42, FheType.euint64),
      ClearInput.ofInt(7, FheType.euint32),
      ClearInput.ofBool(true),
    ];
    final res = ctx.encrypt(
      inputs: inputs,
      metadata: metadata,
      aclContractAddress: acl,
      chainId: chainId,
    );

    final decrypted = ctx.testVerifyDecrypt(
      blob: res.inputProof,
      types: [for (final i in inputs) i.type],
      metadata: metadata,
    );

    expect(decrypted, [BigInt.from(42), BigInt.from(7), BigInt.one]);
  });

  test('single euint64 encrypts and round-trips', () {
    final res = ctx.encrypt(
      inputs: [ClearInput.ofInt(123456789, FheType.euint64)],
      metadata: metadata,
      aclContractAddress: acl,
      chainId: chainId,
    );
    final clear = ctx.testVerifyDecrypt(
      blob: res.inputProof,
      types: [FheType.euint64],
      metadata: metadata,
    );
    expect(clear.single, BigInt.from(123456789));
  });

  test('euint256 round-trips a value wider than u128', () {
    // A 200-bit value: high bits set so a u128-only path would truncate it.
    final big = (BigInt.one << 200) | (BigInt.from(0xdeadbeef) << 130) |
        BigInt.from(0x1234);
    final inputs = [ClearInput.ofUint256(big)];
    final res = ctx.encrypt(
      inputs: inputs,
      metadata: metadata,
      aclContractAddress: acl,
      chainId: chainId,
    );
    expect(res.handles.single.fheType, FheType.euint256);
    final clear = ctx.testVerifyDecrypt(
      blob: res.inputProof,
      types: [FheType.euint256],
      metadata: metadata,
    );
    expect(clear.single, big);
  });

  test('eaddress round-trips a 20-byte address', () {
    const addr = '0x8ba1f109551bD432803012645Ac136ddd64DBA72';
    final inputs = [ClearInput.ofAddress(addr)];
    final res = ctx.encrypt(
      inputs: inputs,
      metadata: metadata,
      aclContractAddress: acl,
      chainId: chainId,
    );
    expect(res.handles.single.fheType, FheType.eaddress);
    final clear = ctx.testVerifyDecrypt(
      blob: res.inputProof,
      types: [FheType.eaddress],
      metadata: metadata,
    );
    // The cleartext is the address as a 160-bit integer.
    expect(clear.single, BigInt.parse(addr.substring(2), radix: 16));
  });
}
