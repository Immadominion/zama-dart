import 'dart:ffi';

/// Owned byte buffer returned by the native library (`ByteBuf` in Rust).
final class NativeByteBuf extends Struct {
  external Pointer<Uint8> ptr;
  @Size()
  external int len;
  @Size()
  external int cap;
}

// ---- C function signatures (native) ----

typedef CtxNewGeneratedC = Pointer<Void> Function(Size maxBits);
typedef CtxNewC = Pointer<Void> Function(
    Pointer<Uint8> pk, Size pkLen, Pointer<Uint8> crs, Size crsLen);
typedef CtxFreeC = Void Function(Pointer<Void> ctx);
typedef BytesFreeC = Void Function(NativeByteBuf buf);
typedef EncryptC = Int32 Function(
  Pointer<Void> ctx,
  Pointer<Uint8> valuesBe32,
  Pointer<Uint8> typeIds,
  Size n,
  Pointer<Uint8> metadata,
  Size metadataLen,
  Pointer<NativeByteBuf> out,
);
typedef VerifyDecryptC = Int32 Function(
  Pointer<Void> ctx,
  Pointer<Uint8> blob,
  Size blobLen,
  Pointer<Uint8> typeIds,
  Size n,
  Pointer<Uint8> metadata,
  Size metadataLen,
  Pointer<Uint8> outVals,
  Size outCap,
);

// ---- Dart function signatures ----

typedef CtxNewGeneratedDart = Pointer<Void> Function(int maxBits);
typedef CtxNewDart = Pointer<Void> Function(
    Pointer<Uint8> pk, int pkLen, Pointer<Uint8> crs, int crsLen);
typedef CtxFreeDart = void Function(Pointer<Void> ctx);
typedef BytesFreeDart = void Function(NativeByteBuf buf);
typedef EncryptDart = int Function(
  Pointer<Void> ctx,
  Pointer<Uint8> valuesBe32,
  Pointer<Uint8> typeIds,
  int n,
  Pointer<Uint8> metadata,
  int metadataLen,
  Pointer<NativeByteBuf> out,
);
typedef VerifyDecryptDart = int Function(
  Pointer<Void> ctx,
  Pointer<Uint8> blob,
  int blobLen,
  Pointer<Uint8> typeIds,
  int n,
  Pointer<Uint8> metadata,
  int metadataLen,
  Pointer<Uint8> outVals,
  int outCap,
);

/// Resolved bindings to `zama_fhe_native`.
class ZamaNativeBindings {
  ZamaNativeBindings(DynamicLibrary lib)
      : ctxNewGenerated = lib
            .lookupFunction<CtxNewGeneratedC, CtxNewGeneratedDart>(
                'zama_ctx_new_generated'),
        ctxNew = lib.lookupFunction<CtxNewC, CtxNewDart>('zama_ctx_new'),
        ctxFree = lib.lookupFunction<CtxFreeC, CtxFreeDart>('zama_ctx_free'),
        bytesFree =
            lib.lookupFunction<BytesFreeC, BytesFreeDart>('zama_bytes_free'),
        encrypt = lib.lookupFunction<EncryptC, EncryptDart>('zama_encrypt'),
        verifyDecrypt = lib.lookupFunction<VerifyDecryptC, VerifyDecryptDart>(
            'zama_test_verify_decrypt');

  final CtxNewGeneratedDart ctxNewGenerated;
  final CtxNewDart ctxNew;
  final CtxFreeDart ctxFree;
  final BytesFreeDart bytesFree;
  final EncryptDart encrypt;
  final VerifyDecryptDart verifyDecrypt;
}
