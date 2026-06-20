import 'package:http/http.dart' as http;

import '../config/networks.dart';
import '../eip712/kms_eip712.dart';
import '../kms/kms_response_verifier.dart';
import '../relayer/public_decrypt.dart';
import '../relayer/relayer_client.dart';
import '../relayer/user_decrypt.dart';
import '../utils/hex.dart';
import 'encrypted_input.dart';
import 'fhevm_backend.dart';
import 'key_cache.dart';
import 'kms_backend.dart';

/// The top-level entry point for confidential interactions with the Zama
/// Protocol from Dart/Flutter.
///
/// It wires together the three concerns a confidential dApp needs:
///   * a crypto [FhevmBackend] (native FFI on mobile/desktop, JS on web),
///   * the relayer HTTP client (key material, input proofs, decryption),
///   * shared pure-Dart glue (handle computation, the 92-byte aux metadata).
///
/// Construct one with a backend and a network, then create encrypted inputs:
///
/// ```dart
/// final instance = FhevmInstance(
///   network: FhevmNetworkConfig.sepolia,
///   backend: NativeFhevmBackend(ZamaNative.openDefault()),
/// );
/// final enc = await instance
///     .createEncryptedInput(contractAddress: c, userAddress: me)
///     .add64(42)
///     .encrypt();
/// ```
///
/// Key material (the public key + ~4 MB CRS) is fetched lazily on the first
/// encryption and cached on the backend for the instance's lifetime.
class FhevmInstance {
  FhevmInstance({
    required this.network,
    required this.backend,
    RelayerClient? relayer,
    http.Client? httpClient,
    this.keyCache,
    this.crsBits = '2048',
  }) : relayer = relayer ?? RelayerClient(network, client: httpClient);

  /// The host/gateway network configuration.
  final FhevmNetworkConfig network;

  /// The crypto backend (encryption + handle computation).
  final FhevmBackend backend;

  /// The relayer HTTP client (key material, input proofs, decryption).
  final RelayerClient relayer;

  /// Optional disk cache for the public key + CRS. When set, key material is
  /// downloaded at most once per key rotation (saves the ~4.4 MB CRS download
  /// on every launch). In Flutter, point it at a `path_provider` directory.
  final FheKeyCache? keyCache;

  /// CRS bit capacity to fetch (default `"2048"`, the only one Sepolia serves).
  final String crsBits;

  /// Starts a fluent [EncryptedInputBuilder] for a single contract call.
  ///
  /// [contractAddress] is the target contract; [userAddress] is the caller —
  /// both are bound into the proof and must be checksummed 20-byte addresses.
  EncryptedInputBuilder createEncryptedInput({
    required String contractAddress,
    required String userAddress,
  }) {
    return EncryptedInputBuilder(
      instance: this,
      contractAddress: contractAddress,
      userAddress: userAddress,
    );
  }

  /// Publicly decrypts handles that have been marked publicly decryptable
  /// on-chain (`FHE.makePubliclyDecryptable`). Decodes the cleartext per type.
  Future<PublicDecryptResult> publicDecrypt(List<String> handles) =>
      relayer.publicDecrypt(handles);

  /// Privately decrypts handles the user is allowed to read, end to end.
  ///
  /// Generates an ephemeral keypair, has the user authorize the request via
  /// [signer] (EIP-712 over the host chain), calls the relayer, **verifies the
  /// KMS threshold signatures** ([kmsSigners] / [threshold] come from the
  /// on-chain `KMSVerifier`), then hybrid-decrypts the shares with [kms].
  ///
  /// Throws if fewer than [threshold] response signatures recover to a known KMS
  /// signer — so a returned value is always threshold-verified.
  ///
  /// [pairs] binds each handle to the contract that authorized it; the same
  /// contracts must appear in [contractAddresses] for the EIP-712 request.
  Future<List<DecryptedValue>> userDecrypt({
    required List<HandleContractPair> pairs,
    required List<String> contractAddresses,
    required String userAddress,
    required Eip712Signer signer,
    required KmsBackend kms,
    required List<String> kmsSigners,
    required int threshold,
    int durationDays = 7,
    int? startTimestamp,
  }) async {
    if (pairs.isEmpty) {
      throw ArgumentError.value(pairs, 'pairs', 'no handles to decrypt');
    }
    final kp = kms.generateKeypair();
    final pkHex = bytesToHex(kp.publicKey); // 0x-prefixed
    final start =
        startTimestamp ?? DateTime.now().millisecondsSinceEpoch ~/ 1000;

    final digest = KmsEip712.fromNetwork(network)
        .createUserDecrypt(
          publicKey: pkHex,
          contractAddresses: contractAddresses,
          startTimestamp: start,
          durationDays: durationDays,
        )
        .digest();
    final sig = await signer(digest);
    if (sig.length != 65) {
      throw ArgumentError.value(
          sig.length, 'signer', 'must return a 65-byte signature');
    }
    final sigHex = bytesToHex(sig);

    final resp = await relayer.userDecrypt(
      handleContractPairs: pairs,
      contractAddresses: contractAddresses,
      userAddress: userAddress,
      signature: sigHex,
      publicKey: pkHex,
      startTimestamp: start,
      durationDays: durationDays,
      chainId: network.chainId,
    );

    final ctHandles = [for (final p in pairs) p.handle];
    final valid = KmsResponseVerifier.countValidSigners(
      publicKey: pkHex,
      ctHandles: ctHandles,
      gatewayChainId: network.gatewayChainId,
      verifyingContract: network.verifyingContractAddressDecryption,
      responses: resp.items,
      kmsSigners: kmsSigners,
    );
    if (valid < threshold) {
      throw StateError(
          'KMS threshold not met: $valid/$threshold valid signatures');
    }

    return kms.decrypt(
      userAddress: userAddress,
      verifyingContract: network.verifyingContractAddressDecryption,
      gatewayChainId: network.gatewayChainId,
      signature: sigHex,
      keypair: kp,
      handles: ctHandles,
      responses: resp.items,
    );
  }

  /// Ensures the backend has key material, fetching + caching it on first use.
  /// Called automatically by [EncryptedInputBuilder.encrypt]; exposed so callers
  /// can pre-warm the (~4 MB CRS) download, e.g. at app start.
  Future<void> ensureReady() async {
    if (backend.isReady) return;
    final cache = keyCache;
    final km = cache != null
        ? await relayer.fetchKeyMaterialCached(cache, crsBits: crsBits)
        : await relayer.fetchKeyMaterial(crsBits: crsBits);
    backend.useKeyMaterial(publicKey: km.publicKey, crs: km.crs);
  }

  /// Releases the backend's native resources and closes the relayer client.
  void dispose() {
    backend.dispose();
    relayer.close();
  }
}
