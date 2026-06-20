import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../config/networks.dart';
import '../instance/key_cache.dart';
import '../utils/hex.dart';
import 'input_proof.dart';
import 'key_material.dart';
import 'public_decrypt.dart';
import 'user_decrypt.dart';

/// Thrown when a relayer request fails.
class RelayerException implements Exception {
  RelayerException(this.message, {this.statusCode, this.url, this.label});
  final String message;
  final int? statusCode;
  final String? url;

  /// The relayer's machine-readable error label, when present.
  final String? label;
  @override
  String toString() =>
      'RelayerException: $message'
      '${label != null ? ' <$label>' : ''}'
      '${statusCode != null ? ' (HTTP $statusCode)' : ''}'
      '${url != null ? ' [$url]' : ''}';
}

/// Thrown when the relayer/coprocessors explicitly reject an input proof.
class InputProofRejectedException extends RelayerException {
  InputProofRejectedException({super.url, Map<String, dynamic>? result})
      : super('relayer rejected the input proof (accepted=false)'
            '${result != null ? ' — $result' : ''}');
}

/// HTTP client for the Zama relayer (v2 API).
///
/// Currently implements the public-key/CRS discovery + download path
/// (`/keyurl`). Input-proof submission and decryption land in later phases.
class RelayerClient {
  RelayerClient(this.network, {http.Client? client})
      : _client = client ?? http.Client(),
        _ownsClient = client == null;

  final FhevmNetworkConfig network;
  final http.Client _client;
  final bool _ownsClient;

  /// `GET {relayer}/v2/keyurl` → parsed key/CRS locations.
  Future<KeyUrlResponse> getKeyUrl() async {
    final url = '${network.relayerUrlV2}/keyurl';
    final res = await _client.get(Uri.parse(url));
    if (res.statusCode != 200) {
      throw RelayerException('keyurl request failed',
          statusCode: res.statusCode, url: url);
    }
    final json = jsonDecode(res.body) as Map<String, dynamic>;
    return KeyUrlResponse.fromJson(json);
  }

  /// Fetches and downloads the FHE public key + CRS.
  ///
  /// [crsBits] selects the CRS capacity (default `"2048"`, the only one the
  /// Sepolia relayer currently serves).
  Future<KeyMaterial> fetchKeyMaterial({String crsBits = '2048'}) async {
    final keyUrl = await getKeyUrl();
    final crsEntry = keyUrl.crs[crsBits];
    if (crsEntry == null) {
      throw RelayerException(
          'no CRS for "$crsBits" bits (have: ${keyUrl.crs.keys.join(", ")})');
    }
    final publicKey = await _download(keyUrl.publicKey.urls);
    final crs = await _download(crsEntry.urls);
    return KeyMaterial(
      publicKey: publicKey,
      publicKeyId: keyUrl.publicKey.dataId,
      crs: crs,
      crsId: crsEntry.dataId,
      crsBits: crsBits,
    );
  }

  /// Like [fetchKeyMaterial] but backed by [cache]: the public key and CRS are
  /// read from disk when present and downloaded (then cached) only on a miss.
  /// Because cache entries are content-addressed by the relayer's `dataId`,
  /// this stays correct across key rotations — a rotation changes the id, which
  /// misses the cache and re-downloads.
  Future<KeyMaterial> fetchKeyMaterialCached(
    FheKeyCache cache, {
    String crsBits = '2048',
  }) async {
    final keyUrl = await getKeyUrl();
    final crsEntry = keyUrl.crs[crsBits];
    if (crsEntry == null) {
      throw RelayerException(
          'no CRS for "$crsBits" bits (have: ${keyUrl.crs.keys.join(", ")})');
    }
    final pkId = keyUrl.publicKey.dataId;
    final crsId = crsEntry.dataId;
    final publicKey = await cache.read(pkId) ??
        await _downloadAndCache(cache, pkId, keyUrl.publicKey.urls);
    final crs = await cache.read(crsId) ??
        await _downloadAndCache(cache, crsId, crsEntry.urls);
    return KeyMaterial(
      publicKey: publicKey,
      publicKeyId: pkId,
      crs: crs,
      crsId: crsId,
      crsBits: crsBits,
    );
  }

  Future<Uint8List> _downloadAndCache(
      FheKeyCache cache, String id, List<String> urls) async {
    final bytes = await _download(urls);
    await cache.write(id, bytes);
    return bytes;
  }

  /// Downloads from the first URL that succeeds, trying each in turn.
  Future<Uint8List> _download(List<String> urls) async {
    Object? lastError;
    for (final url in urls) {
      try {
        final res = await _client.get(Uri.parse(url));
        if (res.statusCode == 200) return res.bodyBytes;
        lastError = RelayerException('download failed',
            statusCode: res.statusCode, url: url);
      } catch (e) {
        lastError = e;
      }
    }
    throw RelayerException('all download URLs failed: $lastError');
  }

  /// Submits a proven ciphertext blob to `/input-proof` and waits for the
  /// coprocessor-attested result (handles + signatures).
  ///
  /// - [ciphertextWithZkProof]: the proven blob from the crypto backend.
  /// - [extraData]: protocol extra data (default `0x00`).
  Future<InputProofResponse> submitInputProof({
    required String contractAddress,
    required String userAddress,
    required Uint8List ciphertextWithZkProof,
    required int chainId,
    String extraData = '0x00',
    Duration timeout = const Duration(minutes: 5),
    Duration pollInterval = const Duration(milliseconds: 2500),
  }) async {
    final url = '${network.relayerUrlV2}/input-proof';
    final result = await _postAndPoll(
      url,
      {
        'contractAddress': contractAddress,
        'userAddress': userAddress,
        'ciphertextWithInputVerification':
            bytesToHex(ciphertextWithZkProof, prefix: false),
        'contractChainId': '0x${chainId.toRadixString(16)}',
        'extraData': extraData,
      },
      timeout: timeout,
      pollInterval: pollInterval,
    );
    if (result['accepted'] != true) {
      throw InputProofRejectedException(url: url, result: result);
    }
    return InputProofResponse(
      accepted: true,
      handles: (result['handles'] as List).cast<String>(),
      signatures: (result['signatures'] as List).cast<String>(),
      extraData: (result['extraData'] as String?) ?? '0x',
    );
  }

  /// Publicly decrypts handles that have been marked publicly decryptable
  /// on-chain (`FHE.makePubliclyDecryptable`). Returns cleartext values plus the
  /// KMS signatures to verify on-chain.
  ///
  /// [handles] are `0x`-prefixed bytes32; their order is bound into the proof.
  Future<PublicDecryptResult> publicDecrypt(
    List<String> handles, {
    String extraData = '0x00',
    Duration timeout = const Duration(minutes: 5),
    Duration pollInterval = const Duration(milliseconds: 2500),
  }) async {
    final url = '${network.relayerUrlV2}/public-decrypt';
    final result = await _postAndPoll(
      url,
      {'ciphertextHandles': handles, 'extraData': extraData},
      timeout: timeout,
      pollInterval: pollInterval,
    );
    final decryptedValue = ensure0x(result['decryptedValue'] as String);
    return PublicDecryptResult(
      values: PublicDecryptResult.decode(handles, decryptedValue),
      signatures:
          (result['signatures'] as List).cast<String>().map(ensure0x).toList(),
      decryptedValue: decryptedValue,
      extraData: (result['extraData'] as String?) ?? '0x',
    );
  }

  /// Requests private (user) decryption of handles the user is allowed to read.
  ///
  /// Returns the per-node re-encrypted items verbatim — decrypting them to
  /// cleartext requires the native KMS client (ML-KEM + threshold verify), which
  /// is a separate backend concern. [signature] is the user's EIP-712 signature
  /// over the request; [publicKey] is the ephemeral ML-KEM public key (hex).
  Future<UserDecryptResponse> userDecrypt({
    required List<HandleContractPair> handleContractPairs,
    required List<String> contractAddresses,
    required String userAddress,
    required String signature,
    required String publicKey,
    required int startTimestamp,
    required int durationDays,
    required int chainId,
    String extraData = '0x00',
    Duration timeout = const Duration(minutes: 5),
    Duration pollInterval = const Duration(milliseconds: 2500),
  }) async {
    final url = '${network.relayerUrlV2}/user-decrypt';
    final result = await _postAndPoll(
      url,
      {
        'handleContractPairs': [for (final p in handleContractPairs) p.toJson()],
        'requestValidity': {
          'startTimestamp': startTimestamp.toString(),
          'durationDays': durationDays.toString(),
        },
        'contractsChainId': chainId.toString(),
        'contractAddresses': contractAddresses,
        'userAddress': userAddress,
        'signature': strip0x(signature),
        'publicKey': strip0x(publicKey),
        'extraData': extraData,
      },
      timeout: timeout,
      pollInterval: pollInterval,
    );
    // v2 nests the items under result.result.
    final items = (result['result'] as List).cast<Map<String, dynamic>>();
    return UserDecryptResponse(
      items: [
        for (final it in items)
          UserDecryptItem(
            payload: ensure0x(it['payload'] as String),
            signature: ensure0x(it['signature'] as String),
            extraData: (it['extraData'] as String?) ?? '0x',
          ),
      ],
    );
  }

  /// The relayer v2 async state machine, shared by all POST operations:
  /// `POST → 202 {result:{jobId}}` then poll `GET {url}/{jobId}` until
  /// `200 {result:{...}}`, honoring `Retry-After` and retrying `429`/`503`.
  /// Returns the terminal `result` object.
  Future<Map<String, dynamic>> _postAndPoll(
    String url,
    Map<String, dynamic> payload, {
    required Duration timeout,
    required Duration pollInterval,
  }) async {
    final deadline = DateTime.now().add(timeout);
    final body = jsonEncode(payload);

    String? jobId;
    while (jobId == null) {
      if (DateTime.now().isAfter(deadline)) {
        throw RelayerException('POST timed out', url: url);
      }
      final res = await _client.post(
        Uri.parse(url),
        headers: const {'Content-Type': 'application/json'},
        body: body,
      );
      switch (res.statusCode) {
        case 200:
          return _resultOf(res, url); // synchronous terminal result
        case 202:
          jobId = _jobIdOf(res, url);
        case 429:
        case 503:
          await _waitRetryAfter(res, pollInterval);
        default:
          throw _apiError(res, url);
      }
    }

    while (true) {
      if (DateTime.now().isAfter(deadline)) {
        throw RelayerException('polling timed out', url: '$url/$jobId');
      }
      await _waitRetryAfter(null, pollInterval);
      final res = await _client.get(Uri.parse('$url/$jobId'));
      switch (res.statusCode) {
        case 200:
          return _resultOf(res, '$url/$jobId');
        case 202:
          continue; // still queued
        default:
          throw _apiError(res, '$url/$jobId');
      }
    }
  }

  Map<String, dynamic> _resultOf(http.Response res, String url) {
    final json = jsonDecode(res.body) as Map<String, dynamic>;
    final result = json['result'];
    if (result is! Map<String, dynamic>) {
      throw RelayerException('missing result in response',
          statusCode: res.statusCode, url: url);
    }
    return result;
  }

  String _jobIdOf(http.Response res, String url) {
    final jobId = _resultOf(res, url)['jobId'];
    if (jobId is! String) {
      throw RelayerException('missing jobId in 202 response',
          statusCode: res.statusCode, url: url);
    }
    return jobId;
  }

  /// Waits for [fallback], or the response's `Retry-After` seconds if larger.
  Future<void> _waitRetryAfter(dynamic res, Duration fallback) async {
    var delay = fallback;
    final header = (res is http.Response) ? res.headers['retry-after'] : null;
    if (header != null) {
      final secs = int.tryParse(header.trim());
      if (secs != null) {
        final ms = secs * 1000;
        if (ms > delay.inMilliseconds) delay = Duration(milliseconds: ms);
      }
    }
    if (delay.inMilliseconds < 1000) delay = const Duration(seconds: 1);
    await Future<void>.delayed(delay);
  }

  RelayerException _apiError(http.Response res, String url) {
    String? label;
    String message = 'relayer request failed';
    try {
      final json = jsonDecode(res.body) as Map<String, dynamic>;
      final error = json['error'] as Map<String, dynamic>?;
      if (error != null) {
        label = error['label'] as String?;
        message = (error['message'] as String?) ?? message;
      }
    } catch (_) {
      // Non-JSON body (e.g. a Cloudflare HTML page).
    }
    return RelayerException(message,
        statusCode: res.statusCode, url: url, label: label);
  }

  /// Closes the underlying HTTP client (only if this client created it).
  void close() {
    if (_ownsClient) _client.close();
  }
}
