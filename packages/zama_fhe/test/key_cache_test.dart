import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:zama_fhe/zama_fhe.dart';
import 'package:test/test.dart';

const _net = FhevmNetworkConfig.sepolia;
const _pkUrl = 'https://dl.test/public-key';
const _crsUrl = 'https://dl.test/crs-2048';

String _keyUrlJson({required String pkId, required String crsId}) => jsonEncode({
      'response': {
        'fheKeyInfo': [
          {
            'fhePublicKey': {'dataId': pkId, 'urls': [_pkUrl]}
          }
        ],
        'crs': {
          '2048': {'dataId': crsId, 'urls': [_crsUrl]}
        },
      }
    });

void main() {
  late Directory tmp;
  setUp(() => tmp = Directory.systemTemp.createTempSync('zama_cache_test'));
  tearDown(() => tmp.existsSync() ? tmp.deleteSync(recursive: true) : null);

  group('FheKeyCache', () {
    test('write then read round-trips bytes; miss returns null', () async {
      final cache = FheKeyCache(tmp);
      expect(await cache.read('absent'), isNull);
      final data = Uint8List.fromList([1, 2, 3, 4, 5]);
      await cache.write('id-1', data);
      expect(await cache.read('id-1'), data);
    });

    test('clear removes cached entries', () async {
      final cache = FheKeyCache(tmp);
      await cache.write('id-1', Uint8List.fromList([9]));
      await cache.clear();
      expect(await cache.read('id-1'), isNull);
    });

    test('sanitizes ids with path-unsafe characters', () async {
      final cache = FheKeyCache(tmp);
      await cache.write('../weird/id:1', Uint8List.fromList([7]));
      expect(await cache.read('../weird/id:1'), Uint8List.fromList([7]));
      // Nothing escaped the cache directory.
      expect(tmp.listSync().whereType<File>().length, 1);
    });
  });

  group('fetchKeyMaterialCached', () {
    test('downloads on a miss, serves from cache on the next call', () async {
      var pkDownloads = 0, crsDownloads = 0, keyUrlHits = 0;
      final pkBytes = Uint8List.fromList(List.filled(32, 0xab));
      final crsBytes = Uint8List.fromList(List.filled(128, 0xcd));

      final mock = MockClient((req) async {
        final u = req.url.toString();
        if (u.endsWith('/keyurl')) {
          keyUrlHits++;
          return http.Response(_keyUrlJson(pkId: 'pk-v1', crsId: 'crs-v1'), 200);
        }
        if (u == _pkUrl) {
          pkDownloads++;
          return http.Response.bytes(pkBytes, 200);
        }
        if (u == _crsUrl) {
          crsDownloads++;
          return http.Response.bytes(crsBytes, 200);
        }
        return http.Response('not found: $u', 404);
      });

      final cache = FheKeyCache(tmp);
      final c = RelayerClient(_net, client: mock);

      final first = await c.fetchKeyMaterialCached(cache);
      expect(first.publicKey, pkBytes);
      expect(first.crs, crsBytes);
      expect(pkDownloads, 1);
      expect(crsDownloads, 1);

      // Second fetch: keyurl is still consulted (to learn the current ids), but
      // the big blobs come from the cache — no re-download.
      final second = await c.fetchKeyMaterialCached(cache);
      expect(second.publicKey, pkBytes);
      expect(second.crs, crsBytes);
      expect(pkDownloads, 1, reason: 'public key must be served from cache');
      expect(crsDownloads, 1, reason: 'CRS must be served from cache');
      expect(keyUrlHits, 2);
    });

    test('a rotated dataId misses the cache and re-downloads', () async {
      var pkDownloads = 0;
      String pkId = 'pk-v1';
      final mock = MockClient((req) async {
        final u = req.url.toString();
        if (u.endsWith('/keyurl')) {
          return http.Response(_keyUrlJson(pkId: pkId, crsId: 'crs-v1'), 200);
        }
        if (u == _pkUrl) {
          pkDownloads++;
          return http.Response.bytes(Uint8List.fromList([pkDownloads]), 200);
        }
        if (u == _crsUrl) {
          return http.Response.bytes(Uint8List.fromList([0]), 200);
        }
        return http.Response('nf', 404);
      });
      final cache = FheKeyCache(tmp);
      final c = RelayerClient(_net, client: mock);

      await c.fetchKeyMaterialCached(cache);
      expect(pkDownloads, 1);
      // Key rotation → new dataId → cache miss → re-download.
      pkId = 'pk-v2';
      final after = await c.fetchKeyMaterialCached(cache);
      expect(pkDownloads, 2);
      expect(after.publicKeyId, 'pk-v2');
    });
  });
}
