import 'dart:io';
import 'dart:typed_data';

/// A disk cache for the FHE public key + CRS, **content-addressed** by the
/// relayer's `dataId`.
///
/// The relayer rotates the `dataId` whenever the underlying key/CRS changes, so
/// a cached entry can never become stale — there is no TTL to tune. This avoids
/// re-downloading the ~4.4 MB CRS (and the public key) on every app launch.
///
/// Pure Dart, no Flutter dependency: pass any writable [directory]. In a Flutter
/// app, use `path_provider`'s application-support or cache directory.
class FheKeyCache {
  FheKeyCache(this.directory);

  final Directory directory;

  File _fileFor(String dataId) {
    final safe = dataId.replaceAll(RegExp(r'[^A-Za-z0-9_.-]'), '_');
    return File('${directory.path}/zama-fhe-key-$safe.bin');
  }

  /// Returns the cached bytes for [dataId], or null if not cached.
  Future<Uint8List?> read(String dataId) async {
    final f = _fileFor(dataId);
    if (!await f.exists()) return null;
    return f.readAsBytes();
  }

  /// Stores [bytes] under [dataId], writing atomically (temp file + rename) so a
  /// crash mid-write never leaves a truncated entry.
  Future<void> write(String dataId, Uint8List bytes) async {
    await directory.create(recursive: true);
    final f = _fileFor(dataId);
    final tmp = File('${f.path}.tmp');
    await tmp.writeAsBytes(bytes, flush: true);
    await tmp.rename(f.path);
  }

  /// Removes every cached key/CRS file in [directory].
  Future<void> clear() async {
    if (!await directory.exists()) return;
    await for (final e in directory.list()) {
      if (e is File && e.path.contains('zama-fhe-key-')) {
        await e.delete();
      }
    }
  }
}
