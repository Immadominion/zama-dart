/// A (handle, contract) pair authorizing decryption of one ciphertext.
class HandleContractPair {
  const HandleContractPair({required this.handle, required this.contractAddress});

  /// `0x`-prefixed bytes32 ciphertext handle.
  final String handle;

  /// `0x`-prefixed contract address that owns/permits the handle.
  final String contractAddress;

  Map<String, String> toJson() => {
        'handle': handle,
        'contractAddress': contractAddress,
      };
}

/// One encrypted item from a `/user-decrypt` response — the KMS payload
/// re-encrypted under the user's ephemeral ML-KEM key, plus its signature.
///
/// Turning these into cleartext requires the native KMS client
/// (`process_user_decryption_resp`); this layer returns them verbatim.
class UserDecryptItem {
  const UserDecryptItem({
    required this.payload,
    required this.signature,
    required this.extraData,
  });

  /// Re-encrypted payload (`0x`-prefixed).
  final String payload;

  /// KMS node signature (`0x`-prefixed).
  final String signature;

  /// Echoed extra data (`0x`-prefixed).
  final String extraData;
}

/// Raw `/user-decrypt` response: the per-node re-encrypted items.
class UserDecryptResponse {
  const UserDecryptResponse({required this.items});
  final List<UserDecryptItem> items;
}
