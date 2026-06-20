/// Network configuration for a Zama Protocol deployment.
///
/// Field values mirror `@zama-fhe/relayer-sdk` `src/configs.ts`. Contract
/// addresses change across protocol releases — treat the relayer-sdk version
/// you target as canonical and re-verify before mainnet use.
class FhevmNetworkConfig {
  const FhevmNetworkConfig({
    required this.name,
    required this.chainId,
    required this.gatewayChainId,
    required this.relayerUrl,
    required this.aclContractAddress,
    required this.kmsContractAddress,
    required this.inputVerifierContractAddress,
    required this.verifyingContractAddressDecryption,
    required this.verifyingContractAddressInputVerification,
  });

  /// Human-readable label, e.g. `sepolia`.
  final String name;

  /// Host chain id (e.g. 11155111 for Sepolia, 1 for mainnet).
  final int chainId;

  /// Gateway (Arbitrum rollup) chain id. Used as the EIP-712 domain `chainId`
  /// for KMS decryption requests.
  final int gatewayChainId;

  /// Base URL of the relayer HTTP service.
  final String relayerUrl;

  /// ACL contract (host chain) — per-handle access control.
  final String aclContractAddress;

  /// KMSVerifier contract (host chain).
  final String kmsContractAddress;

  /// InputVerifier contract (host chain).
  final String inputVerifierContractAddress;

  /// Verifying contract for decryption EIP-712 (on the Gateway).
  final String verifyingContractAddressDecryption;

  /// Verifying contract for input-verification EIP-712 (on the Gateway).
  final String verifyingContractAddressInputVerification;

  /// Same config pointed at the relayer `/v2` API.
  String get relayerUrlV2 => '$relayerUrl/v2';

  /// Same config pointed at the relayer `/v1` API.
  String get relayerUrlV1 => '$relayerUrl/v1';

  /// Sepolia testnet (live since 2025-07-01).
  static const sepolia = FhevmNetworkConfig(
    name: 'sepolia',
    chainId: 11155111,
    gatewayChainId: 10901,
    relayerUrl: 'https://relayer.testnet.zama.org',
    aclContractAddress: '0xf0Ffdc93b7E186bC2f8CB3dAA75D86d1930A433D',
    kmsContractAddress: '0xbE0E383937d564D7FF0BC3b46c51f0bF8d5C311A',
    inputVerifierContractAddress: '0xBBC1fFCdc7C316aAAd72E807D9b0272BE8F84DA0',
    verifyingContractAddressDecryption:
        '0x5D8BD78e2ea6bbE41f26dFe9fdaEAa349e077478',
    verifyingContractAddressInputVerification:
        '0x483b9dE06E4E4C7D35CCf5837A1668487406D955',
  );

  /// Ethereum mainnet (live since 2025-12-30).
  static const mainnet = FhevmNetworkConfig(
    name: 'mainnet',
    chainId: 1,
    gatewayChainId: 261131,
    relayerUrl: 'https://relayer.mainnet.zama.org',
    aclContractAddress: '0xcA2E8f1F656CD25C01F05d0b243Ab1ecd4a8ffb6',
    kmsContractAddress: '0x77627828a55156b04Ac0DC0eb30467f1a552BB03',
    inputVerifierContractAddress: '0xCe0FC2e05CFff1B719EFF7169f7D80Af770c8EA2',
    verifyingContractAddressDecryption:
        '0x0f6024a97684f7d90ddb0fAAD79cB15F2C888D24',
    verifyingContractAddressInputVerification:
        '0xcB1bB072f38bdAF0F328CdEf1Fc6eDa1DF029287',
  );
}
