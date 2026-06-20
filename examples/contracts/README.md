# M1 example contract — ConfidentialCounter

A minimal FHEVM contract the Dart SDK targets for **Milestone M1** (first on-chain
confidential transaction): `increment(externalEuint32, bytes inputProof)` adds an
encrypted amount to a running total and marks it publicly decryptable so the Dart
client can read it back via `publicDecrypt`.

## Deploy to Sepolia

Use Zama's Hardhat template (it wires the FHEVM config + Sepolia addresses):

```bash
# 1. Scaffold from the official template
npx degit zama-ai/fhevm-hardhat-template confidential-counter
cd confidential-counter && npm install

# 2. Drop in ConfidentialCounter.sol (this folder) under contracts/
cp ../ConfidentialCounter.sol contracts/

# 3. Configure a funded Sepolia deployer key + RPC (template uses .env / hardhat vars)
npx hardhat vars set PRIVATE_KEY        # your funded Sepolia test key
npx hardhat vars set INFURA_API_KEY     # or set a SEPOLIA_RPC_URL

# 4. Compile + deploy
npx hardhat compile
npx hardhat run scripts/deploy.ts --network sepolia
```

Get Sepolia test ETH from a faucet (e.g. sepoliafaucet.com / Alchemy / QuickNode).

## Wire it into the Dart M1 test

Once deployed, run the gated Dart integration test with:

```bash
cd ../../packages/zama_fhe_ffi
ZAMA_NETWORK_TESTS=1 \
ZAMA_NATIVE_LIB=rust/target/release/libzama_fhe_native.dylib \
SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/<key> \
SEPOLIA_PRIVATE_KEY=0x<funded test key> \
CONFIDENTIAL_COUNTER=0x<deployed address> \
  dart test test/m1_onchain_test.dart -t network
```

The test: native-encrypt an amount → `/input-proof` (relayer accepts) → assemble
`inputProof` → `increment(...)` tx → read `count()` handle → `publicDecrypt` it →
assert the total increased by the amount.

> Security: pass the key via env var only; never commit it.
