// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import {FHE, euint32, externalEuint32} from "@fhevm/solidity/lib/FHE.sol";
// ZamaEthereumConfig is chain-aware: it wires the Sepolia coprocessor addresses
// when deployed on chainId 11155111 (and mainnet on chainId 1).
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

/// Minimal confidential contract used as the M1 target for the Dart SDK.
///
/// `increment` accepts an encrypted euint32 (handle + inputProof produced by the
/// Dart client), adds it to a running encrypted total, and marks the total
/// publicly decryptable so any client can `publicDecrypt` it back.
contract ConfidentialCounter is ZamaEthereumConfig {
    euint32 private _count;

    /// Adds an encrypted amount to the running total.
    function increment(externalEuint32 inputHandle, bytes calldata inputProof) external {
        euint32 amount = FHE.fromExternal(inputHandle, inputProof);
        _count = FHE.add(_count, amount);
        FHE.allowThis(_count);
        // Make the running total publicly decryptable (demo). A real app would
        // gate this with ACL grants instead.
        FHE.makePubliclyDecryptable(_count);
    }

    /// Returns the (encrypted) running total handle.
    function count() external view returns (euint32) {
        return _count;
    }
}
