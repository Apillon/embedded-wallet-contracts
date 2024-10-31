// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

library SocialRecovery {
    struct SocialRecoveryRequest {
        bytes32 hashedUsername;
        bytes32 platformHash;
        bytes32 socialIdHash;
        uint256 timestamp;
        bytes signature;
    }

    /**
     * @dev Verifies a social recovery request
     * @param request The social recovery request data
     * @param signer The expected signer address
     * @return bool indicating success or failure
     */
    function verifyRecoveryRequest(
        SocialRecoveryRequest memory request,
        address signer
    ) internal pure returns (bool) {
        bytes32 message = keccak256(
            abi.encodePacked(
                "recover-account",
                request.hashedUsername,
                request.platformHash,
                request.socialIdHash,
                request.timestamp
            )
        );
        bytes32 ethSignedMessage = ECDSA.toEthSignedMessageHash(message);
        address recoveredAddress = ECDSA.recover(
            ethSignedMessage,
            request.signature
        );
        return recoveredAddress == signer;
    }
}
