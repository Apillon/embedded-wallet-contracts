// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

library EmailRecovery {
    struct EmailRecoveryRequest {
        bytes32 hashedUsername;
        bytes32 emailHash;
        uint256 timestamp;
        bytes signature;
    }

    /**
     * @dev Verifies an email recovery request
     * @param request The email recovery request data
     * @param signer The expected signer address
     * @return bool indicating success or failure
     */
    function verifyRecoveryRequest(
        EmailRecoveryRequest memory request,
        address signer
    ) internal pure returns (bool) {
        bytes32 message = keccak256(
            abi.encodePacked(
                "recover-account-email",
                request.hashedUsername,
                request.emailHash,
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
