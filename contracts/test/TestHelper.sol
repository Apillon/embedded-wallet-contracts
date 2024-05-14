// SPDX-License-Identifier: Unlicensed

pragma solidity ^0.8.0;

import {Base64URL} from ".././lib/Base64URL.sol";
import {MakeJSON} from ".././lib/MakeJSON.sol";

// struct AuthenticatorResponse {
//     bytes authenticatorData;
//     MakeJSON.KeyValue[] clientDataTokens;
//     uint256 sigR;
//     uint256 sigS;
// }

contract TestHelper {
    
    function createChallengeBase64(
        bytes calldata in_data,
        bytes32 personalization
    ) external pure returns (string memory) {
        bytes32 challenge = sha256(abi.encodePacked(personalization, sha256(in_data)));

        string memory challengeBase64 = Base64URL.encode(abi.encodePacked(challenge), false);

        return challengeBase64;
    }

    function createDigest(
        bytes calldata authenticatorData,
        MakeJSON.KeyValue[] calldata clientDataTokens
    ) external pure returns (bytes32) {
        string memory clientDataJSON = MakeJSON.from(clientDataTokens);
        bytes32 digest = sha256(abi.encodePacked(authenticatorData, sha256(abi.encodePacked(clientDataJSON))));

        return digest;
    }
}