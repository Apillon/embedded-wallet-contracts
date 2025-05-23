// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

interface IAccount {
    function createWallet (
        bytes32 keypairSecret
    ) external returns (bytes32);

    function removeWallet (
        uint256 walletId
    ) external;

    function modifyController(
        address who,
        bool status,
        uint256 deadline
    ) external;
}