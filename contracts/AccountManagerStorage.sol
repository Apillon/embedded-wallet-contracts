// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

import {IAccountFactory} from "./interfaces/IAccountFactory.sol";
import {IAccount} from "./interfaces/IAccount.sol";

import {
    UserCredential,
    User,
    GaslessData,
    ActionCred,
    ActionPass,
    Credential,
    NewAccount,
    WalletData
} from "./structs/Structs.sol";

import {
    TxType,
    CredentialAction
} from "./enums/Enums.sol";

contract AccountManagerStorage {

    IAccountFactory internal accountFactory;

    /**
     * @dev user account mapping
     */
    mapping(bytes32 => User) internal users;

    /**
     * @dev username to credential list mapping
     */
    mapping(bytes32 => bytes32[]) internal usernameToHashedCredentialIdList;

    /**
     * @dev hashedCredential to credential
     */
    mapping(bytes32 => UserCredential) internal credentialsByHashedCredentialId;

    /**
     * @dev sapphire encription salt
     */
    bytes32 public salt;

    /**
     * @dev sapphire encription secret
     */
    bytes32 internal encryptionSecret;

    /**
     * @dev data used for chiper encription and webauthn challanges
     */
    bytes32 public personalization;

    /**
     * @dev address performing gasless transactions - public key
     */
    address public gaspayingAddress;

    /**
     * @dev address performing gasless transactions - private key
     */
    bytes32 internal gaspayingSecret;

    /**
     * @dev address signing on backend (for gasless transactions)
     */
    address public signer;

    /**
     * @dev hash usage mapping to prevent reuse of same hash multiple times
     */
    mapping(bytes32 => bool) public hashUsage;

    event GaslessTransaction(bytes32 indexed dataHash, address indexed publicAddress);

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}