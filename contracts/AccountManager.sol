// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {Sapphire} from "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol";
import {EthereumUtils} from "@oasisprotocol/sapphire-contracts/contracts/EthereumUtils.sol";
import {EIP155Signer} from "@oasisprotocol/sapphire-contracts/contracts/EIP155Signer.sol";

import {WalletType} from "./AccountFactory.sol";
import {WebAuthN,CosePublicKey,AuthenticatorResponse} from "./lib/WebAuthN.sol";
import {IAccountFactory} from "./interfaces/IAccountFactory.sol";
import {IAccount} from "./interfaces/IAccount.sol";
import {AccountManagerStorage} from "./AccountManagerStorage.sol";

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

/// @custom:oz-upgrades-unsafe-allow external-library-linking
contract AccountManager is AccountManagerStorage,
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable
{
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor()  {
        _disableInitializers();
    }

    /**
     * @dev Initialize contract
     *
     * @param _accountFactory account factory address
     * @param _signer backend signer address
     */
    function initialize(
        address _accountFactory,
        address _signer
    ) public payable initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();

        require(_signer != address(0), "Zero address not allowed");
        signer = _signer;

        salt = bytes32(Sapphire.randomBytes(32, abi.encodePacked(address(this))));

        encryptionSecret = bytes32(Sapphire.randomBytes(32, abi.encodePacked(address(this))));

        (gaspayingAddress, gaspayingSecret) = EthereumUtils.generateKeypair();

        require(_accountFactory != address(0), "Zero address not allowed");
        accountFactory = IAccountFactory(_accountFactory);

        personalization = sha256(abi.encodePacked(block.chainid, address(this), salt));

        // Grant the deployer the default admin role: they can grant and revoke any roles
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);

        if(msg.value > 0) {
            payable(gaspayingAddress).transfer(msg.value);
        }
    }

    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /**
     * @dev Get account data for username
     *
     * @param in_username hashed username
     */
    function getAccount (bytes32 in_username, WalletType walletType)
        external view
        returns (address)
    {
        return address(users[in_username].accounts[uint256(walletType)]);
    }

    /**
     * @dev Check if username exists
     *
     * @param in_username hashed username
     */
    function userExists (bytes32 in_username)
        public view
        returns (bool)
    {
        return users[in_username].username != bytes32(0x0);
    }

    /**
     * @dev Create new account
     *
     * @param args new account data
     */
    function createAccount (NewAccount memory args)
        public
    {
        // Don't allow duplicate account
        require(! userExists(args.hashedUsername), "createAccount: user exists");

        internal_createAccount(
            args.hashedUsername, 
            args.optionalPassword, 
            args.wallet.walletType,
            args.wallet.keypairSecret
        );

        internal_addCredential(args.hashedUsername, args.credentialId, args.pubkey);

        // Sapphire.padGas(3500000);
    }

    /**
     * @dev Add wallet with credential
     *
     * @param args credential data
     */
    function addWallet (ActionCred memory args) 
        public 
    {
        bytes32 challenge = sha256(abi.encodePacked(personalization, sha256(args.data)));
        User memory user = internal_verifyCredential(args.credentialIdHashed, challenge, args.resp);

        internal_addWallet(user, args.data);
    }

    /**
     * @dev Add wallet with credential
     *
     * @param args credential data
     */
    function addWalletPassword (ActionPass memory args) 
        public 
    {
        User memory user = internal_verifyPassword(
            args.hashedUsername, 
            args.digest, 
            args.data
        );

        internal_addWallet(user, args.data);
    }

    /**
     * @dev Add/Remove credential with credential
     *
     * @param args credential data
     */
    function manageCredential(ActionCred memory args) 
        public 
    {
        bytes32 challenge = sha256(abi.encodePacked(personalization, sha256(args.data)));
        User memory user = internal_verifyCredential(args.credentialIdHashed, challenge, args.resp);

        internal_manageCredential(user, args.data);
    }

    /**
     * @dev Add/Remove credential with password
     *
     * @param args credential data
     */
    function manageCredentialPassword (ActionPass memory args) 
        public 
    {
        User memory user = internal_verifyPassword(
            args.hashedUsername, 
            args.digest, 
            args.data
        );

        internal_manageCredential(user, args.data);
    }

    /**
     * @dev Remove wallet with credential
     *
     * @param args credential data
     */
    function removeWallet (ActionCred memory args) 
        public 
    {
        bytes32 challenge = sha256(abi.encodePacked(personalization, sha256(args.data)));
        User memory user = internal_verifyCredential(args.credentialIdHashed, challenge, args.resp);

        internal_removeWallet(user, args.data);
    }

    /**
     * @dev Remove wallet with password
     *
     * @param args credential data
     */
    function removeWalletPassword (ActionPass memory args) 
        public 
    {
        User memory user = internal_verifyPassword(
            args.hashedUsername, 
            args.digest, 
            args.data
        );

        internal_removeWallet(user, args.data);
    }

    /**
     * @dev Retrieve a list of credential IDs for a specific user
     *
     * @param in_hashedUsername Hashed username
     */
    function credentialIdsByUsername(bytes32 in_hashedUsername)
        public view
        returns (bytes[] memory out_credentialIds)
    {
        require(userExists(in_hashedUsername), "credentialIdsByUsername");

        bytes32[] memory credentialIdHashes = usernameToHashedCredentialIdList[in_hashedUsername];

        uint length = credentialIdHashes.length;

        out_credentialIds = new bytes[](length);

        for( uint i = 0; i < length; i++ )
        {
            UserCredential memory cred = credentialsByHashedCredentialId[credentialIdHashes[i]];

            out_credentialIds[i] = cred.credentialId;
        }
    }

    /**
     * @dev Manage credential
     *
     * @param user user data
     * @param data encoded credential data
     */
    function internal_manageCredential(
        User memory user, 
        bytes memory data
    ) internal {
        Credential memory credential = abi.decode(data, (Credential));

        // Perform credential action
        if (credential.action == CredentialAction.Add) {
            internal_addCredential(user.username, credential.credentialId, credential.pubkey);
        } else if (credential.action == CredentialAction.Remove) {
            internal_removeCredential(user.username, credential.credentialId);
        } else  {
            revert("Unsupported operation");
        }
    }

    /**
     * @dev Add credential to an existing account
     *
     * @param in_hashedUsername PBKDF2 hashed username
     * @param in_credentialId Raw credentialId provided by WebAuthN compatible authenticator
     * @param in_pubkey Public key extracted from authenticatorData
     */
    function internal_addCredential(
        bytes32 in_hashedUsername,
        bytes memory in_credentialId,
        CosePublicKey memory in_pubkey
    )
        internal
    {
        // Ensure public key validity before registration
        require( WebAuthN.verifyPubkey(in_pubkey), "WebAuthN.verifyPubkey" );

        bytes32 hashedCredentialId = keccak256(in_credentialId);

        // Credential must not previously exist or be associated with a user
        require(
            credentialsByHashedCredentialId[hashedCredentialId].username == bytes32(0),
            "Credential already registered"
        );

        // Add credential to user
        credentialsByHashedCredentialId[hashedCredentialId] = UserCredential({
            pubkey: [in_pubkey.x, in_pubkey.y],
            credentialId: in_credentialId,
            username: in_hashedUsername
        });

        usernameToHashedCredentialIdList[in_hashedUsername].push(hashedCredentialId);
    }

    /**
     * @dev Remove credential from an account
     *
     * @param in_hashedUsername PBKDF2 hashed username
     * @param in_credentialId Raw credentialId provided by WebAuthN compatible authenticator
     */
    function internal_removeCredential(
        bytes32 in_hashedUsername,
        bytes memory in_credentialId
    )
        internal
    {
        bytes32 hashedCredentialId = keccak256(in_credentialId);

        require(
            usernameToHashedCredentialIdList[in_hashedUsername].length > 1, 
            "Cannot remove all credentials"
        );

        // Credential must be associated with in_hashedUsername
        require(
            credentialsByHashedCredentialId[hashedCredentialId].username == in_hashedUsername,
            "Invalid credential user"
        );

        // Remove credential from user
        delete credentialsByHashedCredentialId[hashedCredentialId];

        bytes32[] storage credentialList = usernameToHashedCredentialIdList[in_hashedUsername];

        uint256 credListLength = credentialList.length;
        uint256 credIdx = credListLength;
        uint256 lastIdx = credListLength - 1;
        for (uint256 i = 0; i < credListLength; i++) {
            if (credentialList[i] == hashedCredentialId) {
                credIdx = i;
                break;
            }
        }

        require(credIdx < credListLength, "CINF");

        if (credIdx < lastIdx) {
            // Swap last item to credIdx
            credentialList[credIdx] = credentialList[lastIdx];
        }

        credentialList.pop();
    }

    /**
     * @dev Helper function to check the length of a bytes32 value by looking for zero padding
     * @param data The bytes32 value to check
     * @return The length of the original data before zero padding
     */
    function getBytes32Length(bytes32 data) internal pure returns (uint256) {
        uint256 length = 0;
        for(uint256 i = 0; i < 32; i++) {
            if(data[i] != 0) {
                length = i + 1;
            } else {
                break;
            }
        }
        return length;
    }

    /**
     * @dev Create new account
     *
     * @param in_hashedUsername PBKDF2 hashed username
     * @param in_optionalPassword Optional password to access account
     * @param walletType Wallet type info
     * @param keypairSecret private/secret key if importing an existing address (otherwise bytes32(0) to create new)
     */
    function internal_createAccount(
        bytes32 in_hashedUsername, 
        bytes32 in_optionalPassword,
        WalletType walletType,
        bytes32 keypairSecret
    )
        internal
        returns (User storage user)
    {
        user = users[in_hashedUsername];
        user.username = in_hashedUsername;

        // Set password only first time
        if (user.password == bytes32(0)) {
            uint256 len = getBytes32Length(in_optionalPassword);
            if(len > 0) {
                require(len > 9, "Password must be at least 10 characters");
            }

            user.password = in_optionalPassword;
        }

        require(
            address(user.accounts[uint256(walletType)]) == address(0), 
            "Account for wallet type already exists"
        );

        user.accounts[uint256(walletType)] = IAccount(
            accountFactory.clone(
                address(this), 
                walletType,
                keypairSecret
            )
        );

    }

    /**
     * @dev Add wallet to an account
     *
     * @param user user data
     * @param data encoded wallet data
     */
    function internal_addWallet (
        User memory user, 
        bytes memory data
    ) internal {
        WalletData memory wallet = abi.decode(data, (WalletData));

        IAccount account = user.accounts[uint256(wallet.walletType)];

        if (address(account) == address(0)) {
            // Setup account for new walletType
            internal_createAccount(
                user.username, 
                bytes32(0), // skip password 
                wallet.walletType,
                wallet.keypairSecret
            );
        } else {
            // Add wallet to an existing account
            account.createWallet(wallet.keypairSecret);
        }
    }

    /**
     * @dev Remove wallet from an account
     *
     * @param user user data
     * @param data encoded wallet data
     */
    function internal_removeWallet(
        User memory user,
        bytes memory data
    ) internal {
        (
            uint256 walletType, 
            uint256 walletId
        ) = abi.decode(data, (uint256, uint256));

        IAccount account = user.accounts[walletType];
        require(
            address(account) != address(0), 
            "Account for this walletType not initialized"
        );

        account.removeWallet(walletId);
    }

    /**
     * @dev Get credential and user
     *
     * @param in_credentialIdHashed Raw credentialId provided by WebAuthN compatible authenticator
     */
    function internal_getCredentialAndUser (bytes32 in_credentialIdHashed)
        internal view
        returns (
            User storage user,
            UserCredential storage credential
        )
    {
        credential = credentialsByHashedCredentialId[in_credentialIdHashed];
        user = users[credential.username];

        require(credential.username != bytes32(0x0), "getCredentialAndUser");
    }

    /**
     * @dev Verify credential
     *
     * @param in_credentialIdHashed Raw credentialId provided by WebAuthN compatible authenticator
     * @param in_challenge challange to verify
     * @param in_resp reponse provided by WebAuthN compatible authenticator
     */
    function internal_verifyCredential (
        bytes32 in_credentialIdHashed,
        bytes32 in_challenge,
        AuthenticatorResponse memory in_resp
    )
        internal view
        returns (User storage user)
    {
        UserCredential memory credential;

        (user, credential) = internal_getCredentialAndUser(in_credentialIdHashed);

        require( 
            WebAuthN.verifyECES256P256(in_challenge, credential.pubkey, in_resp), 
            "verification failed" 
        );

        return user;
    }

    /**
     * @dev Verify password
     *
     * @param hashedUsername PBKDF2 hashed username
     * @param digest encoded (password + data)
     * @param data data to be verified
     */
    function internal_verifyPassword (
        bytes32 hashedUsername,
        bytes32 digest,
        bytes memory data
    ) 
        internal view 
        returns (User storage user) 
    {
        user = users[hashedUsername];
        require(user.username != bytes32(0), "Invalid username");
        require(user.password != bytes32(0), "Invalid password");

        // Verify data
        require(
            keccak256(abi.encodePacked(user.password, data)) == digest,
            "digest verification failed"
        );
    }

    /**
     * @dev Performs a proxied call to the users account
     *
     * @param user executor account
     * @param walletType wallet type to select account address
     * @param in_data calldata to pass to account proxy
     * @return out_data result from proxied view call
     */
    function internal_proxyView(
        User storage user,
        WalletType walletType,
        bytes calldata in_data
    )
        internal view
        returns (bytes memory out_data)
    {
        bool success;

        (success, out_data) = address(user.accounts[uint256(walletType)]).staticcall(in_data);

        assembly {
            switch success
            case 0 { revert(add(out_data,32),mload(out_data)) }
        }
    }

    /**
     * @dev Performs a proxied call to the verified users account
     *
     * @param in_hashedUsername hashedUsername
     * @param walletType wallet type to select account address
     * @param in_digest hashed(password + in_data)
     * @param in_data calldata to pass to account proxy
     * @return out_data result from proxied view call
     */
    function proxyViewPassword(
        bytes32 in_hashedUsername,
        WalletType walletType,
        bytes32 in_digest,
        bytes calldata in_data
    )
        external view
        returns (bytes memory out_data)
    {
        User storage user = internal_verifyPassword(
            in_hashedUsername, 
            in_digest, 
            in_data
        );

        return internal_proxyView(user, walletType, in_data);
    }

    /**
     * @dev Performs a proxied call to the verified users account
     *
     * @param in_credentialIdHashed credentialIdHashed
     * @param in_resp Authenticator response
     * @param walletType wallet type to select account address
     * @param in_data calldata to pass to account proxy
     * @return out_data result from proxied view call
     */
    function proxyView(
        bytes32 in_credentialIdHashed,
        AuthenticatorResponse calldata in_resp,
        WalletType walletType,
        bytes calldata in_data
    )
        external view
        returns (bytes memory out_data)
    {
        bytes32 challenge = sha256(abi.encodePacked(personalization, sha256(in_data)));

        User storage user = internal_verifyCredential(in_credentialIdHashed, challenge, in_resp);

        return internal_proxyView(user, walletType, in_data);
    }

    /**
     * @dev Gasless transaction resolves here
     *
     * @param nonce nonce used to decrypt
     * @param ciphertext encrypted in_data
     * @param timestamp validity expiration
     * @param dataHash keccak of data (used to parse emitted events on backend)
     */
    function encryptedTx (
        bytes32 nonce, 
        bytes memory ciphertext, 
        uint256 timestamp,
        bytes32 dataHash
    ) external {
        require(msg.sender == gaspayingAddress, "Only gaspayingAddress");
        require(timestamp >= block.timestamp, "Expired signature");
        require(!hashUsage[dataHash], "dataHash already used");

        hashUsage[dataHash] = true;

        bytes memory plaintext = Sapphire.decrypt(encryptionSecret, nonce, ciphertext, abi.encodePacked(address(this)));
        GaslessData memory gaslessArgs = abi.decode(plaintext, (GaslessData));

        User memory user;

        if (gaslessArgs.txType == uint8(TxType.CreateAccount)) {
            NewAccount memory args = abi.decode(gaslessArgs.funcData, (NewAccount));
            createAccount(args);

            // Get user for emit event
            user = users[args.hashedUsername];

        } else if (
            gaslessArgs.txType == uint8(TxType.ManageCredential) || 
            gaslessArgs.txType == uint8(TxType.AddWallet) ||
            gaslessArgs.txType == uint8(TxType.RemoveWallet) ||
            gaslessArgs.txType == uint8(TxType.ModifyController)
        ) {
            ActionCred memory args = abi.decode(gaslessArgs.funcData, (ActionCred));

            if (gaslessArgs.txType == uint8(TxType.ManageCredential)) {
                manageCredential(args);
            } else if (gaslessArgs.txType == uint8(TxType.AddWallet)) {
                addWallet(args);
            } else if (gaslessArgs.txType == uint8(TxType.RemoveWallet)) {
                removeWallet(args);
            } else if (gaslessArgs.txType == uint8(TxType.ModifyController)) {
                modifyController(args);
            }
            
            // Get user for emit event
            (user, ) = internal_getCredentialAndUser(args.credentialIdHashed);

        } else if (
            gaslessArgs.txType == uint8(TxType.ManageCredentialPassword) ||
            gaslessArgs.txType == uint8(TxType.AddWalletPassword) ||
            gaslessArgs.txType == uint8(TxType.RemoveWalletPassword) ||
            gaslessArgs.txType == uint8(TxType.ModifyControllerPassword)
        ) {
            ActionPass memory args = abi.decode(gaslessArgs.funcData, (ActionPass));

            if (gaslessArgs.txType == uint8(TxType.ManageCredentialPassword)) {
                manageCredentialPassword(args);
            } else if(gaslessArgs.txType == uint8(TxType.AddWalletPassword)) { 
                addWalletPassword(args);
            } else if(gaslessArgs.txType == uint8(TxType.RemoveWalletPassword)) { 
                removeWalletPassword(args);
            } else if(gaslessArgs.txType == uint8(TxType.ModifyControllerPassword)) {
                modifyControllerPassword(args);
            }

            // Get user for emit event
            user = users[args.hashedUsername];

        } else {
            revert("Unsupported operation");
        }

        emit GaslessTransaction(dataHash, address(user.accounts[0])); // EVM account
    }

    /**
     * @dev Generates a private signed transaction
     *
     * @param in_data calldata to execute in users behalf
     * @param nonce nonce to be used in transaction
     * @param gasPrice gasPrice to be used in transaction
     * @param gasLimit gasLimit to be used in transaction
     * @param timestamp signature expiration
     * @param signature signature for the above sensitive data
     * @return out_data signed transaction
     */
    function generateGaslessTx (
        bytes calldata in_data,
        uint64 nonce,
        uint256 gasPrice,
        uint64 gasLimit,
        uint256 timestamp,
        bytes memory signature
    )
        external view
        returns (bytes memory out_data)
    {
        require(timestamp >= block.timestamp, "Expired signature");

        // Verify signature
        (bytes32 dataHash, bool isValid) = validateSignature(
            gasPrice,
            gasLimit,
            timestamp,
            keccak256(in_data),
            signature
        );

        require(isValid, "Invalid signature");
        require(!hashUsage[dataHash], "dataHash already used");

        bytes32 cipherNonce = bytes32(Sapphire.randomBytes(32, in_data));

        bytes memory cipherPersonalization = abi.encodePacked(address(this));

        bytes memory cipherBytes = Sapphire.encrypt(
            encryptionSecret,
            cipherNonce,
            in_data, // plainText,
            cipherPersonalization);

        EIP155Signer.EthTx memory gaslessTx = EIP155Signer.EthTx({
            nonce: nonce,
            gasPrice: gasPrice,
            gasLimit: gasLimit,
            to: address(this),
            value: 0,
            data: abi.encodeCall(
                this.encryptedTx,
                (cipherNonce, cipherBytes, timestamp, dataHash)
            ),
            chainId: block.chainid
        });

        return EIP155Signer.sign(gaspayingAddress, gaspayingSecret, gaslessTx);
    }

    /**
     * @dev Set signer address.
     * 
     * @param _signer Signer address
     */
    function setSigner(address _signer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_signer != address(0), "Zero address not allowed");
        signer = _signer;
    }

    /**
     * @dev Validates signature.
     *
     * @param _gasPrice gas price
     * @param _gasLimit gas limit
     * @param _timestamp timestamp
     * @param _dataKeccak keccak of data
     * @param _signature signature of above parameters
     */
    function validateSignature(
        uint256 _gasPrice,
        uint64 _gasLimit,
        uint256 _timestamp,
        bytes32 _dataKeccak,
        bytes memory _signature
    ) public view returns (bytes32, bool) {
        bytes32 dataHash = keccak256(
            abi.encodePacked(_gasPrice, _gasLimit, _timestamp, _dataKeccak)
        );
        bytes32 message = MessageHashUtils.toEthSignedMessageHash(dataHash);
        address receivedAddress = ECDSA.recover(message, _signature);
        return (dataHash, receivedAddress == signer);
    }

    /**
     * @dev Modify controller with credential
     *
     * @param args credential data
     */
    function modifyController (ActionCred memory args) 
        public 
    {
        bytes32 challenge = sha256(abi.encodePacked(personalization, sha256(args.data)));
        User memory user = internal_verifyCredential(args.credentialIdHashed, challenge, args.resp);

        internal_modifyController(user, args.data);
    }

    /**
     * @dev Modify controller with password
     *
     * @param args credential data
     */
    function modifyControllerPassword (ActionPass memory args) 
        public 
    {
        User memory user = internal_verifyPassword(
            args.hashedUsername, 
            args.digest, 
            args.data
        );

        internal_modifyController(user, args.data);
    }

    /**
     * @dev Modify controller on an account
     *
     * @param user user data
     * @param data encoded controller data
     */
    function internal_modifyController(
        User memory user,
        bytes memory data
    ) internal {
        (
            uint256 walletType,
            address controller,
            bool status,
            uint256 deadline
        ) = abi.decode(data, (uint256, address, bool, uint256));

        IAccount account = user.accounts[walletType];
        require(
            address(account) != address(0), 
            "Account for this walletType not initialized"
        );

        account.modifyController(controller, status, deadline);
    }
}
