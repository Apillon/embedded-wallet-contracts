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

import {Account,AccountFactory} from "./Account.sol";
import {WebAuthN,CosePublicKey,AuthenticatorResponse} from "./lib/WebAuthN.sol";

struct UserCredential {
    uint256[2] pubkey;
    bytes credentialId;
    bytes32 username;
}

struct User {
    bytes32 username;
    bytes32 password;
    Account account;
}

enum TxType {
    CreateAccount,
    ManageCredential,
    ManageCredentialPassword
}

enum CredentialAction {
    Add,
    Remove
}

contract AccountManagerStorage {

    AccountFactory internal accountFactory;

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

    event GaslessTransaction(bytes32 indexed dataHash, bytes32 indexed hashedUsername, address indexed publicAddress);
}

contract AccountManager is AccountManagerStorage,
    Initializable, 
    UUPSUpgradeable,
    AccessControlUpgradeable
{
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor()  {
        _disableInitializers();
    }

    // Initializer instead of constructor
    function initialize(
        address _signer
    ) public payable initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();

        require(_signer != address(0), "Zero address not allowed");
        signer = _signer;

        salt = bytes32(Sapphire.randomBytes(32, abi.encodePacked(address(this))));

        encryptionSecret = bytes32(Sapphire.randomBytes(32, abi.encodePacked(address(this))));

        (gaspayingAddress, gaspayingSecret) = EthereumUtils.generateKeypair();

        accountFactory = new AccountFactory();

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
    function getAccount (bytes32 in_username)
        external view
        returns (Account account, address keypairAddress)
    {
        User storage user = users[in_username];

        account = user.account;

        keypairAddress = account.keypairAddress();
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
        User storage user = users[in_username];

        return user.username != bytes32(0x0);
    }

    struct GaslessData {
        bytes funcData;
        uint8 txType;
    }

    struct NewAccount {
        bytes32 hashedUsername;
        bytes credentialId;
        CosePublicKey pubkey;
        bytes32 optionalPassword;
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

        internal_createAccount(args.hashedUsername, args.optionalPassword);

        internal_addCredential(args.hashedUsername, args.credentialId, args.pubkey);
    }

    struct ManageCred {
        bytes32 credentialIdHashed;
        AuthenticatorResponse resp;
        bytes data;
    }

    struct ManageCredPass {
        bytes32 digest;
        bytes data;
    }

    struct Credential {
        bytes32 hashedUsername;
        bytes credentialId;
        CosePublicKey pubkey;
        CredentialAction action;
    }

    /**
     * @dev Add/Remove credential with credential
     *
     * @param args credential data
     */
    function manageCredential (ManageCred memory args) 
        public 
    {
        Credential memory credential = abi.decode(args.data, (Credential));

        bytes32 challenge = sha256(abi.encodePacked(personalization, sha256(args.data)));

        User storage user = internal_verifyCredential(args.credentialIdHashed, challenge, args.resp);

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
     * @dev Add/Remove credential with password
     *
     * @param args credential data
     */
    function manageCredentialPassword (ManageCredPass memory args) 
        public 
    {
        Credential memory credential = abi.decode(args.data, (Credential));

        User storage user = users[credential.hashedUsername];
        require(user.username != bytes32(0), "Invalid username");
        require(user.password != bytes32(0), "Invalid password");

        // Verify data
        require(
            keccak256(abi.encodePacked(user.password, args.data)) == args.digest,
            "digest verification failed"
        );

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
     * @dev Retrieve a list of credential IDs for a specific user
     *
     * @param in_hashedUsername Hashed username
     */
    function credentialIdsByUsername(bytes32 in_hashedUsername)
        public view
        returns (bytes[] memory out_credentialIds)
    {
        require(userExists(in_hashedUsername), "credentialIdsByUsername");

        bytes32[] storage credentialIdHashes = usernameToHashedCredentialIdList[in_hashedUsername];

        uint length = credentialIdHashes.length;

        out_credentialIds = new bytes[](length);

        for( uint i = 0; i < length; i++ )
        {
            UserCredential storage cred = credentialsByHashedCredentialId[credentialIdHashes[i]];

            out_credentialIds[i] = cred.credentialId;
        }
    }

    /**
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

        require(credIdx < credListLength, "credential index not found");

        if (credIdx < lastIdx) {
            // Swap last item to credIdx
            credentialList[credIdx] = credentialList[lastIdx];
        }

        credentialList.pop();
    }

    function internal_createAccount(bytes32 in_hashedUsername, bytes32 in_optionalPassword)
        internal
        returns (User storage user)
    {
        user = users[in_hashedUsername];
        user.username = in_hashedUsername;
        user.account = accountFactory.clone(address(this));
        user.password = in_optionalPassword;
    }

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

    function internal_verifyCredential (
        bytes32 in_credentialIdHashed,
        bytes32 in_challenge,
        AuthenticatorResponse memory in_resp
    )
        internal view
        returns (User storage user)
    {
        UserCredential storage credential;

        (user, credential) = internal_getCredentialAndUser(in_credentialIdHashed);

        require( 
            WebAuthN.verifyECES256P256(in_challenge, credential.pubkey, in_resp), 
            "verification failed" 
        );

        return user;
    }

    /**
     * @dev Performs a proxied call to the users account
     *
     * @param user executor account
     * @param in_data calldata to pass to account proxy
     * @return out_data result from proxied view call
     */
    function internal_proxyView(
        User storage user,
        bytes calldata in_data
    )
        internal view
        returns (bytes memory out_data)
    {
        bool success;

        (success, out_data) = address(user.account).staticcall(in_data);

        assembly {
            switch success
            case 0 { revert(add(out_data,32),mload(out_data)) }
        }
    }

    /**
     * @dev Performs a proxied call to the verified users account
     *
     * @param in_hashedUsername hashedUsername
     * @param in_digest hashed(password + in_data)
     * @param in_data calldata to pass to account proxy
     * @return out_data result from proxied view call
     */
    function proxyViewPassword(
        bytes32 in_hashedUsername,
        bytes32 in_digest,
        bytes calldata in_data
    )
        external view
        returns (bytes memory out_data)
    {
        User storage user = users[in_hashedUsername];

        require( 
            user.username != bytes32(0),
            "Invalid username"
        );
        require(
            user.password != bytes32(0),
            "Invalid password"    
        );
        require(
            keccak256(abi.encodePacked(user.password, in_data)) == in_digest,
            "in_digest verification failed"
        );

        return internal_proxyView(user, in_data);
    }

    /**
     * @dev Performs a proxied call to the verified users account
     *
     * @param in_credentialIdHashed credentialIdHashed
     * @param in_resp Authenticator response
     * @param in_data calldata to pass to account proxy
     * @return out_data result from proxied view call
     */
    function proxyView(
        bytes32 in_credentialIdHashed,
        AuthenticatorResponse calldata in_resp,
        bytes calldata in_data
    )
        external view
        returns (bytes memory out_data)
    {
        bytes32 challenge = sha256(abi.encodePacked(personalization, sha256(in_data)));

        User storage user = internal_verifyCredential(in_credentialIdHashed, challenge, in_resp);

        return internal_proxyView(user, in_data);
    }

    /**
     * @dev Gasless transaction resolves here
     *
     * @param ciphertext encrypted in_data
     * @param nonce nonce used to decrypt
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

        } else if (gaslessArgs.txType == uint8(TxType.ManageCredential)) {
            ManageCred memory args = abi.decode(gaslessArgs.funcData, (ManageCred));
            manageCredential(args);

            // Get user for emit event
            (user, ) = internal_getCredentialAndUser(args.credentialIdHashed);

        } else if (gaslessArgs.txType == uint8(TxType.ManageCredentialPassword)) {
            ManageCredPass memory args = abi.decode(gaslessArgs.funcData, (ManageCredPass));
            manageCredentialPassword(args);

            // Get user for emit event
            user = users[abi.decode(args.data, (Credential)).hashedUsername];

        } else  {
            revert("Unsupported operation");
        }

        emit GaslessTransaction(dataHash, user.username, user.account.keypairAddress());
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
}
