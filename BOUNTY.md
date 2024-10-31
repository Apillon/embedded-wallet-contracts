# Email based authentication and social recovery

## Table of contents

1. [Problem statement](#problem-statement)
2. [Approach](#approach)
3. [Architecture overview](#architecture-overview)
4. [Key features](#key-features)
5. [Contract structure and changes](#contract-structure-and-changes)
   - [Original `AccountManager`](#original-accountmanager-contract)
   - [Integration of recovery libraries](#integration-of-recovery-libraries)
   - [Updated `AccountManager`](#updated-accountmanager-contract)
   - [EmailRecovery library](#emailrecovery-library)
   - [SocialRecovery library](#socialrecovery-library)
6. [Code changes](#code-changes)
   - [AccountManager.sol](#accountmanagersol)
   - [EmailRecovery.sol](#emailrecoverysol)
   - [SocialRecovery.sol](#socialrecoverysol)
7. [Testing](#testing)
   - [Test suite](#test-suite-overview)
   - [Running tests](#running-tests)
8. [Usage](#usage)
   - [Adding an email](#adding-an-email)
   - [Verifying an email](#verifying-an-email)
   - [Removing an email](#removing-an-email)
   - [Adding social recovery](#adding-social-recovery)
   - [Verifying social recovery](#verifying-social-recovery)
   - [Removing social recovery](#removing-social-recovery)
9. [Future enhancements](#future-enhancements)
10. [Security considerations](#security-considerations)
11. [Additional notes](#additional-notes)

---

## Problem statement

In the world of decentralized apps, keeping user accounts safe and easy to manage is crucial. Relying only on cryptographic keys can be tricky and might not be enough for today's needs. Users often need extra security and ways to recover their accounts, like email verification and social media recovery to protect against losing access or unauthorized use.

The **AccountManager** smart contract tackles these issues by offering a strong and flexible system to manage user accounts by adding different ways to log in that ensures secure recovery options

---

## Approach

To build a secure and easy to manage account system, we followed these steps:

1. **Modular design:** we created solidity libraries (`EmailRecovery` and `SocialRecovery`) to handle specific recovery tasks making the code reusable and easier to maintain

2. **Upgradeability:** we utilized openzeppelin's upgradeable contracts with the UUPS pattern to allow updates and new features without affecting current data

3. **Access control:** we used `AccessControl` to manage roles and permissions, ensuring only authorized users can perform important actions

4. **Signature verification:** we adopted ECDSA (elliptic curve digital signature algorithm) to verify signatures, making sure recovery requests are genuine and authorized

5. **Testing:** we created detailed test suites with hardhat and chai to check all functions, including edge cases and security

6. **Gasless transactions:** implemented ways to allow users to perform actions without handling gas fees, making the system more user friendly

---

## Architecture

1. **AccountManager** The core contract managing user accounts, authentication methods and recovery processes

2. **AccountFactory** Responsible for cloning and deploying individual `Account` contracts for users

3. **Account** Manages user specific data and operations, acting as a proxy for individual user actions

4. **Recovery libraries:**

   - **EmailRecovery:** Handles verification of email based recovery requests
   - **SocialRecovery:** Manages verification of social platform based recovery requests

5. **Other libraries:**
   - **openzeppelin** Provides secure and tested implementations for upgradeability and access control
   - **Sapphire** Facilitates encryption and signature operations for secure transactions

---

## Features

- **User account management:** Create, manage and delete user accounts with unique credentials.
- **Email authentication:** Add, verify, and remove email-based authentication methods
- **Social recovery:** Use social platforms (like Google, Twitter) to recover accounts
- **Gasless transactions:** Let users perform actions without handling gas fees
- **Upgradeable contracts:** Upgrade contract features without losing data
- **Robust security:** Use strong access controls and signature checks to prevent unauthorized access

---

## Contract structure and changes

### Original `AccountManager`

The initial `AccountManager` contract provided functionalities for managing user accounts and credentials. It allowed adding and verifying credentials but lacked integrated recovery mechanisms like email and social recovery

### Integration of recovery libraries

To enhance the contract's capabilities, two libraries were introduced:

1. **EmailRecovery:** Handles verification of email-based recovery requests

2. **SocialRecovery:** Manages verification of social platform-based recovery requests

These libraries encapsulate the verification logic, promoting cleaner and more maintainable code within the `AccountManager` contract

### Updated `AccountManager`

The updated contract incorporates the `EmailRecovery` and `SocialRecovery` libraries, refactoring existing functions to utilize these libraries for recovery processes

### EmailRecovery library

```solidity
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
```

### SocialRecovery library

```solidity
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
```

## Code changes

## Code changes

### Import statements

Added imports for EmailRecovery and SocialRecovery libraries to use their features in the AccountManager contract

```solidity
import {EmailRecovery} from "./lib/EmailRecovery.sol";
import {SocialRecovery} from "./lib/SocialRecovery.sol";
```

### Functions

#### `verifyEmail` function

```solidity
function verifyEmail(bytes32 in_username, string memory email, bytes memory signature) external {
    require(userExists(in_username), "verifyEmail: user does not exist");
    User storage user = users[in_username];
    require(user.emailCredential.emailHash == keccak256(bytes(email)), "verifyEmail: email does not match");
    require(!user.emailCredential.verified, "verifyEmail: already verified");

    // Create EmailRecoveryRequest struct
    EmailRecovery.EmailRecoveryRequest memory request = EmailRecovery.EmailRecoveryRequest({
        hashedUsername: in_username,
        emailHash: keccak256(bytes(email)),
        timestamp: block.timestamp,
        signature: signature
    });

    // Use the library to verify the request
    bool isValid = EmailRecovery.verifyRecoveryRequest(request, signer);
    require(isValid, "verifyEmail: invalid signature");

    user.emailCredential.verified = true;

    emit EmailVerified(in_username, user.emailCredential.emailHash);
}
```

#### `verifySocial`

```solidity
function verifySocial(bytes32 in_username, string memory platform, string memory socialId, bytes memory signature) external {
    require(userExists(in_username), "verifySocial: user does not exist");
    User storage user = users[in_username];
    bytes32 platformHash = keccak256(bytes(platform));
    bytes32 socialIdHash = keccak256(bytes(socialId));

    bool found = false;
    uint index;
    for (uint i = 0; i < user.socialCredentials.length; i++) {
        if (user.socialCredentials[i].platformHash == platformHash &&
            user.socialCredentials[i].socialIdHash == socialIdHash) {
            found = true;
            index = i;
            break;
        }
    }
    require(found, "verifySocial: social credential not found");
    require(!user.socialCredentials[index].verified, "verifySocial: already verified");

    // Create SocialRecoveryRequest struct
    SocialRecovery.SocialRecoveryRequest memory request = SocialRecovery.SocialRecoveryRequest({
        hashedUsername: in_username,
        platformHash: platformHash,
        socialIdHash: socialIdHash,
        timestamp: block.timestamp,
        signature: signature
    });

    // Use the library to verify the request
    bool isValid = SocialRecovery.verifyRecoveryRequest(request, signer);
    require(isValid, "verifySocial: invalid signature");

    user.socialCredentials[index].verified = true;

    emit SocialVerified(in_username, platformHash, socialIdHash);
}
```

## Testing

### Test suite

A complete test suite was built using Hardhat and chai to make sure the AccountManager contract works well and is secure. The tests include:

- **Account ceation:** Making sure new accounts can be created without duplicates
- **Email authentication:** Adding, verifying and removing email authentication methods
- **Social recovery:** Adding, verifying and removing social recovery methods
- **Access control:** Ensuring only authorized roles can do sensitive tasks
- **Signature verification:** Checking that signatures are valid during verification.
- **Edge cases:** Handling cases like adding duplicates or removing non existent credentials

### Running tests

**Install dpendencies:**

```bash
npm install
```

**Compile:**

```bash
npx hardhat compile
```

**Run Tests:**

```bash
npx hardhat test
```

### Example test cases

- **Adding, verifying and removing email authentication:** Checks that email methods can be managed correctly, verified with valid signatures and events are emitted properly
- **Adding, verifying and removing social recovery:** Ensures social recovery methods work securely and are managed correctly
- **Access control enforcement:** Makes sure only admins can do restricted actions like adding or removing methods
- **Invalid signature handling:** Tests that invalid signatures cause the process to fail

## Usage

### Adding an email

**Script:** `scripts/add-email.js`

```javascript
const { ethers } = require("hardhat");
const { pbkdf2Sync } = require("pbkdf2");
const abiCoder = ethers.AbiCoder.defaultAbiCoder();

async function main() {
  // Configuration
  const accountManagerAddress = "0x<>";
  const usernamePlain = "username";
  const email = "user@example.com";

  // Get signer
  const signer = (await ethers.getSigners())[0];

  // Get contract instance
  const accountManager = await ethers.getContractAt(
    "AccountManager",
    accountManagerAddress,
    signer
  );

  // Get salt from contract
  const saltBytes = await accountManager.salt();
  const salt = Buffer.from(saltBytes.slice(2), "hex");

  // Hash the username
  const hashedUsername = pbkdf2Sync(usernamePlain, salt, 100000, 32, "sha256");

  // Check if user exists
  const userExists = await accountManager.userExists(hashedUsername);
  if (!userExists) {
    console.error("User does not exist. Please create the account first.");
    process.exit(1);
  }

  // Add email
  const tx = await accountManager.addEmail(hashedUsername, email);
  await tx.wait();

  console.log(
    `Email "${email}" added for user "${usernamePlain}" (hashed: ${hashedUsername.toString(
      "hex"
    )})`
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Error adding email:", error);
    process.exit(1);
  });
```

**Usage:**

```bash
npx hardhat run --network sapphireTestnet scripts/add-email.js
```

### Verifying an email

**Script:** `scripts/verify-email.js`

```javascript
const { ethers } = require("hardhat");
const { pbkdf2Sync } = require("pbkdf2");
const abiCoder = ethers.AbiCoder.defaultAbiCoder();

async function main() {
  // Configuration
  const accountManagerAddress = "0x<>";
  const usernamePlain = "username";
  const email = "user@example.com";

  // The actual signature obtained from the backend/signing service
  const signature = "0x<>";

  // Get signer
  const signer = (await ethers.getSigners())[0];

  // Get contract instance
  const accountManager = await ethers.getContractAt(
    "AccountManager",
    accountManagerAddress,
    signer
  );

  // Get salt from contract
  const saltBytes = await accountManager.salt();
  const salt = Buffer.from(saltBytes.slice(2), "hex");

  // Hash the username
  const hashedUsername = pbkdf2Sync(usernamePlain, salt, 100000, 32, "sha256");

  // Verify email using the refactored function
  const tx = await accountManager.verifyEmail(hashedUsername, email, signature);
  await tx.wait();

  console.log(
    `Email "${email}" verified for user "${usernamePlain}" (hashed: ${hashedUsername.toString(
      "hex"
    )})`
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Error verifying email:", error);
    process.exit(1);
  });
```

**Usage:**

```bash
npx hardhat run --network sapphireTestnet scripts/verify-email.js
```

### Removing an email

**Script:** `scripts/remove-email.js`

```javascript
const { ethers } = require("hardhat");
const { pbkdf2Sync } = require("pbkdf2");

async function main() {
  // Configuration
  const accountManagerAddress = "0x<>";
  const usernamePlain = "username";

  // Get signer
  const signer = (await ethers.getSigners())[0];

  // Get contract instance
  const accountManager = await ethers.getContractAt(
    "AccountManager",
    accountManagerAddress,
    signer
  );

  // Get salt from contract
  const saltBytes = await accountManager.salt();
  const salt = Buffer.from(saltBytes.slice(2), "hex");

  // Hash the username
  const hashedUsername = pbkdf2Sync(usernamePlain, salt, 100000, 32, "sha256");

  // Remove email
  const tx = await accountManager.removeEmail(hashedUsername);
  await tx.wait();

  console.log(
    `Email removed for user "${usernamePlain}" (hashed: ${hashedUsername.toString(
      "hex"
    )})`
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Error removing email:", error);
    process.exit(1);
  });
```

**Usage:**

```bash
npx hardhat run --network sapphireTestnet scripts/remove-email.js
```

### Adding social recovery

**Script:** `scripts/add-social-recovery.js`

```javascript
const { ethers } = require("hardhat");
const { pbkdf2Sync } = require("pbkdf2");

async function main() {
  // Configuration
  const accountManagerAddress = "0x<>";
  const usernamePlain = "username";
  const platform = "twitter";
  const socialId = "twitter_id_123";

  // Get signer
  const signer = (await ethers.getSigners())[0];

  // Get contract instance
  const accountManager = await ethers.getContractAt(
    "AccountManager",
    accountManagerAddress,
    signer
  );

  // Get salt from contract
  const saltBytes = await accountManager.salt();
  const salt = Buffer.from(saltBytes.slice(2), "hex");

  // Hash the username
  const hashedUsername = pbkdf2Sync(usernamePlain, salt, 100000, 32, "sha256");

  // Check if user exists
  const userExists = await accountManager.userExists(hashedUsername);
  if (!userExists) {
    console.error("User does not exist. Please create the account first.");
    process.exit(1);
  }

  // Add social recovery
  const tx = await accountManager.addSocial(hashedUsername, platform, socialId);
  await tx.wait();

  console.log(
    `social recovery method "${platform}:${socialId}" added for user "${usernamePlain}" (hashed: ${hashedUsername.toString(
      "hex"
    )})`
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Error adding social recovery:", error);
    process.exit(1);
  });
```

**Usage:**

```bash
npx hardhat run --network sapphireTestnet scripts/add-social-recovery.js
```

### Verifying social recovery

**Script:** `scripts/verify-social-recovery.js`

```javascript
const { ethers } = require("hardhat");
const { pbkdf2Sync } = require("pbkdf2");

async function main() {
  // Configuration
  const accountManagerAddress = "0x<>";
  const usernamePlain = "username";
  const platform = "twitter";
  const socialId = "twitter_id_123";

  // The actual signature obtained from the backend/signing service
  const signature = "0x<>";

  // Get signer
  const signer = (await ethers.getSigners())[0];

  // Get contract instance
  const accountManager = await ethers.getContractAt(
    "AccountManager",
    accountManagerAddress,
    signer
  );

  // Get salt from contract
  const saltBytes = await accountManager.salt();
  const salt = Buffer.from(saltBytes.slice(2), "hex");

  // Hash the username
  const hashedUsername = pbkdf2Sync(usernamePlain, salt, 100000, 32, "sha256");

  // Verify social recovery using the refactored function
  const tx = await accountManager.verifySocial(
    hashedUsername,
    platform,
    socialId,
    signature
  );
  await tx.wait();

  console.log(
    `social recovery method "${platform}:${socialId}" verified for user "${usernamePlain}" (hashed: ${hashedUsername.toString(
      "hex"
    )})`
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Error verifying social recovery:", error);
    process.exit(1);
  });
```

**Usage:**

```bash
npx hardhat run --network sapphireTestnet scripts/verify-social-recovery.js
```

### Removing social recovery

**Script:** `scripts/remove-social-recovery.js`

```javascript
const { ethers } = require("hardhat");
const { pbkdf2Sync } = require("pbkdf2");

async function main() {
  // Configuration
  const accountManagerAddress = "0x<>";
  const usernamePlain = "username";
  const platform = "twitter";
  const socialId = "twitter_id_123";

  // Get signer
  const signer = (await ethers.getSigners())[0];

  // Get contract instance
  const accountManager = await ethers.getContractAt(
    "AccountManager",
    accountManagerAddress,
    signer
  );

  // Get salt from contract
  const saltBytes = await accountManager.salt();
  const salt = Buffer.from(saltBytes.slice(2), "hex");

  // Hash the username
  const hashedUsername = pbkdf2Sync(usernamePlain, salt, 100000, 32, "sha256");

  // Remove social recovery
  const tx = await accountManager.removeSocial(
    hashedUsername,
    platform,
    socialId
  );
  await tx.wait();

  console.log(
    `social recovery method "${platform}:${socialId}" removed for user "${usernamePlain}" (hashed: ${hashedUsername.toString(
      "hex"
    )})`
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Error removing social recovery:", error);
    process.exit(1);
  });
```

**Usage:**

```bash
npx hardhat run --network sapphireTestnet scripts/remove-social-recovery.js
```

## Future enhancements

- **Multi factor authentication (MFA):** Add extra security layers like SMS or hardware wallets
- **User interface tntegration:** Create a frontend app for easy account and recovery management
- **Advanced recovery mechanisms:** Use multiple social accounts or emails needed to recover an account
- **Integration with decentralized identifiers (DIDs):** Use DID standards for decentralized identity
