const { ethers } = require("hardhat");
const { pbkdf2Sync } = require("pbkdf2");

async function main() {
  // DATA to be set
  const accountManagerAddress = "0xYourAccountManagerAddressHere";
  const usernamePlain = "username";
  const platform = "google";
  const socialId = "google_unique_id_123";
  // Data to be set [END]

  const signer = (await ethers.getSigners())[0];
  const accountManager = await ethers.getContractAt("AccountManager", accountManagerAddress, signer);

  // Get salt from contract
  const saltBytes = await accountManager.salt();
  const salt = Buffer.from(saltBytes.slice(2), 'hex');

  // Hash the username
  const hashedUsername = pbkdf2Sync(usernamePlain, salt, 100000, 32, 'sha256');

  // Check if user exists
  const userExists = await accountManager.userExists(hashedUsername);
  if (!userExists) {
    console.error("User does not exist. Please create the account first.");
    process.exit(1);
  }

  // Add social recovery method
  const tx = await accountManager.addSocial(hashedUsername, platform, socialId);
  await tx.wait();

  console.log(`Social recovery method "${platform}:${socialId}" added for user "${usernamePlain}" (hashed: ${hashedUsername.toString('hex')})`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Error adding social recovery:", error);
    process.exit(1);
  });