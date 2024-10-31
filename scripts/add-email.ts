const { ethers } = require("hardhat");
const { pbkdf2Sync } = require("pbkdf2");
const abiCoder = ethers.AbiCoder.defaultAbiCoder();

async function main() {
  // DATA to be set
  const accountManagerAddress = "0xe1D85Aa3449690185371193DD46D60c3DA9FC709";
  const usernamePlain = "username";
  const email = "test@example.com";
  // Data to be set [END]

  const signer = (await ethers.getSigners())[0];
  const accountManager = await ethers.getContractAt('AccountManager', accountManagerAddress, signer);

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
