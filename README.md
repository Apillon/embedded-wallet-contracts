# Oasis contracts

This repo contains smart contracts that [Oasis] use.

#### About AccountManager.sol contract

The Account Manager is a smart contract that handles account creation, credential management, simple message signing, and transaction signing. Its goal is to manage accounts for all EVM-compatible chains, with the added option of exporting private keys for direct use in other EVM wallets.

## Development

> Instructions for development.

### Project setup

Create `secrets.json` file in root folder and insert private keys used to deploy.

### Test

Run `npm test`.

### Build

Run `npm run build`.

### Flatten

Run `npm run flatten`.

## Deployment

> Smart contract deployment instructions.

#### Deploy AccountManager.sol

1. Set signer address in `scripts/deploy-account-manager.ts` (this address provides signature for gasless transactions)
2. Set initial value to be transfered on gaspaying address
3. Run `npx hardhat run --network sapphireTestnet ./scripts/deploy-account-manager.ts`

Note: deployment should be executed with unwrapped ethers provider in order to be able to verify contract in next stage. All further transactions should be done using wrapped sapphire provider.

#### Account registration

1. Set `accountManagerAddress`, `usernamePlain`, `password` in `scripts/registration.ts`
2. Run `npx hardhat run --network sapphireTestnet ./scripts/registration.ts`

#### Gasless Account registration (predefined address with funds loaded pays for gas)

1. Set `accountManagerAddress`, `usernamePlain`, `password` in `scripts/registration-gasless.ts`
2. Run `npx hardhat run --network sapphireTestnet ./scripts/registration-gasless.ts`

Note: `usernamePlain` has to be unique. If the transaction fails verify that `signer` address is the same on the AccountManager.sol & in the script

#### Verify if registration success

1. Set `accountManagerAddress`, `usernamePlain` in `scripts/user-exists.ts`
2. Run `npx hardhat run --network sapphireTestnet ./scripts/user-exists.ts`

#### Change signer in AccountManager

1. Set `accountManagerAddress`, `newSigner` in `scripts/set-signer.ts`
2. Run `npx hardhat run --network sapphireTestnet ./scripts/set-signer.ts`

#### Get AccountManager data

1. Set `accountManagerAddress` in `scripts/account-manager-data.ts`
2. Run `npx hardhat run --network sapphireTestnet ./scripts/account-manager-data.ts`

## Helper scripts

#### Output ABI in json format
1. Run `npx hardhat run ./scripts/helper/convert-abi.ts`

#### Generate signature for gasless registration

1. Set `gasPrice`, `gasLimit`, `timestamp`, `gaslessData` in `scripts/helper/generate-signature-for-register.ts`
2. Run `npx hardhat run ./scripts/helper/generate-signature-for-register.ts`

## Examples - how to use a keypair generated via AccountManager

#### Transfer ETH (using password)

1. Set `accountManagerAddress`, `usernamePlain`, `password`, `receiverAddress` in `scripts/examples/proxy-call-transfer.ts`
2. Run `npx hardhat run --network sapphireTestnet ./scripts/examples/proxy-call-transfer.ts`

Note: Make sure you have some ETH on the sender address (if you don't know your sender address, than you can get it by calling `./scripts/user-exists.ts`)

#### Transfer ERC20 (using password)

1. Set `accountManagerAddress`, `usernamePlain`, `password`, `receiverAddress`, `erc20Address`, `erc20Amount` in `scripts/examples/proxy-call-erc20-transfer.ts`
2. Run `npx hardhat run --network sapphireTestnet ./scripts/examples/proxy-call-erc20-transfer.ts`

Note: 
- Make sure you have some ETH on the sender address (if you don't know your sender address, than you can get it by calling `./scripts/user-exists.ts`).
- Make sure you have sufficient ERC20 token on the sender address too.
- You can either deploy your own erc20 token or use an existing one.

#### Transfer ETH on Amoy, generate transaction on sapphire & execute on Amoy (using password)

1. Set `accountManagerAddress`, `usernamePlain`, `password`, `txRequest` in `scripts/examples/proxy-call-cross-chain.ts`
2. Run `npx hardhat run --network sapphireTestnet ./scripts/examples/proxy-call-cross-chain.ts`

Note: 
- Make sure you have some ETH (Amoy) on the sender address (if you don't know your sender address, than you can get it by calling `./scripts/user-exists.ts`).
- Make sure you set the right nonce in `txRequest` (nonce on Amoy chain)