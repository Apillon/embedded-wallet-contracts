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

Note: `usernamePlain` has to be unique.

#### Verify if registration success

1. Set `accountManagerAddress`, `usernamePlain` in `scripts/user-exists.ts`
2. Run `npx hardhat run --network sapphireTestnet ./scripts/user-exists.ts`
