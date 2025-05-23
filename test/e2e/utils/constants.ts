export const SAPPHIRE_LOCALNET = 23293;
export const GAS_LIMIT = 1000000;
export const ACCOUNT_ABI = [
  'function exportPrivateKey(uint256 walletId, uint256 deadline) view returns (bytes32)',
  'function getWalletList() view returns (bytes32[])',
  'function walletAddress (uint256 walletId) view returns (bytes32)',
  'function removeWallet(uint256 walletId)',
  'function transfer(address in_target, uint256 amount, uint256 walletId) public',
  'function call(address in_contract, bytes calldata in_data, uint256 value, uint256 walletId) public',
  'function staticcall(address in_contract, bytes calldata in_data, uint256 value, uint256 walletId) public',
];

export const ACCOUNT_EVM_ABI = [
  ...ACCOUNT_ABI,
  'function signEIP155(uint256 walletId, (uint64 nonce,uint256 gasPrice,uint64 gasLimit,address to,uint256 value,bytes data,uint256 chainId)) view returns (bytes)',
  'function sign(uint256 walletId, bytes32 digest) view returns ((bytes32 r,bytes32 s,uint256 v))',
];

export const ACCOUNT_SUBSTRATE_ABI = [
  ...ACCOUNT_ABI,
  'function sign(uint256 walletId, bytes data) view returns (bytes)',
];

export const GASLESS_TYPE_CREATE_ACCOUNT = 0;
export const GASLESS_TYPE_MANAGE_CREDENTIAL = 1;
export const GASLESS_TYPE_MANAGE_CREDENTIAL_PASSWORD = 2;
export const GASLESS_TYPE_ADD_WALLET = 3;
export const GASLESS_TYPE_ADD_WALLET_PASSWORD = 4;
export const GASLESS_TYPE_REMOVE_WALLET = 5;
export const GASLESS_TYPE_REMOVE_WALLET_PASSWORD = 6;

export const WALLET_TYPE_EVM = 0;
export const WALLET_TYPE_SUBSTRATE = 1;
export const WALLET_TYPE_BITCOIN = 2;