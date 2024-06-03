/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import type {
  BaseContract,
  BigNumberish,
  BytesLike,
  FunctionFragment,
  Result,
  Interface,
  EventFragment,
  AddressLike,
  ContractRunner,
  ContractMethod,
  Listener,
} from "ethers";
import type {
  TypedContractEvent,
  TypedDeferredTopicFilter,
  TypedEventLog,
  TypedLogDescription,
  TypedListener,
  TypedContractMethod,
} from "../../common";

export type CosePublicKeyStruct = {
  kty: BigNumberish;
  alg: BigNumberish;
  crv: BigNumberish;
  x: BigNumberish;
  y: BigNumberish;
};

export type CosePublicKeyStructOutput = [
  kty: bigint,
  alg: bigint,
  crv: bigint,
  x: bigint,
  y: bigint
] & { kty: bigint; alg: bigint; crv: bigint; x: bigint; y: bigint };

export type AuthenticatorResponseStruct = {
  authenticatorData: BytesLike;
  clientDataTokens: MakeJSON.KeyValueStruct[];
  sigR: BigNumberish;
  sigS: BigNumberish;
};

export type AuthenticatorResponseStructOutput = [
  authenticatorData: string,
  clientDataTokens: MakeJSON.KeyValueStructOutput[],
  sigR: bigint,
  sigS: bigint
] & {
  authenticatorData: string;
  clientDataTokens: MakeJSON.KeyValueStructOutput[];
  sigR: bigint;
  sigS: bigint;
};

export declare namespace AccountManager {
  export type NewAccountStruct = {
    hashedUsername: BytesLike;
    credentialId: BytesLike;
    pubkey: CosePublicKeyStruct;
    optionalPassword: BytesLike;
  };

  export type NewAccountStructOutput = [
    hashedUsername: string,
    credentialId: string,
    pubkey: CosePublicKeyStructOutput,
    optionalPassword: string
  ] & {
    hashedUsername: string;
    credentialId: string;
    pubkey: CosePublicKeyStructOutput;
    optionalPassword: string;
  };

  export type ManageCredStruct = {
    credentialIdHashed: BytesLike;
    resp: AuthenticatorResponseStruct;
    data: BytesLike;
  };

  export type ManageCredStructOutput = [
    credentialIdHashed: string,
    resp: AuthenticatorResponseStructOutput,
    data: string
  ] & {
    credentialIdHashed: string;
    resp: AuthenticatorResponseStructOutput;
    data: string;
  };

  export type ManageCredPassStruct = { digest: BytesLike; data: BytesLike };

  export type ManageCredPassStructOutput = [digest: string, data: string] & {
    digest: string;
    data: string;
  };
}

export declare namespace MakeJSON {
  export type KeyValueStruct = { t: BigNumberish; k: string; v: string };

  export type KeyValueStructOutput = [t: bigint, k: string, v: string] & {
    t: bigint;
    k: string;
    v: string;
  };
}

export interface AccountManagerInterface extends Interface {
  getFunction(
    nameOrSignature:
      | "createAccount"
      | "credentialIdsByUsername"
      | "devAddress"
      | "encryptedTx"
      | "gaspayingAddress"
      | "generateGaslessTx"
      | "getAccount"
      | "manageCredential"
      | "manageCredentialPassword"
      | "personalization"
      | "proxyView"
      | "proxyViewPassword"
      | "salt"
      | "setSigner"
      | "signer"
      | "userExists"
      | "validateSignature"
  ): FunctionFragment;

  getEvent(nameOrSignatureOrTopic: "GaslessTransaction"): EventFragment;

  encodeFunctionData(
    functionFragment: "createAccount",
    values: [AccountManager.NewAccountStruct]
  ): string;
  encodeFunctionData(
    functionFragment: "credentialIdsByUsername",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "devAddress",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "encryptedTx",
    values: [BytesLike, BytesLike, BigNumberish, BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "gaspayingAddress",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "generateGaslessTx",
    values: [BytesLike, BigNumberish, BigNumberish, BigNumberish, BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "getAccount",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "manageCredential",
    values: [AccountManager.ManageCredStruct]
  ): string;
  encodeFunctionData(
    functionFragment: "manageCredentialPassword",
    values: [AccountManager.ManageCredPassStruct]
  ): string;
  encodeFunctionData(
    functionFragment: "personalization",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "proxyView",
    values: [BytesLike, AuthenticatorResponseStruct, BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "proxyViewPassword",
    values: [BytesLike, BytesLike, BytesLike]
  ): string;
  encodeFunctionData(functionFragment: "salt", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "setSigner",
    values: [AddressLike]
  ): string;
  encodeFunctionData(functionFragment: "signer", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "userExists",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "validateSignature",
    values: [BigNumberish, BigNumberish, BytesLike, BytesLike]
  ): string;

  decodeFunctionResult(
    functionFragment: "createAccount",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "credentialIdsByUsername",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "devAddress", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "encryptedTx",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "gaspayingAddress",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "generateGaslessTx",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "getAccount", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "manageCredential",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "manageCredentialPassword",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "personalization",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "proxyView", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "proxyViewPassword",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "salt", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "setSigner", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "signer", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "userExists", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "validateSignature",
    data: BytesLike
  ): Result;
}

export namespace GaslessTransactionEvent {
  export type InputTuple = [
    dataHash: BytesLike,
    hashedUsername: BytesLike,
    publicAddress: AddressLike
  ];
  export type OutputTuple = [
    dataHash: string,
    hashedUsername: string,
    publicAddress: string
  ];
  export interface OutputObject {
    dataHash: string;
    hashedUsername: string;
    publicAddress: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export interface AccountManager extends BaseContract {
  connect(runner?: ContractRunner | null): AccountManager;
  waitForDeployment(): Promise<this>;

  interface: AccountManagerInterface;

  queryFilter<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TypedEventLog<TCEvent>>>;
  queryFilter<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TypedEventLog<TCEvent>>>;

  on<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    listener: TypedListener<TCEvent>
  ): Promise<this>;
  on<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    listener: TypedListener<TCEvent>
  ): Promise<this>;

  once<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    listener: TypedListener<TCEvent>
  ): Promise<this>;
  once<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    listener: TypedListener<TCEvent>
  ): Promise<this>;

  listeners<TCEvent extends TypedContractEvent>(
    event: TCEvent
  ): Promise<Array<TypedListener<TCEvent>>>;
  listeners(eventName?: string): Promise<Array<Listener>>;
  removeAllListeners<TCEvent extends TypedContractEvent>(
    event?: TCEvent
  ): Promise<this>;

  createAccount: TypedContractMethod<
    [args: AccountManager.NewAccountStruct],
    [void],
    "nonpayable"
  >;

  credentialIdsByUsername: TypedContractMethod<
    [in_hashedUsername: BytesLike],
    [string[]],
    "view"
  >;

  devAddress: TypedContractMethod<[], [string], "view">;

  encryptedTx: TypedContractMethod<
    [
      nonce: BytesLike,
      ciphertext: BytesLike,
      timestamp: BigNumberish,
      dataHash: BytesLike
    ],
    [void],
    "nonpayable"
  >;

  gaspayingAddress: TypedContractMethod<[], [string], "view">;

  generateGaslessTx: TypedContractMethod<
    [
      in_data: BytesLike,
      nonce: BigNumberish,
      gasPrice: BigNumberish,
      timestamp: BigNumberish,
      signature: BytesLike
    ],
    [string],
    "view"
  >;

  getAccount: TypedContractMethod<
    [in_username: BytesLike],
    [[string, string] & { account: string; keypairAddress: string }],
    "view"
  >;

  manageCredential: TypedContractMethod<
    [args: AccountManager.ManageCredStruct],
    [void],
    "nonpayable"
  >;

  manageCredentialPassword: TypedContractMethod<
    [args: AccountManager.ManageCredPassStruct],
    [void],
    "nonpayable"
  >;

  personalization: TypedContractMethod<[], [string], "view">;

  proxyView: TypedContractMethod<
    [
      in_credentialIdHashed: BytesLike,
      in_resp: AuthenticatorResponseStruct,
      in_data: BytesLike
    ],
    [string],
    "view"
  >;

  proxyViewPassword: TypedContractMethod<
    [in_hashedUsername: BytesLike, in_digest: BytesLike, in_data: BytesLike],
    [string],
    "view"
  >;

  salt: TypedContractMethod<[], [string], "view">;

  setSigner: TypedContractMethod<[_signer: AddressLike], [void], "nonpayable">;

  userExists: TypedContractMethod<[in_username: BytesLike], [boolean], "view">;

  validateSignature: TypedContractMethod<
    [
      _gasPrice: BigNumberish,
      _timestamp: BigNumberish,
      _dataKeccak: BytesLike,
      _signature: BytesLike
    ],
    [[string, boolean]],
    "view"
  >;

  getFunction<T extends ContractMethod = ContractMethod>(
    key: string | FunctionFragment
  ): T;

  getFunction(
    nameOrSignature: "createAccount"
  ): TypedContractMethod<
    [args: AccountManager.NewAccountStruct],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "credentialIdsByUsername"
  ): TypedContractMethod<[in_hashedUsername: BytesLike], [string[]], "view">;
  getFunction(
    nameOrSignature: "devAddress"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "encryptedTx"
  ): TypedContractMethod<
    [
      nonce: BytesLike,
      ciphertext: BytesLike,
      timestamp: BigNumberish,
      dataHash: BytesLike
    ],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "gaspayingAddress"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "generateGaslessTx"
  ): TypedContractMethod<
    [
      in_data: BytesLike,
      nonce: BigNumberish,
      gasPrice: BigNumberish,
      timestamp: BigNumberish,
      signature: BytesLike
    ],
    [string],
    "view"
  >;
  getFunction(
    nameOrSignature: "getAccount"
  ): TypedContractMethod<
    [in_username: BytesLike],
    [[string, string] & { account: string; keypairAddress: string }],
    "view"
  >;
  getFunction(
    nameOrSignature: "manageCredential"
  ): TypedContractMethod<
    [args: AccountManager.ManageCredStruct],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "manageCredentialPassword"
  ): TypedContractMethod<
    [args: AccountManager.ManageCredPassStruct],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "personalization"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "proxyView"
  ): TypedContractMethod<
    [
      in_credentialIdHashed: BytesLike,
      in_resp: AuthenticatorResponseStruct,
      in_data: BytesLike
    ],
    [string],
    "view"
  >;
  getFunction(
    nameOrSignature: "proxyViewPassword"
  ): TypedContractMethod<
    [in_hashedUsername: BytesLike, in_digest: BytesLike, in_data: BytesLike],
    [string],
    "view"
  >;
  getFunction(
    nameOrSignature: "salt"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "setSigner"
  ): TypedContractMethod<[_signer: AddressLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "signer"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "userExists"
  ): TypedContractMethod<[in_username: BytesLike], [boolean], "view">;
  getFunction(
    nameOrSignature: "validateSignature"
  ): TypedContractMethod<
    [
      _gasPrice: BigNumberish,
      _timestamp: BigNumberish,
      _dataKeccak: BytesLike,
      _signature: BytesLike
    ],
    [[string, boolean]],
    "view"
  >;

  getEvent(
    key: "GaslessTransaction"
  ): TypedContractEvent<
    GaslessTransactionEvent.InputTuple,
    GaslessTransactionEvent.OutputTuple,
    GaslessTransactionEvent.OutputObject
  >;

  filters: {
    "GaslessTransaction(bytes32,bytes32,address)": TypedContractEvent<
      GaslessTransactionEvent.InputTuple,
      GaslessTransactionEvent.OutputTuple,
      GaslessTransactionEvent.OutputObject
    >;
    GaslessTransaction: TypedContractEvent<
      GaslessTransactionEvent.InputTuple,
      GaslessTransactionEvent.OutputTuple,
      GaslessTransactionEvent.OutputObject
    >;
  };
}
