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
  ContractRunner,
  ContractMethod,
  Listener,
} from "ethers";
import type {
  TypedContractEvent,
  TypedDeferredTopicFilter,
  TypedEventLog,
  TypedListener,
  TypedContractMethod,
} from "../../common";

export type AuthenticatorDataFlagsStruct = {
  UP: boolean;
  UV: boolean;
  BE: boolean;
  BS: boolean;
  AT: boolean;
  ED: boolean;
};

export type AuthenticatorDataFlagsStructOutput = [
  UP: boolean,
  UV: boolean,
  BE: boolean,
  BS: boolean,
  AT: boolean,
  ED: boolean
] & {
  UP: boolean;
  UV: boolean;
  BE: boolean;
  BS: boolean;
  AT: boolean;
  ED: boolean;
};

export type AttestedCredentialDataStruct = {
  aaguid: BytesLike;
  credentialId: BytesLike;
  credentialPublicKey: BytesLike;
};

export type AttestedCredentialDataStructOutput = [
  aaguid: string,
  credentialId: string,
  credentialPublicKey: string
] & { aaguid: string; credentialId: string; credentialPublicKey: string };

export type AuthenticatorDataStruct = {
  rpIdHash: BytesLike;
  flags: AuthenticatorDataFlagsStruct;
  signCount: BigNumberish;
  attestedCredentialData: AttestedCredentialDataStruct;
};

export type AuthenticatorDataStructOutput = [
  rpIdHash: string,
  flags: AuthenticatorDataFlagsStructOutput,
  signCount: bigint,
  attestedCredentialData: AttestedCredentialDataStructOutput
] & {
  rpIdHash: string;
  flags: AuthenticatorDataFlagsStructOutput;
  signCount: bigint;
  attestedCredentialData: AttestedCredentialDataStructOutput;
};

export interface TestWebAuthNInterface extends Interface {
  getFunction(nameOrSignature: "testParseAuthData"): FunctionFragment;

  encodeFunctionData(
    functionFragment: "testParseAuthData",
    values: [BytesLike]
  ): string;

  decodeFunctionResult(
    functionFragment: "testParseAuthData",
    data: BytesLike
  ): Result;
}

export interface TestWebAuthN extends BaseContract {
  connect(runner?: ContractRunner | null): TestWebAuthN;
  waitForDeployment(): Promise<this>;

  interface: TestWebAuthNInterface;

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

  testParseAuthData: TypedContractMethod<
    [in_data: BytesLike],
    [AuthenticatorDataStructOutput],
    "view"
  >;

  getFunction<T extends ContractMethod = ContractMethod>(
    key: string | FunctionFragment
  ): T;

  getFunction(
    nameOrSignature: "testParseAuthData"
  ): TypedContractMethod<
    [in_data: BytesLike],
    [AuthenticatorDataStructOutput],
    "view"
  >;

  filters: {};
}
