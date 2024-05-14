/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import {
  Contract,
  ContractFactory,
  ContractTransactionResponse,
  Interface,
} from "ethers";
import type {
  Signer,
  AddressLike,
  ContractDeployTransaction,
  ContractRunner,
} from "ethers";
import type { NonPayableOverrides } from "../../common";
import type {
  DummyToken,
  DummyTokenInterface,
} from "../../contracts/DummyToken";

const _abi = [
  {
    inputs: [
      {
        internalType: "string",
        name: "name",
        type: "string",
      },
      {
        internalType: "string",
        name: "symbol",
        type: "string",
      },
      {
        internalType: "address",
        name: "_receiver",
        type: "address",
      },
    ],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "spender",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "allowance",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "needed",
        type: "uint256",
      },
    ],
    name: "ERC20InsufficientAllowance",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "sender",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "balance",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "needed",
        type: "uint256",
      },
    ],
    name: "ERC20InsufficientBalance",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "approver",
        type: "address",
      },
    ],
    name: "ERC20InvalidApprover",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "receiver",
        type: "address",
      },
    ],
    name: "ERC20InvalidReceiver",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "sender",
        type: "address",
      },
    ],
    name: "ERC20InvalidSender",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "spender",
        type: "address",
      },
    ],
    name: "ERC20InvalidSpender",
    type: "error",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "owner",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "spender",
        type: "address",
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "value",
        type: "uint256",
      },
    ],
    name: "Approval",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "from",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "value",
        type: "uint256",
      },
    ],
    name: "Transfer",
    type: "event",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "owner",
        type: "address",
      },
      {
        internalType: "address",
        name: "spender",
        type: "address",
      },
    ],
    name: "allowance",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "spender",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "value",
        type: "uint256",
      },
    ],
    name: "approve",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "account",
        type: "address",
      },
    ],
    name: "balanceOf",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "decimals",
    outputs: [
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
    ],
    stateMutability: "pure",
    type: "function",
  },
  {
    inputs: [],
    name: "maxSupply",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "name",
    outputs: [
      {
        internalType: "string",
        name: "",
        type: "string",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "symbol",
    outputs: [
      {
        internalType: "string",
        name: "",
        type: "string",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "totalSupply",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "value",
        type: "uint256",
      },
    ],
    name: "transfer",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "from",
        type: "address",
      },
      {
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "value",
        type: "uint256",
      },
    ],
    name: "transferFrom",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x60406080815234620003bd5762000b2a803803806200001e81620003c2565b9283398101606082820312620003bd5781516001600160401b039290838111620003bd578262000050918301620003e8565b60209283830151858111620003bd5786916200006e918501620003e8565b9201516001600160a01b0381169490859003620003bd578151818111620002bd576003908154906001948583811c93168015620003b2575b888410146200039c578190601f9384811162000346575b508890848311600114620002df57600092620002d3575b505060001982851b1c191690851b1782555b8451928311620002bd5760049485548581811c91168015620002b2575b888210146200029d5782811162000252575b5086918411600114620001e757938394918492600095620001db575b50501b92600019911b1c19161781555b8215620001c4576002546a52b7d2dcc80cd2e400000091828201809211620001af575060025560008381528083528481208054830190558451918252917fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef91a3516106cf90816200045b8239f35b601190634e487b7160e01b6000525260246000fd5b602490600085519163ec442f0560e01b8352820152fd5b01519350388062000131565b9190601f198416928660005284886000209460005b8a898383106200023a57505050106200021f575b50505050811b01815562000141565b01519060f884600019921b161c191690553880808062000210565b868601518955909701969485019488935001620001fc565b86600052876000208380870160051c8201928a881062000293575b0160051c019086905b8281106200028657505062000115565b6000815501869062000276565b925081926200026d565b602287634e487b7160e01b6000525260246000fd5b90607f169062000103565b634e487b7160e01b600052604160045260246000fd5b015190503880620000d4565b90879350601f19831691866000528a6000209260005b8c8282106200032f575050841162000316575b505050811b018255620000e6565b015160001983871b60f8161c1916905538808062000308565b8385015186558b97909501949384019301620002f5565b90915084600052886000208480850160051c8201928b861062000392575b918991869594930160051c01915b82811062000382575050620000bd565b6000815585945089910162000372565b9250819262000364565b634e487b7160e01b600052602260045260246000fd5b92607f1692620000a6565b600080fd5b6040519190601f01601f191682016001600160401b03811183821017620002bd57604052565b919080601f84011215620003bd5782516001600160401b038111620002bd576020906200041e601f8201601f19168301620003c2565b92818452828287010111620003bd5760005b8181106200044657508260009394955001015290565b85810183015184820184015282016200043056fe608060408181526004918236101561001657600080fd5b600092833560e01c91826306fdde031461046957508163095ea7b3146103bb57816318160ddd1461039c57816323b872dd146102a5578163313ce5671461028957816370a082311461025257816395d89b411461013357508063a9059cbb14610103578063d5abeb01146100de5763dd62ed3e1461009357600080fd5b346100da57806003193601126100da57806020926100af61058a565b6100b76105a5565b6001600160a01b0391821683526001865283832091168252845220549051908152f35b5080fd5b50346100da57816003193601126100da57602090516a52b7d2dcc80cd2e40000008152f35b50346100da57806003193601126100da5760209061012c61012261058a565b60243590336105bb565b5160018152f35b8383346100da57816003193601126100da57805190828454600181811c90808316928315610248575b60209384841081146102355783885290811561021957506001146101c4575b505050829003601f01601f191682019267ffffffffffffffff8411838510176101b157508291826101ad925282610541565b0390f35b634e487b7160e01b815260418552602490fd5b8787529192508591837f8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b5b838510610205575050505083010185808061017b565b8054888601830152930192849082016101ef565b60ff1916878501525050151560051b840101905085808061017b565b634e487b7160e01b895260228a52602489fd5b91607f169161015c565b5050346100da5760203660031901126100da5760209181906001600160a01b0361027a61058a565b16815280845220549051908152f35b5050346100da57816003193601126100da576020905160128152f35b90508234610399576060366003190112610399576102c161058a565b6102c96105a5565b916044359360018060a01b038316808352600160205286832033845260205286832054916000198303610305575b60208861012c8989896105bb565b86831061036d57811561035657331561033f5750825260016020908152868320338452815291869020908590039055829061012c876102f7565b8751634a1406b160e11b8152908101849052602490fd5b875163e602df0560e01b8152908101849052602490fd5b8751637dc7a0d960e11b8152339181019182526020820193909352604081018790528291506060010390fd5b80fd5b5050346100da57816003193601126100da576020906002549051908152f35b9050346104655781600319360112610465576103d561058a565b60243590331561044e576001600160a01b031691821561043757508083602095338152600187528181208582528752205582519081527f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925843392a35160018152f35b8351634a1406b160e11b8152908101859052602490fd5b835163e602df0560e01b8152808401869052602490fd5b8280fd5b8490843461046557826003193601126104655782600354600181811c90808316928315610537575b60209384841081146102355783885290811561021957506001146104e157505050829003601f01601f191682019267ffffffffffffffff8411838510176101b157508291826101ad925282610541565b600387529192508591837fc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b5b838510610523575050505083010185808061017b565b80548886018301529301928490820161050d565b91607f1691610491565b6020808252825181830181905290939260005b82811061057657505060409293506000838284010152601f8019910116010190565b818101860151848201604001528501610554565b600435906001600160a01b03821682036105a057565b600080fd5b602435906001600160a01b03821682036105a057565b916001600160a01b0380841692831561068057169283156106675760009083825281602052604082205490838210610635575091604082827fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef958760209652828652038282205586815220818154019055604051908152a3565b60405163391434e360e21b81526001600160a01b03919091166004820152602481019190915260448101839052606490fd5b60405163ec442f0560e01b815260006004820152602490fd5b604051634b637e8f60e11b815260006004820152602490fdfea264697066735822122037fdab60dcaaaa09798e3f0eb3dc8c12361dbc9f44e8e4cdde310dcecec1247664736f6c63430008150033";

type DummyTokenConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: DummyTokenConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class DummyToken__factory extends ContractFactory {
  constructor(...args: DummyTokenConstructorParams) {
    if (isSuperArgs(args)) {
      super(...args);
    } else {
      super(_abi, _bytecode, args[0]);
    }
  }

  override getDeployTransaction(
    name: string,
    symbol: string,
    _receiver: AddressLike,
    overrides?: NonPayableOverrides & { from?: string }
  ): Promise<ContractDeployTransaction> {
    return super.getDeployTransaction(name, symbol, _receiver, overrides || {});
  }
  override deploy(
    name: string,
    symbol: string,
    _receiver: AddressLike,
    overrides?: NonPayableOverrides & { from?: string }
  ) {
    return super.deploy(name, symbol, _receiver, overrides || {}) as Promise<
      DummyToken & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(runner: ContractRunner | null): DummyToken__factory {
    return super.connect(runner) as DummyToken__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): DummyTokenInterface {
    return new Interface(_abi) as DummyTokenInterface;
  }
  static connect(address: string, runner?: ContractRunner | null): DummyToken {
    return new Contract(address, _abi, runner) as unknown as DummyToken;
  }
}