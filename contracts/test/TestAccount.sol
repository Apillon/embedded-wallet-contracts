// SPDX-License-Identifier: CC-PDDC

pragma solidity ^0.8.0;

import {WalletType} from "../AccountFactory.sol";

import {IAccountFactory} from "../interfaces/IAccountFactory.sol";
import {IAccount} from "../interfaces/IAccount.sol";

contract TestAccount {
    IAccountFactory private factory;
    event CloneCreated(address addr);
    
    constructor(address _factory) {
        factory = IAccountFactory(_factory);
    }
    
    function testClone(address controller)
        public
    {
        IAccount acct = IAccount(
            factory.clone(controller, WalletType.EVM, bytes32(0))
        );
        emit CloneCreated(address(acct));
    }
}
