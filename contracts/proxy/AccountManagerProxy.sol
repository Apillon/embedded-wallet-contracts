// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract AccountManagerProxy is ERC1967Proxy {
    constructor(address _impl, bytes memory _data) ERC1967Proxy(_impl, _data) payable {}
}