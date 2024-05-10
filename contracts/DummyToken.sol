// SPDX-License-Identifier: MIT

pragma solidity 0.8.21;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract DummyToken is ERC20 {
    uint256 public constant maxSupply = 100_000_000 * 1e18;

    constructor(
        string memory name, 
        string memory symbol,
        address _receiver
    ) ERC20(name, symbol) {
        _mint(_receiver, maxSupply);
    }

    function decimals() public pure override returns (uint8) {
        return 18;
    }
}
