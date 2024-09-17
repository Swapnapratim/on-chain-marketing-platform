// SPDX-License-Identifier: MIT
pragma solidity >=0.8.20;

contract SigUtils {

    struct Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }
}
