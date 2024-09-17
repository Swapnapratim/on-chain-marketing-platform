// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FunctionsResponse} from "@chainlink/contracts/src/v0.8/functions/dev/v1_0_0/libraries/FunctionsResponse.sol";
import {FunctionsClient} from "@chainlink/contracts/src/v0.8/functions/dev/v1_0_0/FunctionsClient.sol";

contract MockFunctionsRouter {
    using FunctionsResponse for FunctionsResponse.Commitment;
    using FunctionsResponse for FunctionsResponse.FulfillResult;

    event FunctionsRequestSent(
        bytes32 indexed requestId,
        uint64 subscriptionId,
        bytes data,
        uint16 dataVersion,
        uint32 callbackGasLimit,
        bytes32 donId
    );

    function sendRequest(
        uint64 subscriptionId,
        bytes calldata data,
        uint16 dataVersion,
        uint32 callbackGasLimit,
        bytes32 donId
    ) external pure returns (bytes32) {
        // Return a bytes32 value to simulate a request ID
        return bytes32(uint256(keccak256(abi.encodePacked(subscriptionId, data, dataVersion, callbackGasLimit, donId))));
    }

    function fulfill(
        address client,
        bytes32 requestId,
        bytes memory response,
        bytes memory err
    ) external {
        FunctionsClient(client).handleOracleFulfillment(requestId, response, err);
    }
}
