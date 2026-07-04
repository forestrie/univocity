// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {
    buildDetachedPayloadCommitment
} from "@univocity/checkpoints/lib/consistencyReceipt.sol";

/// @notice Pins the consistency-receipt detached payload encoding (ADR-0046,
///    FOR-321): the raw concatenation of the accumulator peaks in descending
///    height order — matching the draft-bryce inclusion-receipt raw-value
///    convention. No hashing. A publisher signs, and the contract verifies,
///    over exactly these bytes.
contract ConsistencyReceiptPayloadTest is Test {
    function test_singlePeakPayloadIsTheRawPeak() public pure {
        bytes32 p0 = keccak256("peak-0");
        bytes32[] memory acc = new bytes32[](1);
        acc[0] = p0;

        bytes memory payload = buildDetachedPayloadCommitment(acc);

        assertEq(payload.length, 32, "single-peak payload is 32 bytes");
        assertEq(payload, abi.encodePacked(p0), "payload is the raw peak");
    }

    function test_twoPeakPayloadIsRawConcatInOrder() public pure {
        bytes32 p0 = keccak256("peak-0");
        bytes32 p1 = keccak256("peak-1");
        bytes32[] memory acc = new bytes32[](2);
        acc[0] = p0;
        acc[1] = p1;

        bytes memory payload = buildDetachedPayloadCommitment(acc);

        assertEq(payload.length, 64, "two-peak payload is 64 bytes");
        assertEq(
            payload, abi.encodePacked(p0, p1), "payload is concat(p0, p1)"
        );
    }

    /// @notice Regression guard: the payload must not revert to a 32-byte
    ///    SHA-256 commitment over the accumulator (the pre-ADR-0046 form).
    function test_payloadIsNotHashed() public pure {
        bytes32[] memory acc = new bytes32[](2);
        acc[0] = keccak256("peak-0");
        acc[1] = keccak256("peak-1");

        bytes memory payload = buildDetachedPayloadCommitment(acc);

        assertTrue(payload.length != 32, "not a 32-byte hash commitment");
        assertTrue(
            keccak256(payload)
                != keccak256(abi.encodePacked(sha256(abi.encodePacked(acc)))),
            "payload must be raw concat, not sha256(concat)"
        );
    }
}
