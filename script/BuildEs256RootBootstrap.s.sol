// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {IUnivocity} from "@univocity/interfaces/IUnivocity.sol";
import {
    GF_AUTH_LOG,
    GF_CREATE,
    GF_EXTEND,
    GC_AUTH_LOG
} from "@univocity/interfaces/constants.sol";
import {buildSigStructure} from "@univocity/cosecbor/cosecbor.sol";
import {
    ConsistencyProof,
    ConsistencyReceipt,
    DelegationProof,
    InclusionProof,
    PublishGrant
} from "@univocity/interfaces/types.sol";

/// @title BuildEs256RootBootstrap
/// @notice Builds ES256 root bootstrap payload metadata (reference JSON).
contract BuildEs256RootBootstrap is Script {
    bytes32 internal constant AUTHORITY_LOG_ID = keccak256("authority-log");
    bytes8 internal constant IDTIMESTAMP_AUTH = bytes8(0);
    bytes internal constant PROTECTED_HEADER = hex"a10126";
    uint256 internal constant GRANT_ROOT = GF_CREATE | GF_EXTEND | GF_AUTH_LOG;

    function run() external {
        address univocity = vm.envAddress("IMUTABLE_UNIVOCITY_ADDRESS");
        bytes32 es256X = vm.envBytes32("ES256_X");
        bytes32 es256Y = vm.envBytes32("ES256_Y");

        PublishGrant memory grant = PublishGrant({
            logId: AUTHORITY_LOG_ID,
            grant: GRANT_ROOT,
            request: GC_AUTH_LOG,
            maxHeight: 0,
            minGrowth: 0,
            ownerLogId: bytes32(0),
            grantData: abi.encodePacked(es256X, es256Y)
        });

        bytes32 leaf0 = _leafCommitment(IDTIMESTAMP_AUTH, grant);
        bytes32[] memory accMem = _toAcc(leaf0);

        ConsistencyProof[] memory proofs = new ConsistencyProof[](1);
        proofs[0] = ConsistencyProof({
            treeSize1: 0,
            treeSize2: 1,
            paths: new bytes32[][](0),
            rightPeaks: accMem
        });

        bytes32 commitment = sha256(abi.encodePacked(accMem));
        bytes memory sigStruct =
            buildSigStructure(PROTECTED_HEADER, abi.encodePacked(commitment));

        ConsistencyReceipt memory receipt = ConsistencyReceipt({
            protectedHeader: PROTECTED_HEADER,
            signature: "",
            consistencyProofs: proofs,
            delegationProof: DelegationProof({
                protectedHeader: "",
                delegationKey: "",
                mmrStart: 0,
                mmrEnd: 0,
                signature: ""
            })
        });

        bytes memory publishCalldata = abi.encodeCall(
            IUnivocity.publishCheckpoint,
            (
                receipt,
                InclusionProof({index: 0, path: new bytes32[](0)}),
                IDTIMESTAMP_AUTH,
                grant
            )
        );

        console.log("ImutableUnivocity:", univocity);
        console.log("Authority logId:", vm.toString(AUTHORITY_LOG_ID));
        console.log("sigStruct sha256:", vm.toString(sha256(sigStruct)));
        console.log("publishCalldata length:", publishCalldata.length);

        if (vm.envOr("WRITE_ES256_BOOTSTRAP", false)) {
            string memory outDir = "deployments/es256";
            vm.createDir(outDir, true);
            string memory path = string.concat(
                outDir,
                "/root-bootstrap-payload-",
                vm.toString(block.chainid),
                ".json"
            );
            string memory json = string.concat(
                "{\n",
                '  "imutableUnivocity": "',
                vm.toString(univocity),
                '",\n',
                '  "authorityLogId": "',
                vm.toString(AUTHORITY_LOG_ID),
                '",\n',
                '  "protectedHeader": "',
                vm.toString(PROTECTED_HEADER),
                '",\n',
                '  "sigStructSha256": "',
                vm.toString(sha256(sigStruct)),
                '",\n',
                '  "grantData": "',
                vm.toString(abi.encodePacked(es256X, es256Y)),
                '",\n',
                '  "calldataUnsigned": "',
                vm.toString(publishCalldata),
                '"\n',
                "}\n"
            );
            vm.writeFile(path, json);
            console.log("Wrote:", path);
        }
    }

    function _leafCommitment(bytes8 grantIDTimestampBe, PublishGrant memory g)
        internal
        pure
        returns (bytes32)
    {
        bytes32 inner = sha256(
            abi.encodePacked(
                g.logId,
                g.grant,
                g.maxHeight,
                g.minGrowth,
                g.ownerLogId,
                g.grantData
            )
        );
        return sha256(abi.encodePacked(grantIDTimestampBe, inner));
    }

    function _toAcc(bytes32 peak)
        internal
        pure
        returns (bytes32[] memory accMem)
    {
        accMem = new bytes32[](1);
        accMem[0] = peak;
    }
}
