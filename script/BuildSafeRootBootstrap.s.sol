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

/// @title BuildSafeRootBootstrap
/// @notice Builds root `publishCheckpoint` calldata for an ImutableUnivocity whose
///    KS256 bootstrap signer is a Safe. Emits JSON for `ROOT_BOOTSTRAP_JSON` and a
///    two-step Safe batch (signMessage then publishCheckpoint).
contract BuildSafeRootBootstrap is Script {
    address internal constant DEFAULT_SAFE =
        0x1528b86ff561f617602356efdbD05908a07AA788;
    address internal constant DEFAULT_UNIVOCITY =
        0x611dd70B2D36c87B29878089eD8a7aDc68E4441B;
    address internal constant SIGN_MESSAGE_LIB =
        0xd53cd0aB83D845Ac265BE939c57F53AD838012c9;

    bytes32 internal constant AUTHORITY_LOG_ID =
        keccak256("authority-log");
    bytes8 internal constant IDTIMESTAMP_AUTH = bytes8(0);
    bytes internal constant PROTECTED_HEADER = hex"a1013a00010106";
    uint256 internal constant GRANT_ROOT = GF_CREATE | GF_EXTEND | GF_AUTH_LOG;

    function run() external {
        address safe = vm.envOr("SAFE_ADDRESS", DEFAULT_SAFE);
        address univocity = vm.envOr("IMUTABLE_UNIVOCITY_ADDRESS", DEFAULT_UNIVOCITY);
        address signMessageLib =
            vm.envOr("SIGN_MESSAGE_LIB_ADDRESS", SIGN_MESSAGE_LIB);

        (, , bytes32 receiptHash, bytes memory publishCalldata) =
            _buildBootstrapPayload(safe);

        bytes memory signMessageData = abi.encode(receiptHash);
        bytes memory signMessageCalldata =
            abi.encodeCall(ISignMessageLib.signMessage, (signMessageData));

        string memory payloadJson = _payloadJson(
            safe,
            univocity,
            signMessageLib,
            receiptHash,
            signMessageData,
            signMessageCalldata,
            publishCalldata
        );

        string memory batchJson = _safeBatchJson(
            block.chainid,
            block.timestamp * 1000,
            safe,
            signMessageLib,
            univocity,
            signMessageCalldata,
            publishCalldata,
            1,
            0
        );

        console.log("Safe:", safe);
        console.log("ImutableUnivocity:", univocity);
        console.log("Authority logId:", vm.toString(AUTHORITY_LOG_ID));
        console.log("Receipt hash (KS256 / ERC-1271):", vm.toString(receiptHash));
        console.log("SignMessageLib:", signMessageLib);
        console.log("publishCheckpoint calldata length:", publishCalldata.length);
        console.log("Payload JSON:");
        console.log(payloadJson);
        console.log("Safe batch JSON:");
        console.log(batchJson);

        string memory outDir = "deployments/safe";
        string memory payloadPath = string.concat(
            outDir,
            "/root-bootstrap-payload-",
            vm.toString(block.chainid),
            ".json"
        );
        string memory batchPath = string.concat(
            outDir,
            "/imutable-univocity-bootstrap-",
            vm.toString(block.chainid),
            "-safe-",
            vm.toString(safe),
            ".json"
        );

        if (vm.envOr("WRITE_SAFE_BATCH", false)) {
            vm.createDir(outDir, true);
            vm.writeFile(payloadPath, payloadJson);
            vm.writeFile(batchPath, batchJson);
            console.log("Wrote:", payloadPath);
            console.log("Wrote:", batchPath);
        }
    }

    function _buildBootstrapPayload(address safe)
        public
        pure
        returns (
            PublishGrant memory grant,
            ConsistencyReceipt memory receipt,
            bytes32 receiptHash,
            bytes memory publishCalldata
        )
    {
        grant = PublishGrant({
            logId: AUTHORITY_LOG_ID,
            grant: GRANT_ROOT,
            request: GC_AUTH_LOG,
            maxHeight: 0,
            minGrowth: 0,
            ownerLogId: bytes32(0),
            grantData: abi.encodePacked(safe)
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
        bytes memory sigStruct = buildSigStructure(
            PROTECTED_HEADER, abi.encodePacked(commitment)
        );
        receiptHash = keccak256(sigStruct);

        receipt = ConsistencyReceipt({
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

        publishCalldata = abi.encodeCall(
            IUnivocity.publishCheckpoint,
            (
                receipt,
                InclusionProof({index: 0, path: new bytes32[](0)}),
                IDTIMESTAMP_AUTH,
                grant
            )
        );
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

    function _payloadJson(
        address safe,
        address univocity,
        address signMessageLib,
        bytes32 receiptHash,
        bytes memory signMessageData,
        bytes memory signMessageCalldata,
        bytes memory publishCalldata
    ) internal pure returns (string memory) {
        return string.concat(
            "{\n",
            '  "safe": "',
            vm.toString(safe),
            '",\n',
            '  "imutableUnivocity": "',
            vm.toString(univocity),
            '",\n',
            '  "authorityLogId": "',
            vm.toString(AUTHORITY_LOG_ID),
            '",\n',
            '  "receiptHash": "',
            vm.toString(receiptHash),
            '",\n',
            '  "signMessageLib": "',
            vm.toString(signMessageLib),
            '",\n',
            '  "signMessageData": "',
            vm.toString(signMessageData),
            '",\n',
            '  "signMessageCalldata": "',
            vm.toString(signMessageCalldata),
            '",\n',
            '  "calldata": "',
            vm.toString(publishCalldata),
            '"\n',
            "}\n"
        );
    }

    function _safeBatchJson(
        uint256 chainId,
        uint256 createdAt,
        address safe,
        address signMessageLib,
        address univocity,
        bytes memory signMessageCalldata,
        bytes memory publishCalldata,
        uint8 signMessageOperation,
        uint8 publishOperation
    ) internal pure returns (string memory) {
        return string.concat(
            "{\n",
            '  "version": "1.0",\n',
            '  "chainId": "',
            vm.toString(chainId),
            '",\n',
            '  "createdAt": ',
            vm.toString(createdAt),
            ",\n",
            '  "meta": {\n',
            '    "name": "Bootstrap ImutableUnivocity root auth log",\n',
            '    "description": "DelegateCall SignMessageLib then publish root checkpoint",\n',
            '    "txBuilderVersion": "1.18.0",\n',
            '    "createdFromSafeAddress": "',
            vm.toString(safe),
            '",\n',
            '    "createdFromOwnerAddress": "",\n',
            '    "checksum": ""\n',
            "  },\n",
            '  "transactions": [\n',
            _transactionJson(signMessageLib, signMessageCalldata, signMessageOperation),
            ",\n",
            _transactionJson(univocity, publishCalldata, publishOperation),
            "\n  ]\n",
            "}\n"
        );
    }

    function _transactionJson(address to, bytes memory data, uint8 operation)
        internal
        pure
        returns (string memory)
    {
        return string.concat(
            "    {\n",
            '      "to": "',
            vm.toString(to),
            '",\n',
            '      "value": "0",\n',
            '      "data": "',
            vm.toString(data),
            '",\n',
            '      "operation": ',
            vm.toString(operation),
            ",\n",
            '      "baseGas": "0",\n',
            '      "gasPrice": "0",\n',
            '      "gasToken": "0x0000000000000000000000000000000000000000",\n',
            '      "refundReceiver": "0x0000000000000000000000000000000000000000",\n',
            '      "nonce": 0,\n',
            '      "safeTxGas": "0"\n',
            "    }"
        );
    }
}

interface ISignMessageLib {
    function signMessage(bytes memory message) external;
}
