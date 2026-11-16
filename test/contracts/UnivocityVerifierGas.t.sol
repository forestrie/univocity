// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PublishedEnforcer} from "@univocity/contracts/PublishedEnforcer.sol";
import {
    UnivocityVerifierFactory
} from "@univocity/contracts/UnivocityVerifierFactory.sol";
import {ImutableVerifier} from "@univocity/contracts/ImutableVerifier.sol";
import {IUnivocal} from "@univocity/interfaces/IUnivocal.sol";
import {
    IUnivocityVerifier
} from "@univocity/interfaces/IUnivocityVerifier.sol";
import {ICaveatEnforcer} from "@univocity/interfaces/ICaveatEnforcer.sol";
import {mmrSizeForLeafCount} from "@univocity/algorithms/peaks.sol";
import {Mmr, MmrBuilder} from "../shared/MmrBuilder.sol";
import {StubUnivocal} from "../shared/StubUnivocal.sol";
import {GetterUnivocal} from "../shared/GetterUnivocal.sol";
import {
    ProvisionalDelegationStatement,
    SplitStatement
} from "../shared/ProvisionalDelegationStatement.sol";

/// @notice Cold-access gas of one published hop, as on the first touch of
///    an instance in a redemption: instance, verifier, factory and enforcer
///    are cooled before each measured call.
contract UnivocityVerifierGasTest is Test {
    using MmrBuilder for Mmr;
    using ProvisionalDelegationStatement for SplitStatement;

    bytes32 internal constant LOG = keccak256("log");
    bytes32 internal constant HOP = keccak256("hop");
    uint64 internal constant ID_TS = 0x0000019a2b3c4d5e;

    /// @dev Getter-path beforeHook ceilings: measured plus ~15%.
    uint256 internal constant CEILING_HOOK_SMALL = 39_000;
    uint256 internal constant CEILING_HOOK_LARGE = 79_700;

    UnivocityVerifierFactory internal factory;
    PublishedEnforcer internal enforcer;
    GetterUnivocal internal getterSrc;
    StubUnivocal internal plainSrc;
    IUnivocityVerifier internal viaGetter;
    IUnivocityVerifier internal viaFallback;
    ImutableVerifier internal oracle;
    SplitStatement internal st;

    function setUp() public {
        factory = new UnivocityVerifierFactory();
        enforcer = new PublishedEnforcer(factory);
        getterSrc = new GetterUnivocal();
        plainSrc = new StubUnivocal();
        viaGetter = IUnivocityVerifier(factory.deploy(address(getterSrc)));
        viaFallback = IUnivocityVerifier(factory.deploy(address(plainSrc)));
        oracle = new ImutableVerifier(IUnivocal(address(plainSrc)));
        st = ProvisionalDelegationStatement.split(84532);
    }

    function _cool() internal {
        vm.cool(address(getterSrc));
        vm.cool(address(plainSrc));
        vm.cool(address(viaGetter));
        vm.cool(address(viaFallback));
        vm.cool(address(oracle));
        vm.cool(address(factory));
        vm.cool(address(enforcer));
    }

    function _gas(address target, bytes memory data)
        internal
        returns (uint256 used)
    {
        _cool();
        uint256 before_ = gasleft();
        (bool ok, bytes memory ret) = target.staticcall(data);
        used = before_ - gasleft();
        assertTrue(ok);
        if (
            data.length > 4
                && bytes4(data) != ICaveatEnforcer.beforeHook.selector
        ) {
            assertEq(abi.decode(ret, (bool)), true);
        }
    }

    function _measure(string memory label, uint256 leaves, uint256 at)
        internal
        returns (uint256 hookGetter)
    {
        Mmr memory m = MmrBuilder.create(2 * leaves + 64);
        bytes32 target = st.leafFor(enforcer.DELEGATION_TAG(), HOP, ID_TS);
        uint256 index;
        for (uint256 i = 0; i < leaves; i++) {
            uint256 ix = m.append(i == at ? target : sha256(abi.encode(i)));
            if (i == at) index = ix;
        }
        uint256 size = mmrSizeForLeafCount(leaves);
        bytes32[] memory acc = m.accumulatorAt(size);
        // forge-lint: disable-next-line(unsafe-typecast)
        getterSrc.setLogState(LOG, acc, uint64(size));
        // forge-lint: disable-next-line(unsafe-typecast)
        plainSrc.setLogState(LOG, acc, uint64(size));
        bytes32[] memory path = m.pathAt(index, size);

        bytes memory call = abi.encodeCall(
            IUnivocityVerifier.verifyInclusionAtAnchored,
            (LOG, index, target, path)
        );
        uint256 g = _gas(address(viaGetter), call);
        uint256 f = _gas(address(viaFallback), call);
        uint256 o = _gas(address(oracle), call);
        emit log_named_uint(string.concat(label, " verifier getter"), g);
        emit log_named_uint(string.concat(label, " verifier fallback"), f);
        emit log_named_uint(string.concat(label, " verifier oracle"), o);
        assertLt(g, f);

        bytes memory args = abi.encode(
            PublishedEnforcer.PublishedArgs({
                prefix: st.prefix,
                suffix: st.suffix,
                idTimestamp: ID_TS,
                mmrIndex: index,
                path: path
            })
        );
        hookGetter = _gas(
            address(enforcer),
            abi.encodeCall(
                ICaveatEnforcer.beforeHook,
                (
                    abi.encode(address(getterSrc), LOG),
                    args,
                    bytes32(0),
                    "",
                    HOP,
                    address(0),
                    address(0)
                )
            )
        );
        uint256 hookFallback = _gas(
            address(enforcer),
            abi.encodeCall(
                ICaveatEnforcer.beforeHook,
                (
                    abi.encode(address(plainSrc), LOG),
                    args,
                    bytes32(0),
                    "",
                    HOP,
                    address(0),
                    address(0)
                )
            )
        );
        emit log_named_uint(
            string.concat(label, " beforeHook getter"), hookGetter
        );
        emit log_named_uint(
            string.concat(label, " beforeHook fallback"), hookFallback
        );
        assertLt(hookGetter, hookFallback);
    }

    function test_gas_smallLog() public {
        uint256 g = _measure("small(7 leaves)", 7, 5);
        assertLt(g, CEILING_HOOK_SMALL);
    }

    function test_gas_1023Leaves() public {
        uint256 g = _measure("1023 leaves", 1023, 0);
        assertLt(g, CEILING_HOOK_LARGE);
    }
}
