"""Tests for scripts/canopy_payment_check.py, the stand-in canopy check.

The receipt vectors under test/fixtures/delegated-spend/ come from
test/integration/PaymentBindingFork.t.sol, redeemed against the
Delegation Framework v1.3.0 bytecode on a Base Sepolia fork. Each names
the outcome a request for each of its purposes must get.
"""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from canopy_payment_check import (  # noqa: E402
    AUTHORIZATION_USED_TOPIC,
    MAX_RELEVANT_LOGS,
    REDEEMED_DELEGATION_TOPIC,
    TRANSFER_SELECTOR,
    TRANSFER_TOPIC,
    ChainContext,
    Purpose,
    check_payment,
    decode_redemptions,
    keccak256,
    payment_nonce,
)

FIXTURES = (
    Path(__file__).resolve().parent.parent / "test" / "fixtures" / "delegated-spend"
)


def load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def purpose(vector: dict, label: str) -> Purpose:
    for p in vector["context"]["purposes"]:
        if p["label"] == label:
            return Purpose.from_json(p)
    raise KeyError(label)


def check(vector: dict, label: str):
    return check_payment(
        vector, ChainContext.from_json(vector["context"]), purpose(vector, label)
    )


class KeccakTest(unittest.TestCase):
    def test_known_vectors(self) -> None:
        self.assertEqual(
            keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(
            keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )

    def test_event_topics(self) -> None:
        self.assertEqual(
            TRANSFER_TOPIC, keccak256(b"Transfer(address,address,uint256)")
        )
        self.assertEqual(
            AUTHORIZATION_USED_TOPIC,
            keccak256(b"AuthorizationUsed(address,bytes32)"),
        )
        self.assertEqual(
            REDEEMED_DELEGATION_TOPIC,
            keccak256(
                b"RedeemedDelegation(address,address,"
                b"(address,address,bytes32,(address,bytes,bytes)[],uint256,bytes))"
            ),
        )


class VectorTest(unittest.TestCase):
    """Every vector's purposes get the outcome the fork test recorded."""

    def test_every_vector_matches_its_expectations(self) -> None:
        names = sorted(p.stem for p in FIXTURES.glob("*.json"))
        self.assertGreaterEqual(len(names), 7)
        for name in names:
            vector = load(name)
            for p in vector["context"]["purposes"]:
                with self.subTest(vector=name, purpose=p["label"]):
                    got = check(vector, p["label"])
                    self.assertEqual(got.outcome, p["expect"])

    def test_nonce_matches_the_fork_test(self) -> None:
        for path in FIXTURES.glob("*.json"):
            vector = json.loads(path.read_text(encoding="utf-8"))
            for p in vector["context"]["purposes"]:
                with self.subTest(vector=path.stem, purpose=p["label"]):
                    pur = Purpose.from_json(p)
                    self.assertEqual(
                        payment_nonce(pur.kind, pur.purpose_digest, p["payer"]),
                        int(p["nonce"], 16),
                    )

    def test_delegation_hashes_match_the_manager(self) -> None:
        """The checker's EIP-712 struct hash equals the manager's own.

        The struct hash preimage is 192 bytes, so this also covers Keccak
        inputs longer than one 136-byte block.
        """
        for path in FIXTURES.glob("*.json"):
            vector = json.loads(path.read_text(encoding="utf-8"))
            ctx = ChainContext.from_json(vector["context"])
            got = {
                r.hash
                for chain in decode_redemptions(vector["logs"], ctx)
                for r in chain
            }
            want = {
                bytes.fromhex(h[2:]) for h in vector["context"]["delegations"].values()
            }
            with self.subTest(vector=path.stem):
                self.assertEqual(got, want)


class BindingRuleTest(unittest.TestCase):
    """Which delegation binds, and which Transfer it pairs with: ARC-0032
    section 5.4 step 3."""

    def _hash(self, vector: dict, role: str) -> bytes:
        return bytes.fromhex(vector["context"]["delegations"][role][2:])

    def test_one_payment_binds_the_leaf(self) -> None:
        v = load("one-payment")
        got = check(v, "grant-1")
        self.assertEqual(got.payment.binding_hash, self._hash(v, "leaf"))
        self.assertEqual(got.payment.amount, 2_500_000)

    def test_salted_hop_binds_not_the_leaf(self) -> None:
        v = load("salted-hop-above-salted-leaf")
        self.assertEqual(
            check(v, "grant-2").payment.binding_hash, self._hash(v, "dAB")
        )
        self.assertEqual(check(v, "grant-1").outcome, "not-this-request")

    def test_stranger_child_leaves_the_leaf_binding(self) -> None:
        v = load("stranger-child-under-open-leaf")
        self.assertEqual(
            check(v, "grant-1").payment.binding_hash, self._hash(v, "leaf")
        )

    def test_two_payments_pair_with_distinct_transfers(self) -> None:
        v = load("two-payments-one-root-one-tx")
        a = check(v, "grant-1").payment
        b = check(v, "grant-2").payment
        self.assertEqual(a.binding_hash, self._hash(v, "leaf1"))
        self.assertEqual(b.binding_hash, self._hash(v, "leaf2"))
        self.assertNotEqual(a.transfer_position, b.transfer_position)
        self.assertLess(a.transfer_position, b.transfer_position)

    def test_one_transfer_for_two_bindings_pairs_the_first(self) -> None:
        v = load("two-bindings-one-transfer")
        self.assertEqual(
            check(v, "grant-1").payment.binding_hash, self._hash(v, "l1")
        )
        self.assertEqual(check(v, "grant-2").outcome, "not-this-request")

    def test_leaf_without_call_limit_is_unbound_money(self) -> None:
        v = load("leaf-without-call-limit")
        got = check(v, "grant-1")
        self.assertEqual(got.outcome, "unbound")
        self.assertEqual(got.unbound.amount, 2_500_000)

    def test_eip3009_transfer_never_pairs_and_is_never_refunded(self) -> None:
        v = load("eip3009-beside-binding")
        self.assertEqual(check(v, "grant-1").outcome, "no-usdc-to-payee")


class ReceiptShapeTest(unittest.TestCase):
    def test_reverted_receipt(self) -> None:
        v = copy.deepcopy(load("one-payment"))
        v["status"] = "0x0"
        v["logs"] = []
        self.assertEqual(check(v, "grant-1").outcome, "reverted")

    def test_oversized_receipt(self) -> None:
        v = copy.deepcopy(load("one-payment"))
        transfer = next(
            log
            for log in v["logs"]
            if log["topics"][0] == "0x" + TRANSFER_TOPIC.hex()
        )
        v["logs"] = v["logs"] + [copy.deepcopy(transfer)] * MAX_RELEVANT_LOGS
        self.assertEqual(check(v, "grant-1").outcome, "oversized")

    def test_unlisted_manager_binds_nothing(self) -> None:
        v = copy.deepcopy(load("one-payment"))
        v["context"]["delegationManagers"] = [
            "0x000000000000000000000000000000000000dEaD"
        ]
        got = check(v, "grant-1")
        self.assertEqual(got.outcome, "unbound")

    def test_identity_uses_position_not_block_log_index(self) -> None:
        v = load("one-payment")
        moved = copy.deepcopy(v)
        for i, log in enumerate(moved["logs"]):
            log["logIndex"] = hex(1000 + i)
        self.assertEqual(
            check(v, "grant-1").payment, check(moved, "grant-1").payment
        )

    def test_transfer_from_another_token_is_not_usdc(self) -> None:
        v = copy.deepcopy(load("one-payment"))
        for log in v["logs"]:
            if log["topics"][0] == "0x" + TRANSFER_TOPIC.hex():
                log["address"] = "0x000000000000000000000000000000000000bEEF"
        self.assertEqual(check(v, "grant-1").outcome, "no-usdc-to-payee")

    def test_transfer_to_another_address_is_not_a_payment(self) -> None:
        v = copy.deepcopy(load("one-payment"))
        for log in v["logs"]:
            if log["topics"][0] == "0x" + TRANSFER_TOPIC.hex():
                log["topics"][2] = _topic_addr(
                    "0x000000000000000000000000000000000000dEaD"
                )
        self.assertEqual(check(v, "grant-1").outcome, "no-usdc-to-payee")

    def test_transfer_to_another_address_does_not_move_the_pairing(self) -> None:
        v = copy.deepcopy(load("one-payment"))
        pos = next(
            i
            for i, log in enumerate(v["logs"])
            if log["topics"][0] == "0x" + TRANSFER_TOPIC.hex()
        )
        stray = copy.deepcopy(v["logs"][pos])
        stray["topics"][2] = _topic_addr(
            "0x000000000000000000000000000000000000dEaD"
        )
        v["logs"].insert(pos, stray)
        got = check(v, "grant-1")
        self.assertEqual(got.outcome, "bound")
        self.assertEqual(got.payment.transfer_position, pos + 1)


def _topic_addr(a: str) -> str:
    return "0x" + "00" * 12 + a[2:].lower()


class BindingPinTest(unittest.TestCase):
    """Edits to one-payment.json that must leave the payment unbound: the
    pairing filters and the pins that make a delegation the binding."""

    def _transfer(self, v: dict) -> dict:
        return next(
            log
            for log in v["logs"]
            if log["topics"][0] == "0x" + TRANSFER_TOPIC.hex()
        )

    def _patch_leaf(self, v: dict, old: bytes, new: bytes) -> None:
        """Replace `old` once in the leaf's RedeemedDelegation data. The
        leaf's hash is no delegation's authority, so the links hold."""
        ctx = ChainContext.from_json(v["context"])
        leaf = next(
            log
            for log in v["logs"]
            if log["address"].lower() in {m.lower() for m in ctx.managers}
        )
        data = bytes.fromhex(leaf["data"][2:])
        self.assertEqual(data.count(old), 1)
        leaf["data"] = "0x" + data.replace(old, new).hex()

    def test_unbound_when_the_edit_breaks_a_filter_or_pin(self) -> None:
        base = load("one-payment")
        ctx = base["context"]
        word = lambda n: n.to_bytes(32, "big")  # noqa: E731
        other = "0x000000000000000000000000000000000000dEaD"

        def transfer_from_other(v: dict) -> None:
            self._transfer(v)["topics"][1] = _topic_addr(other)

        def transfer_below_pinned_price(v: dict) -> None:
            t = self._transfer(v)
            amount = int(t["data"], 16)
            t["data"] = "0x" + (amount - 1).to_bytes(32, "big").hex()

        def call_limit_two(v: dict) -> None:
            self._patch_leaf(v, word(32) + word(1), word(32) + word(2))

        def look_alike_limit_enforcer(v: dict) -> None:
            self._patch_leaf(
                v,
                bytes.fromhex(ctx["limitedCallsEnforcer"][2:]),
                bytes.fromhex(other[2:]),
            )

        def pinned_token_changed(v: dict) -> None:
            self._patch_leaf(
                v, bytes.fromhex(ctx["usdc"][2:]), bytes.fromhex(other[2:])
            )

        def pinned_selector_changed(v: dict) -> None:
            self._patch_leaf(v, TRANSFER_SELECTOR, bytes.fromhex("23b872dd"))

        def pinned_payee_changed(v: dict) -> None:
            self._patch_leaf(
                v, bytes.fromhex(ctx["payee"][2:]), bytes.fromhex(other[2:])
            )

        def look_alike_exact_enforcer(v: dict) -> None:
            self._patch_leaf(
                v, bytes.fromhex(ctx["exactExecutionEnforcer"][2:]), bytes.fromhex(other[2:])
            )

        def pinned_value_nonzero(v: dict) -> None:
            usdc = bytes.fromhex(ctx["usdc"][2:])
            self._patch_leaf(v, usdc + word(0), usdc + word(1))

        def terms_with_trailing_byte(v: dict) -> None:
            # Terms are 120 bytes (20+32+68); claim one more, from the
            # zero padding, so the call is no longer transfer(payee, x).
            self._patch_leaf(v, word(120), word(121))

        def dirty_payee_word(v: dict) -> None:
            payee = bytes.fromhex(ctx["payee"][2:])
            self._patch_leaf(
                v,
                TRANSFER_SELECTOR + bytes(12) + payee,
                TRANSFER_SELECTOR + b"\x01" + bytes(11) + payee,
            )

        rows = {
            "terms with a trailing byte": terms_with_trailing_byte,
            "payee word with a dirty high byte": dirty_payee_word,
            "look-alike exact-execution enforcer": look_alike_exact_enforcer,
            "pinned value non-zero": pinned_value_nonzero,
            "transfer from another address": transfer_from_other,
            "transfer below the pinned price": transfer_below_pinned_price,
            "call limit 2": call_limit_two,
            "look-alike limit enforcer": look_alike_limit_enforcer,
            "pinned token changed": pinned_token_changed,
            "pinned selector changed": pinned_selector_changed,
            "pinned payee changed": pinned_payee_changed,
        }
        for name, edit in rows.items():
            with self.subTest(edit=name):
                v = copy.deepcopy(base)
                edit(v)
                self.assertEqual(check(v, "grant-1").outcome, "unbound")

    def test_hostile_logs_leave_the_payment_bound(self) -> None:
        base = load("one-payment")
        ctx = base["context"]
        manager = ctx["delegationManagers"][0].lower()
        usdc = ctx["usdc"]
        other = "0x000000000000000000000000000000000000dEaD"

        def insert_before_transfer(v: dict, log: dict) -> None:
            pos = next(
                i
                for i, x in enumerate(v["logs"])
                if x["topics"][0] == "0x" + TRANSFER_TOPIC.hex()
            )
            v["logs"].insert(pos, log)

        def auth_used(address: str, authorizer: str) -> dict:
            return {
                "address": address,
                "topics": [
                    "0x" + AUTHORIZATION_USED_TOPIC.hex(),
                    _topic_addr(authorizer),
                    "0x" + "00" * 32,
                ],
                "data": "0x",
            }

        def disabled_delegation_copy(v: dict) -> None:
            leaf = copy.deepcopy(
                next(x for x in v["logs"] if x["address"].lower() == manager)
            )
            leaf["topics"][0] = "0x" + keccak256(
                b"DisabledDelegation(bytes32,address,address,"
                b"(address,address,bytes32,(address,bytes,bytes)[],"
                b"uint256,bytes))"
            ).hex()
            v["logs"].append(leaf)

        def approval_from_root(v: dict) -> None:
            root = self._transfer(v)["topics"][1]
            insert_before_transfer(
                v,
                {
                    "address": usdc,
                    "topics": [
                        "0x" + keccak256(b"Approval(address,address,uint256)").hex(),
                        root,
                        _topic_addr(other),
                    ],
                    "data": "0x" + "00" * 32,
                },
            )

        def authorization_used_elsewhere(v: dict) -> None:
            sender = "0x" + self._transfer(v)["topics"][1][26:]
            insert_before_transfer(v, auth_used(other, sender))

        def authorization_used_by_another(v: dict) -> None:
            insert_before_transfer(v, auth_used(usdc, other))

        rows = {
            "disabled-delegation copy": disabled_delegation_copy,
            "approval from the root": approval_from_root,
            "authorization used on another contract": authorization_used_elsewhere,
            "authorization used by another authorizer": authorization_used_by_another,
        }
        for name, edit in rows.items():
            with self.subTest(edit=name):
                v = copy.deepcopy(base)
                edit(v)
                self.assertEqual(check(v, "grant-1").outcome, "bound")

    def test_malformed_manager_chain_raises(self) -> None:
        base = load("one-payment")
        manager = base["context"]["delegationManagers"][0].lower()

        def manager_positions(v: dict) -> list[int]:
            return [
                i for i, x in enumerate(v["logs"]) if x["address"].lower() == manager
            ]

        def truncated(v: dict) -> None:
            del v["logs"][manager_positions(v)[-1]]

        def reordered(v: dict) -> None:
            a, b = manager_positions(v)[:2]
            v["logs"][a], v["logs"][b] = v["logs"][b], v["logs"][a]

        def root_delegator_differs(v: dict) -> None:
            first = manager_positions(v)[0]
            v["logs"][first]["topics"][1] = _topic_addr(
                "0x000000000000000000000000000000000000dEaD"
            )

        rows = {
            "truncated": truncated,
            "reordered": reordered,
            "root delegator differs": root_delegator_differs,
        }
        for name, edit in rows.items():
            with self.subTest(edit=name):
                v = copy.deepcopy(base)
                edit(v)
                with self.assertRaises(ValueError):
                    check(v, "grant-1")

    def test_relevant_log_count_limit_is_inclusive(self) -> None:
        v = copy.deepcopy(load("one-payment"))
        transfer = copy.deepcopy(self._transfer(v))
        relevant = sum(
            1
            for log in v["logs"]
            if log["topics"][0] == "0x" + TRANSFER_TOPIC.hex()
            or log["address"].lower() in {m.lower() for m in v["context"]["delegationManagers"]}
        )
        at_limit = copy.deepcopy(v)
        at_limit["logs"] += [copy.deepcopy(transfer)] * (MAX_RELEVANT_LOGS - relevant)
        self.assertEqual(check(at_limit, "grant-1").outcome, "bound")
        over = copy.deepcopy(at_limit)
        over["logs"].append(copy.deepcopy(transfer))
        self.assertEqual(check(over, "grant-1").outcome, "oversized")

    def test_usdc_authorization_used_counts_toward_the_cap(self) -> None:
        """The sketch's relevantLogs counts USDC AuthorizationUsed beside
        RedeemedDelegation and Transfer (06 section 5.5)."""
        v = copy.deepcopy(load("one-payment"))
        transfer = copy.deepcopy(self._transfer(v))
        managers = {m.lower() for m in v["context"]["delegationManagers"]}
        relevant = sum(
            1
            for log in v["logs"]
            if log["topics"][0] == "0x" + TRANSFER_TOPIC.hex()
            or log["address"].lower() in managers
        )
        v["logs"] += [copy.deepcopy(transfer)] * (MAX_RELEVANT_LOGS - relevant)
        self.assertEqual(check(v, "grant-1").outcome, "bound")
        v["logs"].append(
            {
                "address": v["context"]["usdc"],
                "topics": [
                    "0x" + AUTHORIZATION_USED_TOPIC.hex(),
                    _topic_addr("0x000000000000000000000000000000000000dEaD"),
                    "0x" + "00" * 32,
                ],
                "data": "0x",
            }
        )
        self.assertEqual(check(v, "grant-1").outcome, "oversized")


if __name__ == "__main__":
    unittest.main()
