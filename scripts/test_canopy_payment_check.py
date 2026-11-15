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


if __name__ == "__main__":
    unittest.main()
