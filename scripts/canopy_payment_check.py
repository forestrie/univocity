#!/usr/bin/env python3
"""Stand-in for canopy-api's delegated payment check (spike, FOR-696).

Binds a payment from a transaction receipt the way devdocs ARC-0032
section 5.4 says canopy will, reading only the receipt's logs and never
the calldata:

1. The transaction succeeded and emitted a USDC Transfer to the payee
   (the Payment scheme's EVM charge check). A Transfer made under an
   EIP-3009 authorization belongs to the x402 path: it never pairs and
   is never refund money here.
2. Each redeemed chain is rebuilt from the RedeemedDelegation events of
   a listed delegation manager, through their authority links.
3. In each chain only the delegation nearest the root that pins
   transfer(payee, amount) on USDC through the listed
   ExactExecutionEnforcer can bind. It binds a request when its
   salt is the request's payment nonce over the chain's root and it
   carries LimitedCallsEnforcer(1).
4. Pairing is receipt-wide and deterministic: binding delegations in log
   order each take the first unpaired Transfer of their pinned amount
   from their root. A binding without the call limit pairs too, so its
   Transfer is counted once, but it binds nothing.

The outcome for one request is one of: reverted, oversized,
no-usdc-to-payee, bound, unbound (money that can only be refunded) or
not-this-request. Price, dust, depth and the used-payment record are
canopy's (ADR-0076) and are left to the caller.

The payment nonce and the binding rule are provisional until protocol
publishes them as erc7710-leaf-salt/v1 with vectors (ARC-0032 section
10).
Standard library only, so CI runs it without installing anything.

Usage:
  canopy_payment_check.py --receipt FILE --context FILE --label LABEL
  canopy_payment_check.py --rpc-url URL --tx HASH --context FILE \\
      --kind 1 --purpose-digest 0x...
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from dataclasses import dataclass, field

# --- Keccak-256 (the pre-standard padding Ethereum uses) ---

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_MASK = (1 << 64) - 1


def _rol(v: int, n: int) -> int:
    return ((v << n) | (v >> (64 - n))) & _MASK if n else v


def _keccak_f(a: list[list[int]]) -> None:
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Keccak-256 as Ethereum uses it (pad 0x01 ... 0x80, rate 136)."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate:
        padded.append(0)
    padded[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(padded), rate):
        block = padded[off : off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            a[x][y] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        _keccak_f(a)
    out = b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out


# --- constants ---

TRANSFER_TOPIC = keccak256(b"Transfer(address,address,uint256)")
AUTHORIZATION_USED_TOPIC = keccak256(b"AuthorizationUsed(address,bytes32)")
REDEEMED_DELEGATION_TOPIC = keccak256(
    b"RedeemedDelegation(address,address,"
    b"(address,address,bytes32,(address,bytes,bytes)[],uint256,bytes))"
)
DELEGATION_TYPEHASH = keccak256(
    b"Delegation(address delegate,address delegator,bytes32 authority,"
    b"Caveat[] caveats,uint256 salt)Caveat(address enforcer,bytes terms)"
)
CAVEAT_TYPEHASH = keccak256(b"Caveat(address enforcer,bytes terms)")
ROOT_AUTHORITY = b"\xff" * 32
TRANSFER_SELECTOR = bytes.fromhex("a9059cbb")

# canopy decodes at most this many relevant logs per receipt (ARC-0032
# section 5.4).
MAX_RELEVANT_LOGS = 256

# Provisional payment nonce tag: ARC-0032 section 5.3 gives the formula
# and protocol will fix the tag and kinds.
NONCE_TAG = b"forestrie/payment-nonce/v1"


def payment_nonce(kind: int, purpose_digest: bytes, payer: str) -> int:
    """SHA-256(TAG ‖ kind ‖ purposeDigest ‖ payer), ARC-0032 §5.3."""
    pre = NONCE_TAG + bytes([kind]) + purpose_digest + _addr_bytes(payer)
    return int.from_bytes(hashlib.sha256(pre).digest(), "big")


# --- inputs ---


def _hex(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def _addr_bytes(a: str) -> bytes:
    b = _hex(a)
    if len(b) != 20:
        raise ValueError(f"not an address: {a}")
    return b


def _addr(a: str) -> str:
    return "0x" + _addr_bytes(a).hex()


@dataclass(frozen=True)
class ChainContext:
    """What canopy's payment-chain table holds for one chain (ARC-0032
    section 5.4)."""

    usdc: str
    payee: str
    managers: frozenset[str]
    exact_execution_enforcer: str
    limited_calls_enforcer: str

    @staticmethod
    def from_json(j: dict) -> "ChainContext":
        return ChainContext(
            usdc=_addr(j["usdc"]),
            payee=_addr(j["payee"]),
            managers=frozenset(_addr(m) for m in j["delegationManagers"]),
            exact_execution_enforcer=_addr(j["exactExecutionEnforcer"]),
            limited_calls_enforcer=_addr(j["limitedCallsEnforcer"]),
        )


@dataclass(frozen=True)
class Purpose:
    """The request's purpose: its nonce kind and digest. The payer input of
    the nonce is each redeemed chain's root, never the presenter."""

    kind: int
    purpose_digest: bytes

    @staticmethod
    def from_json(j: dict) -> "Purpose":
        return Purpose(kind=int(j["kind"]), purpose_digest=_hex(j["purposeDigest"]))


# --- ABI decoding of RedeemedDelegation ---


def _word(b: bytes, off: int) -> int:
    return int.from_bytes(b[off : off + 32], "big")


def _dyn_bytes(b: bytes, base: int, rel: int) -> bytes:
    start = base + rel
    n = _word(b, start)
    return b[start + 32 : start + 32 + n]


@dataclass(frozen=True)
class Caveat:
    enforcer: str
    terms: bytes
    args: bytes


@dataclass(frozen=True)
class Redeemed:
    """One RedeemedDelegation event: its delegation and where it sits."""

    position: int
    manager: str
    root_delegator: str
    delegate: str
    delegator: str
    authority: bytes
    caveats: tuple[Caveat, ...]
    salt: int
    hash: bytes


def _decode_delegation(data: bytes) -> tuple:
    # data = abi.encode(Delegation): one head word pointing at the tuple.
    t = _word(data, 0)
    delegate = "0x" + data[t + 12 : t + 32].hex()
    delegator = "0x" + data[t + 44 : t + 64].hex()
    authority = data[t + 64 : t + 96]
    cav_off = t + _word(data, t + 96)
    salt = _word(data, t + 128)
    n = _word(data, cav_off)
    caveats = []
    heads = cav_off + 32
    for i in range(n):
        c = heads + _word(data, heads + 32 * i)
        enforcer = "0x" + data[c + 12 : c + 32].hex()
        terms = _dyn_bytes(data, c, _word(data, c + 32))
        args = _dyn_bytes(data, c, _word(data, c + 64))
        caveats.append(Caveat(enforcer, terms, args))
    return delegate, delegator, authority, tuple(caveats), salt


def delegation_hash(
    delegate: str, delegator: str, authority: bytes, caveats, salt: int
) -> bytes:
    """EIP-712 struct hash, as EncoderLib._getDelegationHash computes it."""
    packets = b"".join(
        keccak256(
            CAVEAT_TYPEHASH
            + bytes(12)
            + _addr_bytes(c.enforcer)
            + keccak256(c.terms)
        )
        for c in caveats
    )
    return keccak256(
        DELEGATION_TYPEHASH
        + bytes(12)
        + _addr_bytes(delegate)
        + bytes(12)
        + _addr_bytes(delegator)
        + authority
        + keccak256(packets)
        + salt.to_bytes(32, "big")
    )


def _topic0(log: dict) -> bytes:
    return _hex(log["topics"][0]) if log["topics"] else b""


def decode_redemptions(logs: list[dict], ctx: ChainContext) -> list[list[Redeemed]]:
    """Rebuild each redeemed chain, leaf first, from a listed manager's
    RedeemedDelegation events. The manager emits a chain's events
    contiguously, leaf to root, so a chain ends at ROOT_AUTHORITY; every
    link must point at the next delegation's hash."""
    chains: list[list[Redeemed]] = []
    open_chain: dict[str, list[Redeemed]] = {}
    for pos, log in enumerate(logs):
        manager = _addr(log["address"])
        if manager not in ctx.managers or _topic0(log) != REDEEMED_DELEGATION_TOPIC:
            continue
        delegate, delegator, authority, caveats, salt = _decode_delegation(
            _hex(log["data"])
        )
        r = Redeemed(
            position=pos,
            manager=manager,
            root_delegator="0x" + _hex(log["topics"][1])[12:].hex(),
            delegate=delegate,
            delegator=delegator,
            authority=authority,
            caveats=caveats,
            salt=salt,
            hash=delegation_hash(delegate, delegator, authority, caveats, salt),
        )
        chain = open_chain.setdefault(manager, [])
        if chain and chain[-1].authority != r.hash:
            raise ValueError(f"broken authority link at log {pos}")
        chain.append(r)
        if r.authority == ROOT_AUTHORITY:
            if any(x.root_delegator != r.delegator for x in chain):
                raise ValueError(f"root delegator mismatch at log {pos}")
            chains.append(chain)
            open_chain[manager] = []
    if any(open_chain.values()):
        raise ValueError("redeemed chain does not reach the root")
    return chains


# --- binding and pairing ---


@dataclass(frozen=True)
class Transfer:
    position: int
    sender: str
    amount: int
    eip3009: bool


@dataclass(frozen=True)
class Binding:
    """The delegation nearest a chain's root that pins transfer(payee, x)."""

    position: int
    manager: str
    binding_hash: bytes
    root: str
    salt: int
    amount: int
    has_call_limit: bool


@dataclass(frozen=True)
class BoundPayment:
    """A payment's identity is its manager and binding delegation hash; the
    Transfer key is the transaction hash and the Transfer's position among
    the receipt's own logs, never the block-wide logIndex."""

    manager: str
    binding_hash: bytes
    root: str
    amount: int
    transaction_hash: str
    transfer_position: int


@dataclass(frozen=True)
class UnboundTransfer:
    transaction_hash: str
    position: int
    sender: str
    amount: int


@dataclass(frozen=True)
class Reading:
    outcome: str
    payment: BoundPayment | None = None
    unbound: UnboundTransfer | None = None
    bindings: tuple[Binding, ...] = field(default_factory=tuple)


def _pinned_amount(r: Redeemed, ctx: ChainContext) -> int | None:
    """The amount r pins to the payee through ExactExecutionEnforcer, if
    it pins USDC.transfer(payee, amount) with value 0."""
    for c in r.caveats:
        if _addr(c.enforcer) != ctx.exact_execution_enforcer:
            continue
        t = c.terms
        if len(t) != 20 + 32 + 68:
            continue
        if "0x" + t[0:20].hex() != ctx.usdc or _word(t, 20) != 0:
            continue
        call = t[52:]
        if call[0:4] != TRANSFER_SELECTOR:
            continue
        if "0x" + call[16:36].hex() != ctx.payee or any(call[4:16]):
            continue
        return _word(call, 36)
    return None


def _has_call_limit(r: Redeemed, ctx: ChainContext) -> bool:
    return any(
        _addr(c.enforcer) == ctx.limited_calls_enforcer
        and c.terms == (1).to_bytes(32, "big")
        for c in r.caveats
    )


def _bindings(chains: list[list[Redeemed]], ctx: ChainContext) -> list[Binding]:
    out = []
    for chain in chains:
        for r in reversed(chain):  # root first
            amount = _pinned_amount(r, ctx)
            if amount is None:
                continue
            out.append(
                Binding(
                    position=r.position,
                    manager=r.manager,
                    binding_hash=r.hash,
                    root=chain[-1].delegator,
                    salt=r.salt,
                    amount=amount,
                    has_call_limit=_has_call_limit(r, ctx),
                )
            )
            break
    return sorted(out, key=lambda b: b.position)


def _transfers_to_payee(logs: list[dict], ctx: ChainContext) -> list[Transfer]:
    out = []
    for pos, log in enumerate(logs):
        if _addr(log["address"]) != ctx.usdc or _topic0(log) != TRANSFER_TOPIC:
            continue
        to = "0x" + _hex(log["topics"][2])[12:].hex()
        if to != ctx.payee:
            continue
        sender = "0x" + _hex(log["topics"][1])[12:].hex()
        # USDC emits AuthorizationUsed(authorizer) immediately before the
        # Transfer of transferWithAuthorization or receiveWithAuthorization.
        prev = logs[pos - 1] if pos > 0 else None
        eip3009 = (
            prev is not None
            and _addr(prev["address"]) == ctx.usdc
            and _topic0(prev) == AUTHORIZATION_USED_TOPIC
            and "0x" + _hex(prev["topics"][1])[12:].hex() == sender
        )
        out.append(Transfer(pos, sender, _word(_hex(log["data"]), 0), eip3009))
    return out


def _relevant_count(logs: list[dict], ctx: ChainContext) -> int:
    n = 0
    for log in logs:
        a, t = _addr(log["address"]), _topic0(log)
        if a in ctx.managers and t == REDEEMED_DELEGATION_TOPIC:
            n += 1
        elif a == ctx.usdc and t in (TRANSFER_TOPIC, AUTHORIZATION_USED_TOPIC):
            n += 1
    return n


def check_payment(receipt: dict, ctx: ChainContext, purpose: Purpose) -> Reading:
    """Classify `receipt` for a request with `purpose` (ARC-0032 §5.4
    steps 2 and 3)."""
    if int(receipt["status"], 16) != 1:
        return Reading("reverted")
    logs = receipt["logs"]
    if _relevant_count(logs, ctx) > MAX_RELEVANT_LOGS:
        return Reading("oversized")
    transfers = [t for t in _transfers_to_payee(logs, ctx) if not t.eip3009]
    if not transfers:
        return Reading("no-usdc-to-payee")

    bindings = _bindings(decode_redemptions(logs, ctx), ctx)
    paired: dict[int, Transfer] = {}
    pairs: list[tuple[Binding, Transfer]] = []
    for b in bindings:
        for t in transfers:
            if t.position in paired or t.sender != b.root or t.amount != b.amount:
                continue
            paired[t.position] = t
            pairs.append((b, t))
            break

    tx = receipt.get("transactionHash", "")
    for b, t in pairs:
        if not b.has_call_limit:
            continue
        if b.salt == payment_nonce(purpose.kind, purpose.purpose_digest, b.root):
            return Reading(
                "bound",
                payment=BoundPayment(
                    manager=b.manager,
                    binding_hash=b.binding_hash,
                    root=b.root,
                    amount=b.amount,
                    transaction_hash=tx,
                    transfer_position=t.position,
                ),
                bindings=tuple(bindings),
            )

    counted = {t.position for b, t in pairs if b.has_call_limit}
    for t in transfers:
        if t.position not in counted:
            return Reading(
                "unbound",
                unbound=UnboundTransfer(tx, t.position, t.sender, t.amount),
                bindings=tuple(bindings),
            )
    return Reading("not-this-request", bindings=tuple(bindings))


# --- command line ---


def _rpc_receipt(url: str, tx: str) -> dict:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getTransactionReceipt",
            "params": [tx],
        }
    ).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.load(resp).get("result")
    if result is None:
        raise SystemExit(f"no receipt for {tx} (not mined, or wrong chain)")
    return result


def _jsonable(r: Reading) -> dict:
    def conv(o):
        if isinstance(o, bytes):
            return "0x" + o.hex()
        if hasattr(o, "__dataclass_fields__"):
            return {k: conv(getattr(o, k)) for k in o.__dataclass_fields__}
        if isinstance(o, (list, tuple)):
            return [conv(x) for x in o]
        return o

    return conv(r)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--receipt", help="receipt JSON (a fixture or RPC result)")
    src.add_argument("--rpc-url", help="JSON-RPC endpoint to read the receipt")
    p.add_argument("--tx", help="transaction hash, with --rpc-url")
    p.add_argument(
        "--context",
        help="JSON with the chain context (defaults to the receipt's own)",
    )
    p.add_argument("--label", help="purpose label from the context")
    p.add_argument("--kind", type=int, help="nonce kind (1 grant)")
    p.add_argument("--purpose-digest", help="0x-prefixed 32-byte digest")
    a = p.parse_args(argv)

    if a.receipt:
        with open(a.receipt, encoding="utf-8") as f:
            receipt = json.load(f)
    else:
        if not a.tx:
            p.error("--tx is required with --rpc-url")
        receipt = _rpc_receipt(a.rpc_url, a.tx)
    if a.context:
        with open(a.context, encoding="utf-8") as f:
            ctx_json = json.load(f)
        ctx_json = ctx_json.get("context", ctx_json)
    else:
        ctx_json = receipt.get("context")
        if ctx_json is None:
            p.error("--context is required for a receipt without one")
    ctx = ChainContext.from_json(ctx_json)
    if a.label:
        match = [x for x in ctx_json.get("purposes", []) if x["label"] == a.label]
        if not match:
            p.error(f"no purpose labelled {a.label}")
        purpose = Purpose.from_json(match[0])
    elif a.kind is not None and a.purpose_digest:
        purpose = Purpose(a.kind, _hex(a.purpose_digest))
    else:
        p.error("give --label, or --kind and --purpose-digest")
    print(json.dumps(_jsonable(check_payment(receipt, ctx, purpose)), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
