"""Shared helpers for ES256 ImutableUnivocity deploy and bootstrap scripts."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.asymmetric import ec
from eth_account import Account

MIN_BALANCE_WEI = int(os.environ.get("ES256_DEPLOY_MIN_BALANCE_WEI", "800000000000000"))  # 0.0008 ETH
P256_N = int(
    "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E884FCE93D47B0FBF27663D86",
    16,
)


@dataclass(frozen=True)
class Es256Coords:
    x: bytes
    y: bytes
    x_hex: str
    y_hex: str
    pubkey64: bytes


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        print(f"{name} is required", file=sys.stderr)
        raise SystemExit(1)
    return value


def normalize_pk(pk: str) -> str:
    if not pk.startswith("0x"):
        pk = "0x" + pk
    return pk


def load_pem_es256_coords() -> Es256Coords:
    pem_text = require_env("BOOTSTRAP_PEM_ES256")
    if "BEGIN" not in pem_text:
        print("BOOTSTRAP_PEM_ES256 must be inline PEM text", file=sys.stderr)
        raise SystemExit(1)
    key = serialization.load_pem_private_key(pem_text.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        print("BOOTSTRAP_PEM_ES256 must be an EC private key", file=sys.stderr)
        raise SystemExit(1)
    pub = key.public_key().public_numbers()
    x = pub.x.to_bytes(32, "big")
    y = pub.y.to_bytes(32, "big")
    return Es256Coords(
        x=x,
        y=y,
        x_hex="0x" + x.hex(),
        y_hex="0x" + y.hex(),
        pubkey64=x + y,
    )


def cast_balance_wei(rpc_url: str, address: str) -> int:
    out = subprocess.check_output(
        ["cast", "balance", address, "--rpc-url", rpc_url],
        text=True,
    ).strip()
    if out.startswith("0x"):
        return int(out, 16)
    return int(out)


def select_gas_payer_private_key(rpc_url: str) -> tuple[str, str]:
    deploy_pk = normalize_pk(require_env("DEPLOY_KEY"))
    fallback_pk = normalize_pk(require_env("BOOTSTRAP_MULTISIG_SIGNER"))
    deploy_addr = Account.from_key(deploy_pk).address
    fallback_addr = Account.from_key(fallback_pk).address
    deploy_bal = cast_balance_wei(rpc_url, deploy_addr)
    if deploy_bal >= MIN_BALANCE_WEI:
        print(f"Gas payer: DEPLOY_KEY ({deploy_addr}) balance={deploy_bal}")
        return deploy_pk, deploy_addr
    fallback_bal = cast_balance_wei(rpc_url, fallback_addr)
    if fallback_bal >= MIN_BALANCE_WEI:
        print(
            f"Gas payer: BOOTSTRAP_MULTISIG_SIGNER ({fallback_addr}) "
            f"balance={fallback_bal}"
        )
        return fallback_pk, fallback_addr
    print(
        f"Neither DEPLOY_KEY ({deploy_addr}, {deploy_bal} wei) nor "
        f"BOOTSTRAP_MULTISIG_SIGNER ({fallback_addr}, {fallback_bal} wei) "
        f"has at least {MIN_BALANCE_WEI} wei",
        file=sys.stderr,
    )
    raise SystemExit(2)


def encode_bstr(data: bytes) -> bytes:
    n = len(data)
    if n < 24:
        return bytes([0x40 + n]) + data
    if n < 256:
        return bytes([0x58, n]) + data
    if n < 65536:
        return bytes([0x59]) + n.to_bytes(2, "big") + data
    return bytes([0x5A]) + n.to_bytes(4, "big") + data


def build_sig_structure(protected_header: bytes, payload: bytes) -> bytes:
    return (
        b"\x84"
        + b"\x6aSignature1"
        + encode_bstr(protected_header)
        + b"\x40"
        + encode_bstr(payload)
    )


def ensure_lower_s(s: int) -> int:
    if s > P256_N // 2:
        return P256_N - s
    return s


def sign_es256_p256(pem_text: str, message: bytes) -> bytes:
    key = serialization.load_pem_private_key(pem_text.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("expected EC private key")
    der_sig = key.sign(Prehashed(hashlib.sha256(message)), ec.ECDSA(Prehashed(hashlib.sha256)))
    r, s = decode_der_ecdsa_signature(der_sig)
    s = ensure_lower_s(s)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def decode_der_ecdsa_signature(der: bytes) -> tuple[int, int]:
    if der[0] != 0x30:
        raise ValueError("invalid DER signature")
    idx = 2
    if der[1] & 0x80:
        idx = 2 + (der[1] & 0x7F)
    if der[idx] != 0x02:
        raise ValueError("invalid DER r")
    r_len = der[idx + 1]
    r = int.from_bytes(der[idx + 2 : idx + 2 + r_len], "big")
    idx = idx + 2 + r_len
    if der[idx] != 0x02:
        raise ValueError("invalid DER s")
    s_len = der[idx + 1]
    s = int.from_bytes(der[idx + 2 : idx + 2 + s_len], "big")
    return r, s


def mnemonic_uuid_from_address(address: str) -> str:
    h = address.lower().removeprefix("0x")
    if len(h) != 40:
        raise ValueError(f"expected 20-byte address, got {address}")
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def parse_deployed_address(forge_output: str) -> str | None:
    match = re.search(
        r"ImutableUnivocity deployed at:\s*(0x[a-fA-F0-9]{40})",
        forge_output,
    )
    return match.group(1) if match else None
