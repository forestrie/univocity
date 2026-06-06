"""Shared helpers for Safe Transaction Service proposers."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from eth_abi import decode
from eth_account import Account
from eth_utils import keccak, to_checksum_address
from safe_eth.eth import EthereumClient, EthereumNetwork
from safe_eth.eth.constants import NULL_ADDRESS
from safe_eth.safe import Safe, SafeTx
from safe_eth.safe.api import TransactionServiceApi
from safe_eth.safe.api.base_api import SafeAPIException
from safe_eth.safe.enums import SafeOperationEnum

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SAFE = "0x1528b86ff561f617602356efdbD05908a07AA788"
CHAIN_ID = 84532
DEFAULT_SAFE_VERSION = "1.4.1"
CREATE_CALL_ADDRESS = "0x7cbB62EaA69F79e6873cD1ecB2392971036cFAa4"
SIGN_MESSAGE_LIB_ADDRESS = "0xd53cd0aB83D845Ac265BE939c57F53AD838012c9"
LEGACY_IMMUTABLE_UNIVOCITY = "0x611dd70B2D36c87B29878089eD8a7aDc68E4441B"
PERFORM_CREATE2_SELECTOR = bytes.fromhex("4847be6f")


def resolve_safe_address(env_var: str = "SAFE_ADDRESS", batch_meta: dict | None = None) -> str:
    if env_var in os.environ and os.environ[env_var]:
        return to_checksum_address(os.environ[env_var])
    if batch_meta and batch_meta.get("createdFromSafeAddress"):
        return to_checksum_address(batch_meta["createdFromSafeAddress"])
    return to_checksum_address(DEFAULT_SAFE)


def require_rpc_and_deploy_key() -> tuple[str, str]:
    rpc = os.environ.get("RPC_URL")
    pk = os.environ.get("DEPLOY_KEY")
    if not rpc or not pk:
        print("RPC_URL and DEPLOY_KEY are required", file=sys.stderr)
        raise SystemExit(1)
    if not pk.startswith("0x"):
        pk = "0x" + pk
    return rpc, pk


def assert_safe_deployed(client: EthereumClient, safe: str, chain_id: int = CHAIN_ID) -> None:
    code = client.w3.eth.get_code(safe)
    if code in (b"", b"0x"):
        print(
            f"Safe {safe} has no contract code on chain {chain_id}. "
            "Deploy or activate the Safe on Base Sepolia before proposing.",
            file=sys.stderr,
        )
        raise SystemExit(2)


def fetch_safe_nonce(client: EthereumClient, safe: str) -> int:
    return Safe(safe, client).retrieve_nonce()


def load_batch(path: Path) -> dict:
    batch = json.loads(path.read_text())
    batch_chain_id = str(batch.get("chainId", ""))
    if batch_chain_id and int(batch_chain_id) != CHAIN_ID:
        print(
            f"Batch chainId {batch_chain_id} does not match expected {CHAIN_ID}",
            file=sys.stderr,
        )
        raise SystemExit(4)
    return batch


def safe_tx_from_builder_entry(
    client: EthereumClient,
    safe: str,
    entry: dict,
    nonce: int,
    chain_id: int,
    safe_version: str = DEFAULT_SAFE_VERSION,
) -> SafeTx:
    operation = (
        SafeOperationEnum.DELEGATE_CALL.value
        if int(entry["operation"]) == 1
        else SafeOperationEnum.CALL.value
    )
    data_hex = entry["data"]
    data = bytes.fromhex(data_hex[2:] if data_hex.startswith("0x") else data_hex)
    return SafeTx(
        client,
        to_checksum_address(safe),
        to_checksum_address(entry["to"]),
        int(entry.get("value", 0)),
        data,
        operation,
        int(entry.get("safeTxGas", 0)),
        int(entry.get("baseGas", 0)),
        int(entry.get("gasPrice", 0)),
        to_checksum_address(entry.get("gasToken", NULL_ADDRESS)),
        to_checksum_address(entry.get("refundReceiver", NULL_ADDRESS)),
        safe_nonce=nonce,
        safe_version=safe_version,
        chain_id=chain_id,
    )


def transaction_service_api(
    ethereum_client: EthereumClient | None = None,
) -> TransactionServiceApi:
    return TransactionServiceApi(
        network=EthereumNetwork.BASE_SEPOLIA_TESTNET,
        ethereum_client=ethereum_client,
    )


def dashboard_url(safe: str, tx_hash: str) -> str:
    h = tx_hash if tx_hash.startswith("0x") else f"0x{tx_hash}"
    return (
        "https://app.safe.global/transactions/tx?"
        f"safe=basesep:{safe}&id=multisig_{safe}_{h}"
    )


def post_proposed_tx(
    api: TransactionServiceApi,
    safe_tx: SafeTx,
    pk: str,
    safe: str,
    proposer: str,
    *,
    label: str,
    batch_path: Path | None = None,
    nonce: int | None = None,
) -> str:
    safe_tx.sign(pk)
    try:
        api.post_transaction(safe_tx)
    except SafeAPIException as exc:
        print(f"{label}: {exc}", file=sys.stderr)
        raise SystemExit(3) from exc

    tx_hash = safe_tx.safe_tx_hash.hex()
    print(f"Proposed {label}")
    print(f"  safe:       {safe}")
    print(f"  proposer:   {proposer}")
    if batch_path is not None:
        print(f"  batch:      {batch_path}")
    if nonce is not None:
        print(f"  safe_nonce: {nonce}")
    print(f"  safeTxHash: {tx_hash}")
    print(f"  dashboard:  {dashboard_url(safe, tx_hash)}")
    return tx_hash


def compute_create2_address(deployer: str, salt: bytes, init_code: bytes) -> str:
    init_code_hash = keccak(init_code)
    digest = keccak(b"\xff" + bytes.fromhex(deployer[2:]) + salt + init_code_hash)
    return to_checksum_address(digest[-20:])


def predict_immutable_univocity_from_create2_calldata(data: bytes) -> str | None:
    if len(data) < 4 or data[:4] != PERFORM_CREATE2_SELECTOR:
        return None
    _, init_code, salt = decode(["uint256", "bytes", "bytes32"], data[4:])
    return compute_create2_address(CREATE_CALL_ADDRESS, salt, init_code)


def validate_deploy_batch(batch: dict) -> None:
    txs = batch.get("transactions", [])
    if len(txs) != 1:
        print(
            f"Deploy batch must have exactly 1 transaction, got {len(txs)}",
            file=sys.stderr,
        )
        raise SystemExit(4)

    tx0 = txs[0]
    to_addr = to_checksum_address(tx0["to"])
    if to_addr != to_checksum_address(CREATE_CALL_ADDRESS):
        print(
            f"Deploy batch tx0 must target CreateCall {CREATE_CALL_ADDRESS}, "
            f"got {to_addr}",
            file=sys.stderr,
        )
        raise SystemExit(4)

    if int(tx0.get("operation", 0)) != 0:
        print("Deploy batch tx0 must be a CALL (operation 0)", file=sys.stderr)
        raise SystemExit(4)

    expected = os.environ.get("IMUTABLE_UNIVOCITY_ADDRESS")
    if not expected:
        return

    data_hex = tx0["data"]
    data = bytes.fromhex(data_hex[2:] if data_hex.startswith("0x") else data_hex)
    predicted = predict_immutable_univocity_from_create2_calldata(data)
    if predicted is None:
        print(
            "Could not decode performCreate2 calldata for address check",
            file=sys.stderr,
        )
        raise SystemExit(4)

    expected_checksum = to_checksum_address(expected)
    if predicted != expected_checksum:
        print(
            f"IMUTABLE_UNIVOCITY_ADDRESS {expected_checksum} does not match "
            f"CREATE2 prediction {predicted}. Regenerate the deploy batch.",
            file=sys.stderr,
        )
        raise SystemExit(4)


def validate_bootstrap_batch(batch: dict) -> None:
    txs = batch.get("transactions", [])
    if len(txs) != 2:
        print(
            f"Bootstrap batch must have exactly 2 transactions, got {len(txs)}",
            file=sys.stderr,
        )
        raise SystemExit(4)

    tx0, tx1 = txs
    if to_checksum_address(tx0["to"]) != to_checksum_address(SIGN_MESSAGE_LIB_ADDRESS):
        print(
            "Bootstrap tx0 must delegatecall SignMessageLib "
            f"{SIGN_MESSAGE_LIB_ADDRESS}",
            file=sys.stderr,
        )
        raise SystemExit(4)
    if int(tx0.get("operation", 0)) != 1:
        print("Bootstrap tx0 must be DELEGATECALL (operation 1)", file=sys.stderr)
        raise SystemExit(4)
    if int(tx1.get("operation", 0)) != 0:
        print("Bootstrap tx1 must be CALL (operation 0)", file=sys.stderr)
        raise SystemExit(4)

    publish_to = to_checksum_address(tx1["to"])
    legacy = to_checksum_address(LEGACY_IMMUTABLE_UNIVOCITY)
    expected = os.environ.get("IMUTABLE_UNIVOCITY_ADDRESS")

    if expected:
        expected_checksum = to_checksum_address(expected)
        if publish_to != expected_checksum:
            print(
                f"Bootstrap publishCheckpoint target {publish_to} does not match "
                f"IMUTABLE_UNIVOCITY_ADDRESS {expected_checksum}. "
                "Regenerate the bootstrap batch.",
                file=sys.stderr,
            )
            raise SystemExit(4)
    elif publish_to == legacy:
        print(
            f"Bootstrap batch still targets legacy ImutableUnivocity {legacy}. "
            "Set IMUTABLE_UNIVOCITY_ADDRESS or regenerate the bootstrap batch.",
            file=sys.stderr,
        )
        raise SystemExit(4)


def assert_immutable_univocity_deployed(
    client: EthereumClient, address: str, *, label: str = "ImutableUnivocity"
) -> None:
    code = client.w3.eth.get_code(to_checksum_address(address))
    if code in (b"", b"0x"):
        print(
            f"{label} {address} has no code on chain. "
            "Execute the Safe deploy transaction before proposing bootstrap.",
            file=sys.stderr,
        )
        raise SystemExit(5)


def proposer_address(pk: str) -> str:
    return Account.from_key(pk).address
