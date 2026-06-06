import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import Safe from "@safe-global/protocol-kit";
import SafeApiKit from "@safe-global/api-kit";
import { JsonRpcProvider } from "ethers";

const CHAIN_ID = 84532n;
const DEFAULT_SAFE = "0x1528b86ff561f617602356efdbD05908a07AA788";
const DEFAULT_BATCH = resolve(
  import.meta.dirname,
  "../../deployments/safe/imutable-univocity-84532-safe-0x1528b86ff561f617602356efdbD05908a07AA788.json",
);

const rpc = process.env.RPC_URL;
const pk = process.env.DEPLOY_KEY?.startsWith("0x")
  ? process.env.DEPLOY_KEY
  : `0x${process.env.DEPLOY_KEY}`;
const safeAddress = process.env.SAFE_ADDRESS ?? DEFAULT_SAFE;
const batchPath = process.env.SAFE_BATCH_JSON ?? DEFAULT_BATCH;

if (!rpc || !pk) {
  console.error("RPC_URL and DEPLOY_KEY are required");
  process.exit(1);
}

const batch = JSON.parse(readFileSync(batchPath, "utf8"));
const tx = batch.transactions[0];

const provider = new JsonRpcProvider(rpc, { chainId: Number(CHAIN_ID), name: "base-sepolia" });
const protocolKit = await Safe.init({
  provider,
  signer: pk,
  safeAddress,
});

const deployed = await protocolKit.isSafeDeployed();
if (!deployed) {
  console.error(
    `Safe ${safeAddress} is not deployed on chain ${CHAIN_ID}. ` +
      "Deploy or activate it in the Safe UI before proposing via the Transaction Service.",
  );
  process.exit(2);
}

const safeTransaction = await protocolKit.createTransaction({
  transactions: [
    {
      to: tx.to,
      value: tx.value,
      data: tx.data,
      operation: tx.operation,
    },
  ],
});

const signed = await protocolKit.signTransaction(safeTransaction);
const safeTxHash = await protocolKit.getTransactionHash(signed);
const senderAddress = await protocolKit.getAddress();

const apiKit = new SafeApiKit({ chainId: CHAIN_ID });
await apiKit.proposeTransaction({
  safeAddress,
  safeTransactionData: signed.data,
  safeTxHash,
  senderAddress,
  senderSignature: signed.encodedSignatures(),
});

console.log(
  JSON.stringify(
    {
      safeAddress,
      safeTxHash,
      senderAddress,
      dashboard: `https://app.safe.global/transactions/tx?safe=basesep:${safeAddress}&id=${safeTxHash}`,
    },
    null,
    2,
  ),
);
