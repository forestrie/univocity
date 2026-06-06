import Safe from "@safe-global/protocol-kit";

const TARGET = "0x1528b86ff561f617602356efdbD05908a07AA788".toLowerCase();
const rpc = process.env.RPC_URL;
const owner = process.env.OWNER_ADDRESS;
if (!rpc || !owner) {
  console.error("Need RPC_URL and OWNER_ADDRESS");
  process.exit(1);
}

const ownerLists = [[owner]];

const salts = ["0", "1", "12345", String(Date.now()).slice(0, 8)];
const thresholds = [1, 2];

for (const owners of ownerLists.filter((o) => o.length && o[0])) {
  for (const threshold of thresholds) {
    if (threshold > owners.length) continue;
    for (const saltNonce of salts) {
      const kit = await Safe.init({
        provider: rpc,
        signer: process.env.DEPLOY_KEY,
        predictedSafe: {
          safeAccountConfig: { owners, threshold },
          safeDeploymentConfig: { saltNonce, safeVersion: "1.4.1" },
        },
      });
      const addr = (await kit.getAddress()).toLowerCase();
      if (addr === TARGET) {
        console.log(
          JSON.stringify({ match: true, owners, threshold, saltNonce, safeVersion: "1.4.1" }),
        );
        process.exit(0);
      }
    }
  }
}
console.log(JSON.stringify({ match: false }));
