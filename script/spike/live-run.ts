#!/usr/bin/env bun
/**
 * SPIKE-ONLY driver for the publication enforcer's Base Sepolia live run
 * (devdocs ARC-0032 §4 and §5).
 *
 * It runs the parts the forge scripts beside it cannot: the Lane A forest
 * bootstrap through the release-pinned forestrie CLI, as system-testing's
 * tests/support/forest-bootstrap.ts does; the delegation statements of
 * protocol spec/delegated-spend-statements.md §4, signed and registered
 * through the CLI; their anchoring and proof inputs, from canopy's receipt
 * route; and the transaction measurements.
 *
 * Secrets come only from the environment, through `doppler run` (Doppler
 * univocity/dev for SPIKE_7710_*, system-testing/dev for the lane), and are
 * handed to the CLI only through its environment. Public results go to
 * deployments/spike-7710/; keys, grants and tokens stay in SPIKE_WORK.
 *
 *   doppler run -p univocity -c dev -- doppler run -p system-testing -c dev \
 *     -- bun script/spike/live-run.ts <forest|statements|anchor|measure>
 */
import { spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const RUN_DIR = 'deployments/spike-7710';
const RUN_FILE = join(RUN_DIR, 'run.json');
const BASE_URL = 'https://api-a.forest-2.forestrie.dev';
const COORDINATOR_URL = 'https://coordinator-a.forest-2.forestrie.dev';
const CHAIN_ID = 84532;
const MANAGER = 'db9b1e94b5b69df7e401ddbede43491141047db3';
const DELEGATION_TAG = 'b09bc7d90e4fa6b305d213aa3f89a5df627c8bace691cabe3ccbe1bd85251649';
const CONTENT_TYPE = 'application/univocity.erc7710-delegation+cbor';
const ANCHOR_TIMEOUT_SECONDS = 600;

type Run = Record<string, any>;

function env(name: string): string {
	const v = process.env[name]?.trim();
	if (!v) throw new Error(`${name} is not set`);
	return v;
}

function work(...parts: string[]): string {
	const dir = env('SPIKE_WORK');
	mkdirSync(dir, { recursive: true, mode: 0o700 });
	return join(dir, ...parts);
}

function loadRun(): Run {
	return existsSync(RUN_FILE) ? JSON.parse(readFileSync(RUN_FILE, 'utf8')) : {};
}

function saveRun(update: Run): Run {
	const run = { ...loadRun(), ...update };
	writeFileSync(RUN_FILE, JSON.stringify(run, null, 2) + '\n');
	return run;
}

function now(): string {
	return new Date().toISOString();
}

/** Run the CLI with only the named secrets in its environment. */
function cli(args: string[], secrets: Record<string, string> = {}, timeoutMs = 900_000) {
	const started = Date.now();
	const base: Record<string, string> = {
		PATH: process.env.PATH ?? '',
		HOME: process.env.HOME ?? '',
		NO_COLOR: '1'
	};
	const r = spawnSync(env('FORESTRIE_CLI'), args, {
		env: { ...base, ...secrets },
		encoding: 'utf8',
		timeout: timeoutMs,
		maxBuffer: 64 * 1024 * 1024
	});
	const seconds = (Date.now() - started) / 1000;
	const out = { code: r.status ?? 1, stdout: r.stdout ?? '', stderr: r.stderr ?? '', seconds };
	console.log(`$ forestrie ${args[0]} ${args[1] ?? ''} … exit ${out.code} in ${seconds.toFixed(1)}s`);
	if (out.code !== 0) {
		throw new Error(`forestrie ${args.join(' ')} failed\nstdout: ${out.stdout}\nstderr: ${out.stderr}`);
	}
	return out;
}

function contractLogId(uuid: string): string {
	const hex = uuid.replace(/-/g, '').toLowerCase();
	if (!/^[0-9a-f]{32}$/.test(hex)) throw new Error(`not a 16-byte log id: ${uuid}`);
	return '0x' + hex.padStart(64, '0');
}

// --- forest: a per-run deploy on Lane A ---

function forest() {
	const rpc = env('RPC_URL');
	const deployment = work('deployment.json');
	const hPem = work('h-log.pem');
	const genesis = work('genesis.cbor');
	const times: Run = {};

	times.deployStart = now();
	cli(
		[
			'deploy', '--bootstrap-alg', 'es256', '--bootstrap-es256-generate',
			'--bootstrap-es256-pem-out', hPem, '--out', deployment
		],
		{ DEPLOYER_KEY: env('DEPLOY_KEY'), RPC_URL: rpc }
	);
	times.deployEnd = now();
	const d = JSON.parse(readFileSync(deployment, 'utf8'));
	writeFileSync(join(RUN_DIR, 'deployment.json'), JSON.stringify(d, null, 2) + '\n');
	const root = d.genesisLogId as string;
	saveRun({ instance: d.imutableUnivocity, genesisLogId: root, logH: contractLogId(root) });

	const tokenPath = work('onboard-token');
	cli(
		[
			'admin', 'onboard-token', '--base-url', BASE_URL, '--deployment', deployment,
			'--label', 'spike-7710', '--out', tokenPath
		],
		{ CANOPY_OPS_ADMIN_TOKEN: env('CANOPY_OPS_ADMIN_TOKEN') }
	);
	cli(
		[
			'onboard-genesis', '--base-url', BASE_URL, '--deployment', deployment,
			'--bootstrap-pem', hPem, '--chain-id', String(CHAIN_ID),
			'--coordinator-url', COORDINATOR_URL, '--out', genesis
		],
		{ ONBOARD_TOKEN: readFileSync(tokenPath, 'utf8').trim() }
	);
	times.onboarded = now();
	const sealer = { KNOWN_SEALER_KEY: env('KNOWN_SEALER_KEY') };
	cli(
		['delegate', '--coordinator-url', COORDINATOR_URL, '--log-id', root, '--sign-with', hPem],
		sealer
	);
	const rootGrant = work('root-grant.b64');
	const wait = ['--wait-anchored', '--genesis', genesis, '--anchor-timeout', String(ANCHOR_TIMEOUT_SECONDS)];
	times.rootCreateStart = now();
	cli(
		[
			'create-log', '--base-url', BASE_URL, '--owner-log', root, '--new-log', root,
			'--sign-with', hPem, '--self-referential', '--out-b64', rootGrant, ...wait
		],
		{ RPC_URL: rpc }
	);
	times.rootAnchored = now();

	// L_A: a child of the root, owned by agent A's log key (prepare →
	// delegate → create, ADR-0053), waited on until anchored.
	const aPem = work('agent-a-log.pem');
	writeFileSync(aPem, env('SPIKE_7710_AGENT_A_LOG_PEM') + '\n', { mode: 0o600 });
	const la = randomUUID().toLowerCase();
	saveRun({ logAUuid: la, logA: contractLogId(la) });
	const laGrant = work('la-grant.b64');
	const parent = readFileSync(rootGrant, 'utf8').trim();
	const child = (prepare: boolean) => [
		'create-log', ...(prepare ? ['--prepare'] : []), '--base-url', BASE_URL,
		'--owner-log', root, '--new-log', la, '--signer-pem', aPem, '--sign-with', hPem,
		'--parent-grant-b64', parent, '--out-b64', laGrant, ...(prepare ? [] : wait)
	];
	cli(child(true));
	cli(['delegate', '--coordinator-url', COORDINATOR_URL, '--log-id', la, '--sign-with', aPem], sealer);
	times.laCreateStart = now();
	cli(child(false), { RPC_URL: rpc });
	times.laAnchored = now();
	saveRun({ forestTimes: times });
	console.log(JSON.stringify({ instance: d.imutableUnivocity, root, la, times }, null, 2));
}

// --- deterministic CBOR (every label here encodes in one byte) ---

type Cbor = number | bigint | string | Uint8Array | Cbor[] | Map<number, Cbor>;

function head(major: number, n: bigint): Uint8Array {
	const m = major << 5;
	if (n < 24n) return Uint8Array.of(m | Number(n));
	if (n < 0x100n) return Uint8Array.of(m | 24, Number(n));
	if (n < 0x10000n) return Uint8Array.of(m | 25, Number(n >> 8n), Number(n & 0xffn));
	const size = n < 0x100000000n ? 4 : 8;
	const out = new Uint8Array(1 + size);
	out[0] = m | (size === 4 ? 26 : 27);
	for (let i = 0; i < size; i++) out[size - i] = Number((n >> BigInt(8 * i)) & 0xffn);
	return out;
}

function cbor(v: Cbor): Uint8Array {
	if (typeof v === 'number' || typeof v === 'bigint') {
		const n = BigInt(v);
		return n >= 0n ? head(0, n) : head(1, -1n - n);
	}
	if (typeof v === 'string') {
		const b = new TextEncoder().encode(v);
		return Buffer.concat([head(3, BigInt(b.length)), b]);
	}
	if (v instanceof Uint8Array) return Buffer.concat([head(2, BigInt(v.length)), v]);
	if (Array.isArray(v)) return Buffer.concat([head(4, BigInt(v.length)), ...v.map(cbor)]);
	const keys = [...v.keys()].sort((a, b) => a - b);
	if (keys.some((k) => k < 0 || k > 23)) throw new Error('labels must encode in one byte');
	return Buffer.concat([head(5, BigInt(keys.length)), ...keys.flatMap((k) => [cbor(k), cbor(v.get(k)!)])]);
}

function hex(s: string): Uint8Array {
	return Uint8Array.from(Buffer.from(s.replace(/^0x/, ''), 'hex'));
}

function toHex(b: Uint8Array): string {
	return '0x' + Buffer.from(b).toString('hex');
}

function sha256(...parts: Uint8Array[]): Uint8Array {
	const h = createHash('sha256');
	for (const p of parts) h.update(p);
	return Uint8Array.from(h.digest());
}

// --- delegation statements (protocol spec/delegated-spend-statements.md §4) ---

type SignedHop = {
	delegate: string;
	delegator: string;
	authority: string;
	enforcers: string[];
	terms: string[];
	salt: string;
	signature: string;
	hash: string;
};

/** The delegation statement payload: keys 1 to 7 and 10. */
function delegationPayload(d: SignedHop, delegateLog: string, depth: number, description: string): Uint8Array {
	const hop: Cbor[] = [
		hex(d.delegate),
		hex(d.delegator),
		hex(d.authority),
		d.enforcers.map((e, i) => [hex(e), hex(d.terms[i]!)]),
		hex(d.salt),
		hex(d.signature)
	];
	return cbor(
		new Map<number, Cbor>([
			[1, 1],
			[2, hex(DELEGATION_TAG + d.hash.replace(/^0x/, ''))],
			[3, CHAIN_ID],
			[4, hex(MANAGER)],
			[5, hop],
			[6, hex(delegateLog)],
			[7, depth],
			[10, new Map<number, Cbor>([[3, description]])]
		])
	);
}

/** Bytes before and after TAG ‖ hash, which must occur exactly once. */
function split(statement: Uint8Array, hash: string) {
	const s = Buffer.from(statement);
	const anchor = Buffer.from(DELEGATION_TAG + hash.replace(/^0x/, ''), 'hex');
	const off = s.indexOf(anchor);
	if (off < 0 || s.indexOf(anchor, off + 1) >= 0) throw new Error('TAG ‖ hash must occur once');
	if (s.indexOf(Buffer.from(DELEGATION_TAG, 'hex'), off + 1) >= 0) throw new Error('second tag');
	return { prefix: toHex(s.subarray(0, off)), suffix: toHex(s.subarray(off + 64)), offset: off };
}

const STATEMENTS = [
	{
		name: 'dHA',
		pem: 'h-log.pem',
		grant: 'root-grant.b64',
		logKey: 'logH',
		delegateLogKey: 'logA',
		depth: 2,
		description: 'Spike 7710 live run: the household root lets agent A pay Forestrie fees and one seller'
	},
	{
		name: 'dAB',
		pem: 'agent-a-log.pem',
		grant: 'la-grant.b64',
		logKey: 'logA',
		// Agent B has no log in this run; key 6 is required, so it is zero.
		delegateLogKey: '',
		depth: 1,
		description: 'Spike 7710 live run: agent A lets agent B make single payments'
	}
] as const;

function statements() {
	const run = loadRun();
	const hops = JSON.parse(readFileSync(join(RUN_DIR, 'delegations.json'), 'utf8')) as Record<string, SignedHop>;
	const dir = join(RUN_DIR, 'statements');
	mkdirSync(dir, { recursive: true });
	const records: Run = run.statements ?? {};
	for (const s of STATEMENTS) {
		if (records[s.name]?.entryId) {
			console.log(`${s.name} already registered as ${records[s.name].entryId}`);
			continue;
		}
		const d = hops[s.name]!;
		const delegateLog = s.delegateLogKey ? run[s.delegateLogKey] : '0x' + '00'.repeat(32);
		const payloadPath = join(dir, `${s.name}.payload.cbor`);
		writeFileSync(payloadPath, delegationPayload(d, delegateLog, s.depth, s.description));
		const cosePath = join(dir, `${s.name}.cose`);
		cli([
			'sign-statement', '--key', work(s.pem), '--payload', payloadPath,
			'--content-type', CONTENT_TYPE, '--sub', d.hash.replace(/^0x/, '').toLowerCase(), '--out', cosePath
		]);
		const stmt = new Uint8Array(readFileSync(cosePath));
		if (stmt[0] !== 0x84) throw new Error(`${s.name}: not an untagged COSE_Sign1 (first byte ${stmt[0]})`);
		const parts = split(stmt, d.hash);
		const registeredFrom = now();
		const reg = cli([
			'register', '--json', '--base-url', BASE_URL, '--log-id', run.genesisLogId,
			'--statement', cosePath, '--grant-b64', readFileSync(work(s.grant), 'utf8').trim(),
			'--out', work(`receipt-${s.name}-first.cbor`), '--timeout', '300'
		]);
		const report = JSON.parse(reg.stdout);
		records[s.name] = {
			delegationHash: d.hash,
			log: run[s.logKey],
			entryId: report.entryId,
			receiptUrl: report.receiptUrl,
			registeredFrom,
			receiptAt: now(),
			registerSeconds: reg.seconds,
			statementBytes: stmt.length,
			tagOffset: parts.offset
		};
		saveRun({ statements: records });
		console.log(`${s.name}: entry ${report.entryId}`);
	}
}

// --- anchoring and proof inputs ---

async function rpc(method: string, params: unknown[]): Promise<any> {
	const res = await fetch(env('RPC_URL'), {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params })
	});
	const j = (await res.json()) as { result?: unknown; error?: { message: string } };
	if (j.error) throw new Error(`${method}: ${j.error.message}`);
	return j.result;
}

/** logState(bytes32) size: the third word of the return. */
async function anchoredSize(instance: string, logId: string): Promise<bigint> {
	const data = '0xeecac1b7' + logId.replace(/^0x/, '');
	const r = (await rpc('eth_call', [{ to: instance, data }, 'latest'])) as string;
	return r.length >= 2 + 3 * 64 ? BigInt('0x' + r.slice(2 + 2 * 64, 2 + 3 * 64)) : 0n;
}

function cast(args: string[]): string {
	const r = spawnSync('mise', ['exec', '--', 'cast', ...args, '--rpc-url', env('RPC_URL')], {
		encoding: 'utf8'
	});
	if (r.status !== 0) throw new Error(`cast ${args[0]} failed: ${r.stderr}`);
	return r.stdout.trim();
}

async function anchor() {
	const run = loadRun();
	const records: Run = run.statements;
	const proofs: Run = run.proofs ?? {};
	for (const s of STATEMENTS) {
		const r = records[s.name];
		const idts = BigInt('0x' + r.entryId.slice(0, 16));
		const mmrIndex = BigInt('0x' + r.entryId.slice(16, 32));
		const started = Date.now();
		let size = await anchoredSize(run.instance, r.log);
		while (size <= mmrIndex) {
			if (Date.now() - started > ANCHOR_TIMEOUT_SECONDS * 1000) {
				throw new Error(`${s.name}: not anchored after ${ANCHOR_TIMEOUT_SECONDS}s (size ${size})`);
			}
			await Bun.sleep(5000);
			size = await anchoredSize(run.instance, r.log);
		}
		r.anchoredSeenAt = r.anchoredSeenAt ?? now();
		r.anchoredSize = size.toString();
		r.anchorLatencySeconds =
			(Date.parse(r.anchoredSeenAt) - Date.parse(r.registeredFrom)) / 1000;
		saveRun({ statements: records });

		const res = await fetch(r.receiptUrl);
		if (!res.ok) throw new Error(`${s.name}: receipt route answered ${res.status}`);
		const receiptPath = work(`receipt-${s.name}.cbor`);
		writeFileSync(receiptPath, Buffer.from(await res.arrayBuffer()));
		const decoded = JSON.parse(cli(['decode-receipt', '--json', receiptPath]).stdout);
		const inc = decoded.inclusion ?? decoded.receipt?.inclusion;
		if (BigInt(inc.mmrIndex) !== mmrIndex) throw new Error(`${s.name}: receipt index ${inc.mmrIndex}`);
		const path = (inc.path as string[]).map((p) => '0x' + p.replace(/^0x/, ''));

		const stmt = new Uint8Array(readFileSync(join(RUN_DIR, 'statements', `${s.name}.cose`)));
		const idtsBe = hex(idts.toString(16).padStart(16, '0'));
		const leaf = toHex(sha256(idtsBe, sha256(stmt)));
		const { prefix, suffix } = split(stmt, r.delegationHash);
		const ok = cast([
			'call', run.verifier, 'verifyInclusionAtAnchored(bytes32,uint256,bytes32,bytes32[])(bool)',
			r.log, mmrIndex.toString(), leaf, `[${path.join(',')}]`
		]);
		console.log(`${s.name}: index ${mmrIndex}, anchored size ${size}, path ${path.length}, verifies ${ok}`);
		if (ok !== 'true') throw new Error(`${s.name}: verifier refuses the receipt's path`);
		proofs[s.name] = { prefix, suffix, idTimestamp: idts.toString(), mmrIndex: mmrIndex.toString(), path, leaf };
		saveRun({ proofs });
	}
}

// --- measurements ---

async function measure() {
	const tx = process.argv[3] ?? '';
	const r = await rpc('eth_getTransactionReceipt', [tx]);
	if (!r) throw new Error(`no receipt for ${tx}`);
	const big = (x?: string) => (x === undefined ? undefined : BigInt(x).toString());
	const out = {
		tx,
		status: r.status,
		blockNumber: big(r.blockNumber),
		from: r.from,
		to: r.to,
		gasUsed: big(r.gasUsed),
		effectiveGasPrice: big(r.effectiveGasPrice),
		l2FeeWei: (BigInt(r.gasUsed) * BigInt(r.effectiveGasPrice)).toString(),
		l1FeeWei: big(r.l1Fee),
		l1GasUsed: big(r.l1GasUsed),
		l1GasPrice: big(r.l1GasPrice),
		l1BlobBaseFee: big(r.l1BlobBaseFee),
		logs: r.logs.length
	};
	console.log(JSON.stringify(out, null, 2));
}

// --- the seller path through MetaMask's x402 facilitator ---

const USDC = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
const DELEGATION_MANAGER = '0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3';
const HOSTS: Record<string, { base: string; facilitators: string[] }> = {
	prod: {
		base: 'https://tx-sentinel-base-sepolia.api.cx.metamask.io/platform/v2/x402',
		facilitators: [
			'0xB01caEa8c6C47bbf4F4b4c5080Ca642043359C2E',
			'0xB42F812A44c22cc6b861478900401ee759EbEAD6',
			'0xC066ac5D385419B1A8c43A0E146fA439837a8B8c'
		]
	},
	dev: {
		base: 'https://tx-sentinel-base-sepolia.dev-api.cx.metamask.io/platform/v2/x402',
		facilitators: ['0xb4827A2a066CD2Ef88560EFdf063dD05C6c41cC7']
	}
};

/** The address lists each host's /supported gives for Base Sepolia. */
async function supported(host: string) {
	const res = await fetch(`${HOSTS[host]!.base}/supported`);
	const j = (await res.json()) as any;
	const kind = (j.kinds as any[]).find((k) => k.network === `eip155:${CHAIN_ID}` && k.scheme === 'exact');
	return {
		status: res.status,
		methods: kind?.extra?.assetTransferMethods as string[] | undefined,
		facilitators: (kind?.extra?.facilitatorAddresses ?? []) as string[],
		signers: (j.signers?.['eip155:*'] ?? []) as string[]
	};
}

const same = (a: string[], b: string[]) =>
	a.length === b.length && a.every((x) => b.some((y) => y.toLowerCase() === x.toLowerCase()));

/** Exits non-zero unless both hosts still list exactly the leaf's redeemers. */
async function x402Check() {
	const out: Run = {};
	let ok = true;
	for (const host of Object.keys(HOSTS)) {
		const s = await supported(host);
		const match =
			same(s.facilitators, HOSTS[host]!.facilitators) && same(s.signers, HOSTS[host]!.facilitators) &&
			(s.methods ?? []).includes('erc7710');
		out[host] = { ...s, match, at: now() };
		ok &&= match;
	}
	console.log(JSON.stringify(out, null, 2));
	if (!ok) process.exit(3);
}

async function post(url: string, body: unknown) {
	const started = Date.now();
	const res = await fetch(url, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify(body)
	});
	const text = await res.text();
	let json: unknown;
	try {
		json = JSON.parse(text);
	} catch {
		json = undefined;
	}
	return { status: res.status, seconds: (Date.now() - started) / 1000, body: json ?? text };
}

/**
 * /verify, then /settle, for one seller leaf. Settle runs even after a
 * refused verify, to record what settle itself answers; the leaf is
 * single-use, so a settle can pay at most once.
 */
async function x402Pay() {
	const [host, purpose] = process.argv.slice(3);
	const h = HOSTS[host ?? ''];
	if (!h || !purpose) throw new Error('usage: x402-pay <prod|dev> <purpose>');
	const leaf = JSON.parse(readFileSync(join(RUN_DIR, `${purpose}.json`), 'utf8'));
	const requirements = {
		scheme: 'exact',
		network: `eip155:${CHAIN_ID}`,
		amount: String(leaf.amount),
		asset: USDC,
		payTo: leaf.payTo,
		maxTimeoutSeconds: 300,
		extra: { assetTransferMethod: 'erc7710', name: 'USDC', version: '2', facilitatorAddresses: h.facilitators }
	};
	const body = {
		x402Version: 2,
		paymentPayload: {
			x402Version: 2,
			resource: {
				url: 'https://forestrie.dev/spike-7710/seller-resource',
				description: 'Spike 7710 seller payment (Base Sepolia test USDC)',
				mimeType: 'application/json'
			},
			accepted: requirements,
			payload: {
				delegationManager: DELEGATION_MANAGER,
				permissionContext: leaf.permissionContext,
				delegator: leaf.delegator
			},
			extensions: {}
		},
		paymentRequirements: requirements
	};
	const record: Run = { host, base: h.base, leaf: leaf.leaf, request: body, at: now() };
	record.verify = await post(`${h.base}/verify`, body);
	console.log(`verify ${record.verify.status}: ${JSON.stringify(record.verify.body)}`);
	record.settle = await post(`${h.base}/settle`, body);
	console.log(`settle ${record.settle.status}: ${JSON.stringify(record.settle.body)}`);
	writeFileSync(join(RUN_DIR, `${purpose}-facilitator.json`), JSON.stringify(record, null, 2) + '\n');
}

// --- main ---

const commands: Record<string, () => void | Promise<void>> = {
	forest,
	statements,
	anchor,
	measure,
	'x402-check': x402Check,
	'x402-pay': x402Pay
};
const cmd = process.argv[2] ?? '';
if (!commands[cmd]) {
	console.error(`usage: live-run.ts <${Object.keys(commands).join('|')}>`);
	process.exit(2);
}
await commands[cmd]!();
