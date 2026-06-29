#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";

import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { GasPrice } from "@cosmjs/stargate";
import { SigningCosmWasmClient } from "@cosmjs/cosmwasm-stargate";

const DORA_DECIMALS = 18n;
const DEFAULT_COST_GAS_PRICE_PEAKA = 100000000000n;

function usage() {
  return `usage:
  node scripts/run_cosmwasm_round_e2e.mjs --manifest fixtures/round-e2e.local.json

The manifest deploys the AMACI round E2E CosmWasm contract, submits each SP1
compressed proof stage, and writes per-transaction gas/DORA cost metrics.`;
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      throw new Error(usage());
    }
    if (arg === "--manifest") {
      out.manifest = argv[++i];
      continue;
    }
    throw new Error(`unknown argument: ${arg}\n\n${usage()}`);
  }
  if (!out.manifest) {
    throw new Error(`missing --manifest\n\n${usage()}`);
  }
  return out;
}

function readJson(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

function resolveInputPath(manifestDir, value) {
  if (path.isAbsolute(value)) return value;
  const cwdPath = path.resolve(value);
  if (existsSync(cwdPath)) return cwdPath;
  return path.resolve(manifestDir, value);
}

function readMnemonic(manifest, manifestDir) {
  if (manifest.mnemonicEnv && process.env[manifest.mnemonicEnv]) {
    return process.env[manifest.mnemonicEnv].trim();
  }
  if (manifest.mnemonicFile) {
    const parsed = readJson(resolveInputPath(manifestDir, manifest.mnemonicFile));
    if (typeof parsed.mnemonic === "string") return parsed.mnemonic.trim();
  }
  if (process.env.MNEMONIC) return process.env.MNEMONIC.trim();
  throw new Error("missing mnemonic: set mnemonicEnv, mnemonicFile, or MNEMONIC");
}

function parsePeaka(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  return BigInt(value.toString());
}

function peakaToDora(peaka) {
  const scale = 10n ** DORA_DECIMALS;
  const whole = peaka / scale;
  const frac = (peaka % scale).toString().padStart(Number(DORA_DECIMALS), "0");
  return `${whole}.${frac.slice(0, 9)}`;
}

function costForGas(gas, gasPricePeaka) {
  return BigInt(gas.toString()) * gasPricePeaka;
}

function feeForGas(gas, gasPricePeaka, denom) {
  return {
    gas: gas.toString(),
    amount: [{ denom, amount: costForGas(gas, gasPricePeaka).toString() }],
  };
}

function wrapStageMessage(stage, verifyMsg) {
  if (!verifyMsg.verify_compressed) {
    throw new Error(`stage ${stage} msg must contain verify_compressed`);
  }
  const { proof, public_values, vkey_hash } = verifyMsg.verify_compressed;
  return {
    verify_compressed_stage: {
      stage,
      proof,
      public_values,
      vkey_hash,
    },
  };
}

function txSummary(label, result, costGasPricePeaka, extra = {}) {
  const gasUsed = BigInt(result.gasUsed ?? 0);
  const gasWanted = BigInt(result.gasWanted ?? 0);
  const costPeaka = costForGas(gasUsed, costGasPricePeaka);
  return {
    label,
    height: result.height,
    txhash: result.transactionHash,
    code: result.code ?? 0,
    gasWanted: gasWanted.toString(),
    gasUsed: gasUsed.toString(),
    costPeaka: costPeaka.toString(),
    costDora: peakaToDora(costPeaka),
    ...extra,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifestPath = path.resolve(args.manifest);
  const manifest = readJson(manifestPath);
  const manifestDir = path.dirname(manifestPath);

  const rpc = manifest.rpc ?? "http://127.0.0.1:26657";
  const chainId = manifest.chainId ?? "zkvm-amaci-devnet";
  const prefix = manifest.prefix ?? "dora";
  const denom = manifest.denom ?? "peaka";
  const signGasPricePeaka = parsePeaka(manifest.signGasPricePeaka, 0n);
  const costGasPricePeaka = parsePeaka(
    manifest.costGasPricePeaka,
    DEFAULT_COST_GAS_PRICE_PEAKA,
  );
  const wasmPath = resolveInputPath(manifestDir, manifest.wasmPath);
  const outDir = path.resolve(
    manifest.outputDir ?? `round-e2e-results/${new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14)}`,
  );
  mkdirSync(outDir, { recursive: true });

  const wallet = await DirectSecp256k1HdWallet.fromMnemonic(readMnemonic(manifest, manifestDir), {
    prefix,
  });
  const [account] = await wallet.getAccounts();
  const client = await SigningCosmWasmClient.connectWithSigner(rpc, wallet, {
    gasPrice: GasPrice.fromString(`${signGasPricePeaka}${denom}`),
    broadcastTimeoutMs: manifest.broadcastTimeoutMs ?? 180_000,
    broadcastPollIntervalMs: manifest.broadcastPollIntervalMs ?? 3_000,
  });

  const rows = [];
  const wasm = readFileSync(wasmPath);
  const uploadFee =
    manifest.uploadGas === "auto" || manifest.uploadGas === undefined
      ? "auto"
      : feeForGas(BigInt(manifest.uploadGas), signGasPricePeaka, denom);
  const upload = await client.upload(account.address, wasm, uploadFee, manifest.uploadMemo ?? "");
  rows.push(
    txSummary("store_code", upload, costGasPricePeaka, {
      codeId: upload.codeId,
      wasmBytes: wasm.length,
    }),
  );

  const instantiateMsg = {
    round_id: manifest.roundId ?? "zkvm-amaci-round-e2e",
    expected: manifest.expected,
  };
  const instantiateFee =
    manifest.instantiateGas === "auto" || manifest.instantiateGas === undefined
      ? "auto"
      : feeForGas(BigInt(manifest.instantiateGas), signGasPricePeaka, denom);
  const instantiate = await client.instantiate(
    account.address,
    upload.codeId,
    instantiateMsg,
    manifest.label ?? `zkvm-amaci-round-e2e-${Date.now()}`,
    instantiateFee,
    { memo: manifest.instantiateMemo ?? "" },
  );
  rows.push(
    txSummary("instantiate_round", instantiate, costGasPricePeaka, {
      contractAddress: instantiate.contractAddress,
    }),
  );

  for (const stageConfig of manifest.stages) {
    const msgPath = resolveInputPath(manifestDir, stageConfig.msgPath);
    const verifyMsg = readJson(msgPath);
    const executeMsg = wrapStageMessage(stageConfig.stage, verifyMsg);
    const executeGas = BigInt(stageConfig.gas ?? manifest.executeGas ?? 300_000_000);
    const executeFee =
      stageConfig.gas === "auto" || manifest.executeGas === "auto"
        ? "auto"
        : feeForGas(executeGas, signGasPricePeaka, denom);
    const result = await client.execute(
      account.address,
      instantiate.contractAddress,
      executeMsg,
      executeFee,
      stageConfig.memo ?? `verify ${stageConfig.stage}`,
    );
    rows.push(
      txSummary(stageConfig.label ?? stageConfig.stage, result, costGasPricePeaka, {
        stage: stageConfig.stage,
        msgPath,
        msgBytes: Buffer.byteLength(JSON.stringify(executeMsg)),
      }),
    );
  }

  const state = await client.queryContractSmart(instantiate.contractAddress, {
    round_state: {},
  });
  const totalCostPeaka = rows.reduce((acc, row) => acc + BigInt(row.costPeaka), 0n);
  const summary = {
    manifest: manifestPath,
    rpc,
    chainId,
    denom,
    signer: account.address,
    contractAddress: instantiate.contractAddress,
    codeId: upload.codeId,
    signGasPricePeaka: signGasPricePeaka.toString(),
    costGasPricePeaka: costGasPricePeaka.toString(),
    totalCostPeaka: totalCostPeaka.toString(),
    totalCostDora: peakaToDora(totalCostPeaka),
    roundState: state,
    transactions: rows,
  };

  writeFileSync(path.join(outDir, "summary.json"), JSON.stringify(summary, null, 2));
  writeFileSync(path.join(outDir, "summary.md"), renderMarkdown(summary));
  console.log(JSON.stringify(summary, null, 2));
  await client.disconnect();
}

function renderMarkdown(summary) {
  const lines = [
    "# AMACI Round E2E Cost",
    "",
    `- chain: ${summary.chainId}`,
    `- contract: ${summary.contractAddress}`,
    `- signer: ${summary.signer}`,
    `- cost gas price: ${summary.costGasPricePeaka} peaka/gas`,
    `- total estimated cost: ${summary.totalCostDora} DORA`,
    `- final round complete: ${summary.roundState.is_complete}`,
    "",
    "| step | stage | gas used | estimated DORA | tx hash |",
    "| --- | --- | ---: | ---: | --- |",
  ];
  for (const row of summary.transactions) {
    lines.push(
      `| ${row.label} | ${row.stage ?? ""} | ${row.gasUsed} | ${row.costDora} | ${row.txhash} |`,
    );
  }
  lines.push("");
  return `${lines.join("\n")}\n`;
}

main().catch((err) => {
  console.error(err?.stack ?? err);
  process.exit(1);
});
