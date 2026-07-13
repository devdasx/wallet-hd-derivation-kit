import { performance } from "node:perf_hooks";
import { readFileSync } from "node:fs";
import os from "node:os";
import {
  deriveAccountPublicKey,
  deriveAddress,
  deriveAddresses,
  deriveAddressFromExtendedPublicKey,
  parseExtendedKey,
  sourceToSeed,
} from "../javascript/src/index.js";

const source = { mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" };
const account = deriveAccountPublicKey({ source, chain: "bitcoin" });

function measure(name, iterations, operation, unit = "ops/sec") {
  for (let index = 0; index < Math.min(iterations, 5); index += 1) operation();
  const started = performance.now();
  for (let index = 0; index < iterations; index += 1) operation();
  const seconds = (performance.now() - started) / 1000;
  return { name, value: unit === "ops/sec" ? iterations / seconds : seconds * 1000 / iterations, unit, iterations };
}

const results = [
  measure("mnemonic + seed validation", 100, () => sourceToSeed(source)),
  measure("account derivation", 50, () => deriveAccountPublicKey({ source, chain: "bitcoin" })),
  measure("one Bitcoin address", 100, () => deriveAddress({ source, chain: "bitcoin" })),
  measure("1,000 Bitcoin addresses", 2, () => deriveAddresses({ source, chain: "bitcoin", count: 1000 }), "ms/batch"),
  measure("xpub watch-only address", 200, () => deriveAddressFromExtendedPublicKey({ extendedPublicKey: account.extendedPublicKey, chain: "bitcoin" })),
  measure("extended-key parse", 10000, () => parseExtendedKey(account.extendedPublicKey)),
  measure("one EVM address", 100, () => deriveAddress({ source, chain: "ethereum" })),
  measure("one Solana address", 100, () => deriveAddress({ source, chain: "solana" })),
];

const report = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  runtime: process.version,
  platform: `${os.platform()} ${os.arch()}`,
  cpu: os.cpus()[0]?.model,
  results,
};

if (process.argv.includes("--check")) {
  const baseline = JSON.parse(readFileSync(new URL("../benchmarks/baseline.json", import.meta.url)));
  for (const result of results) {
    const maximum = baseline.metrics[`${result.name} maxMs`];
    if (maximum === undefined) continue;
    const milliseconds = result.unit === "ops/sec" ? 1000 / result.value : result.value;
    if (milliseconds > maximum) {
      throw new Error(`${result.name} took ${milliseconds.toFixed(3)}ms; regression ceiling is ${maximum}ms`);
    }
  }
}

console.log(JSON.stringify(report, null, 2));
