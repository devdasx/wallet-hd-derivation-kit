import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import process from "node:process";

const root = new URL("../", import.meta.url).pathname;
const expectedVectors = JSON.parse(readFileSync(new URL("../test-vectors/public-vectors.json", import.meta.url)));
const expected = Object.fromEntries(expectedVectors.addresses.map(({ chain, address }) => [chain, address]));
const runners = [
  ["javascript", "node", ["javascript/test/conformance-runner.mjs"]],
  ["python", `${root}.venv/bin/python`, ["python/tests/conformance_runner.py"]],
  ["rust", "cargo", ["run", "--quiet", "--bin", "conformance"]],
  ["go", "go", ["run", "./cmd/conformance"]],
  ["dart", "dart", ["run", "tool/conformance.dart"]],
  ["kotlin", "gradle", ["--quiet", "conformance"]],
  ["swift", "swift", ["run", "--quiet", "WalletHDConformance"]],
];

let reference;
const normalized = (value) => JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b))));
for (const [name, command, args] of runners) {
  const output = execFileSync(command, args, { cwd: root, encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
  const line = output.split(/\r?\n/).find((value) => value.startsWith("WALLETHD_CONFORMANCE="));
  if (!line) throw new Error(`${name} did not emit conformance JSON`);
  const value = JSON.parse(line.slice("WALLETHD_CONFORMANCE=".length));
  if (normalized(value) !== normalized(expected)) {
    const differences = Object.keys(expected).filter((chain) => value[chain] !== expected[chain]);
    throw new Error(`${name} disagrees with public vectors for: ${differences.join(", ")}`);
  }
  reference ??= value;
  if (normalized(value) !== normalized(reference)) throw new Error(`${name} disagrees with the reference implementation`);
  console.log(`conformance: ${name} verified ${Object.keys(value).length} chains`);
}
console.log(`conformance: all ${runners.length} native implementations agree`);
