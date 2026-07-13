import { readFileSync } from "node:fs";

const expected = (process.env.RELEASE_VERSION || process.env.GITHUB_REF_NAME?.replace(/^v/, "") || "1.0.0").trim();
const checks = [
  ["package.json", /"version":\s*"([^"]+)"/],
  ["jsr.json", /"version":\s*"([^"]+)"/],
  ["pyproject.toml", /^version = "([^"]+)"/m],
  ["Cargo.toml", /^version = "([^"]+)"/m],
  ["pubspec.yaml", /^version: ([^\s]+)/m],
  ["build.gradle.kts", /^version = "([^"]+)"/m],
  ["WalletHDDerivationKit.podspec", /spec\.version = "([^"]+)"/],
  ["install.sh", /^VERSION="([^"]+)"/m],
  ["install.ps1", /\$Version = "([^"]+)"/],
  ["CITATION.cff", /^version: ([^\s]+)/m],
  ["codemeta.json", /"version":\s*"([^"]+)"/],
];
let failed = false;
for (const [file, pattern] of checks) {
  const match = readFileSync(file, "utf8").match(pattern);
  if (!match || match[1] !== expected) {
    console.error(`${file}: expected ${expected}, found ${match?.[1] ?? "no version"}`);
    failed = true;
  }
}
if (failed) process.exit(1);
console.log(`version-sync: ${checks.length} manifests agree on ${expected}`);
