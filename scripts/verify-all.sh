#!/bin/sh
set -eu

node scripts/check-versions.mjs
npm ci
npm test
npm run test:coverage
npm pack --dry-run
.venv/bin/python -m ruff check python
.venv/bin/python -m pytest --cov=wallet_hd_derivation_kit --cov-fail-under=90 python/tests
cargo fmt --check
cargo test --all-targets
if ! rustup component list >/dev/null 2>&1 && command -v xcrun >/dev/null 2>&1; then
  LLVM_COV="$(xcrun --find llvm-cov)"
  LLVM_PROFDATA="$(xcrun --find llvm-profdata)"
  export LLVM_COV LLVM_PROFDATA
fi
cargo llvm-cov --lib --fail-under-lines 90
go test -race -coverprofile=/tmp/wallethd-go-cover.out ./...
dart analyze
dart test --coverage=coverage
dart run coverage:format_coverage --packages=.dart_tool/package_config.json --report-on=lib --in=coverage --out=coverage/lcov.info --lcov
awk -F: '/^LF:/{lf+=$2} /^LH:/{lh+=$2} END{exit (100*lh/lf < 90)}' coverage/lcov.info
gradle --no-daemon test jacocoTestCoverageVerification
swift test --enable-code-coverage
swift_report="$(swift test --show-codecov-path)"
swift_coverage="$(jq '[.data[0].files[] | select(.filename | contains("/Sources/WalletHDDerivationKit/")) | .summary.lines] | (map(.covered) | add) * 100 / (map(.count) | add)' "$swift_report")"
awk -v coverage="$swift_coverage" 'BEGIN { exit (coverage < 90) }'
npm run conformance
