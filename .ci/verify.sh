#!/usr/bin/env bash
set -euo pipefail
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}"
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
export GITHUB_PATH="${GITHUB_PATH:-$RUNNER_TEMP/github_path}"
touch "$GITHUB_PATH"

cargo metadata --locked --format-version 1 > dependency-metadata.json
python3 .github/check-first-party.py
python3 .github/test-check-coverage.py
rustc --version
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo check --locked --target wasm32-unknown-unknown
bash scripts/wasm-runner.sh
export PATH="$(tail -n 1 "$GITHUB_PATH"):$PATH"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
cargo test --locked --target wasm32-unknown-unknown --no-default-features --lib --test shared --test published

rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
"$NIGHTLY_CARGO" llvm-cov --locked --branch --ignore-filename-regex '(^|/)(tests|scripts)/' --json --output-path coverage.json
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '(^|/)(tests|scripts)/' --text --show-instantiations --output-path coverage.txt
"$NIGHTLY_CARGO" llvm-cov report --branch --ignore-filename-regex '(^|/)(tests|scripts)/' --lcov --output-path coverage.lcov
python3 .github/test-check-coverage.py
python3 .github/check-coverage.py coverage.lcov coverage.json coverage.txt
