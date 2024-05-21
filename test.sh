#!/bin/sh
set -eox

RUSTC_MINOR_VERSION=$(rustc --version | awk '{ split($2,a,"."); print a[2] }')
if [ "$RUSTC_MINOR_VERSION" = 63 ]; then
	export RUSTC_BOOTSTRAP=1
	export RUSTFLAGS=--cfg=rust_1_63
fi

cargo test --no-default-features
cargo test
cargo test --no-default-features --features std
cargo test --no-default-features --features tokio
cargo test --no-default-features --features validation
cargo test --features std,tokio,validation
cargo test --no-default-features --features build_server
cargo build --lib
cargo build --lib --features std
cargo build --lib --features tokio
cargo build --lib --features validation
cargo build --lib --features std,tokio,validation
cargo build --lib --features std,tokio,validation --release
cargo build --bin http_proof_gen --features build_server
cargo doc --features std,tokio,validation
cd fuzz
RUSTFLAGS="$RUSTFLAGS --cfg=fuzzing" RUSTC_BOOTSTRAP=1 cargo build --features stdin_fuzz
cd ../bench
RUSTFLAGS="$RUSTFLAGS --cfg=dnssec_validate_bench" cargo bench
