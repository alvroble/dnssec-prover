# Manual Build Guide: DNSSEC Prover Python Bindings

This guide shows how to manually build DNSSEC Prover for all supported platforms using Docker and create Python bindings.

## Prerequisites

- **Docker**: Install Docker Desktop or Docker Engine
- **Python**: Version 3.7 or later
- **uniffi-bindgen**: `pip install uniffi-bindgen`

## Docker Build Approach

Instead of cross-compilation, we'll use Docker to build natively for each platform. This is more reliable and avoids linker issues.

## Build Process

### 1. Build for macOS ARM64 (Apple Silicon)

```bash
# Not available for cross-compilation. Must be built from macOS ARM64
rustup target add aarch64-apple-darwin &&
cargo build --release --target aarch64-apple-darwin --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/aarch64-apple-darwin/release/libdnssec_prover_uniffi.dylib dist/libuniffi_dnssec_prover_darwin_arm64.dylib
```

### 2. Build for macOS x86_64 (Intel)

```bash
# Not available for cross-compilation. Must be built from macOS x86_64
rustup target add x86_64-apple-darwin &&
cargo build --release --target x86_64-apple-darwin --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/x86_64-apple-darwin/release/libdnssec_prover_uniffi.dylib dist/libuniffi_dnssec_prover_darwin_x86_64.dylib
```

### 3. Build for Linux ARM64

```bash
# Build using Docker with ARM64 Linux
docker run --rm --platform linux/arm64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add aarch64-unknown-linux-gnu &&
cargo build --release --target aarch64-unknown-linux-gnu --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/aarch64-unknown-linux-gnu/release/libdnssec_prover_uniffi.so dist/libuniffi_dnssec_prover_linux_aarch64.so
"
```

### 4. Build for Linux ARMv6

```bash
# Build using Docker with ARMv6 Linux (use linux/arm for compatibility)
docker run --rm --platform linux/arm -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add arm-unknown-linux-gnueabihf &&
cargo build --release --target arm-unknown-linux-gnueabihf --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/arm-unknown-linux-gnueabihf/release/libdnssec_prover_uniffi.so dist/libuniffi_dnssec_prover_linux_armv6l.so
"
```

### 5. Build for Linux ARMv7

```bash
# Build using Docker with ARMv7 Linux (use linux/arm for compatibility)
docker run --rm --platform linux/arm -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add armv7-unknown-linux-gnueabihf &&
cargo build --release --target armv7-unknown-linux-gnueabihf --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/armv7-unknown-linux-gnueabihf/release/libdnssec_prover_uniffi.so dist/libuniffi_dnssec_prover_linux_armv7l.so
"
```

### 6. Build for Linux x86_64

```bash
# Build using Docker with x86_64 Linux
docker run --rm --platform linux/amd64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add x86_64-unknown-linux-gnu &&
cargo build --release --target x86_64-unknown-linux-gnu --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/x86_64-unknown-linux-gnu/release/libdnssec_prover_uniffi.so dist/libuniffi_dnssec_prover_linux_x86_64.so
"
```

### 7. Build for Windows AMD64

```bash
# Build using Docker with Windows container
# rust:latest is not published as Windows container, so we compile from a x86_64 Linux container
docker run --rm --platform linux/amd64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add x86_64-pc-windows-gnu &&
cargo build --release --target x86_64-pc-windows-gnu --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/x86_64-pc-windows-gnu/release/dnssec_prover_uniffi.dll dist/libuniffi_dnssec_prover_windows_amd64.dll
"
```


## Complete Build Script

For the ultimate convenience, here's a script that builds everything using Docker:

```bash
# Create complete build script (remove macOS builds if running from Linux)
cat > build-all-platforms.sh << 'EOF'
#!/bin/bash
set -e

echo "Building DNSSEC Prover for all platforms using Docker..."

mkdir -p dist

# macOS builds 
echo "Building macOS ARM64..."
rustup target add aarch64-apple-darwin &&
cargo build --release --target aarch64-apple-darwin --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/aarch64-apple-darwin/release/libdnssec_prover_uniffi.dylib dist/libuniffi_dnssec_prover_darwin_arm64.dylib

echo "Building macOS x86_64..."
rustup target add x86_64-apple-darwin &&
cargo build --release --target x86_64-apple-darwin --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/x86_64-apple-darwin/release/libdnssec_prover_uniffi.dylib dist/libuniffi_dnssec_prover_darwin_x86_64.dylib

# Linux builds (Docker)
echo "Building Linux ARM64..."
docker run --rm --platform linux/arm64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add aarch64-unknown-linux-gnu &&
cargo build --release --target aarch64-unknown-linux-gnu --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/aarch64-unknown-linux-gnu/release/libdnssec_prover_uniffi.so dist/libuniffi_dnssec_prover_linux_aarch64.so
"

echo "Building Linux ARMv6..."
docker run --rm --platform linux/arm -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add arm-unknown-linux-gnueabihf &&
cargo build --release --target arm-unknown-linux-gnueabihf --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/arm-unknown-linux-gnueabihf/release/libdnssec_prover_uniffi.so dist/libuniffi_dnssec_prover_linux_armv6l.so
"

echo "Building Linux ARMv7..."
docker run --rm --platform linux/arm -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add armv7-unknown-linux-gnueabihf &&
cargo build --release --target armv7-unknown-linux-gnueabihf --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/armv7-unknown-linux-gnueabihf/release/libdnssec_prover_uniffi.so dist/libuniffi_dnssec_prover_linux_armv7l.so
"

echo "Building Linux x86_64..."
docker run --rm --platform linux/amd64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add x86_64-unknown-linux-gnu &&
cargo build --release --target x86_64-unknown-linux-gnu --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/x86_64-unknown-linux-gnu/release/libdnssec_prover_uniffi.so dist/libuniffi_dnssec_prover_linux_x86_64.so
"

# Windows build (Docker)
echo "Building Windows AMD64..."
docker run --rm --platform linux/amd64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
apt-get update &&
apt-get install -y mingw-w64 &&
rustup target add x86_64-pc-windows-gnu &&
cargo build --release --target x86_64-pc-windows-gnu --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/x86_64-pc-windows-gnu/release/dnssec_prover_uniffi.dll dist/libuniffi_dnssec_prover_windows_amd64.dll
"

shasum -a 256 dist/libuniffi_dnssec_prover_*
EOF

# Make executable and run
chmod +x build-all-platforms.sh
./build-all-platforms.sh
```

### Expected hash output:
```bash
6ef0d1d762a0171b0ff2d5b09730096667be252ebf9cb7aafe5a09de4a5e839b  dist/libuniffi_dnssec_prover_darwin_arm64.dylib
35128508261ac7e2185fdeb7f8af0f811e8924cf4237e5d717bd9b7aa1be6f85  dist/libuniffi_dnssec_prover_darwin_x86_64.dylib
678c0e0566b361099b800bc457b74f041afb4b88aed8eee8681b21ffccf5ce0d  dist/libuniffi_dnssec_prover_linux_aarch64.so
9a7762204ca92e34b64c97dfbb52a3f25210e00c950409288d91e97feb9d5e45  dist/libuniffi_dnssec_prover_linux_armv6l.so
88e8d790bd21f686b7828798bcd0fb99adb9d1513be774f4a7f0cde462c77ff4  dist/libuniffi_dnssec_prover_linux_armv7l.so
66fab93c1ab388f4e09775e9be6cc70a9f8fe0778924719ea8758dafdfd7087a  dist/libuniffi_dnssec_prover_linux_x86_64.so
4d13fe7e0ee376105098f2132e58fa90bb892a9154212c86236405eb3d14a612  dist/libuniffi_dnssec_prover_windows_amd64.dll
```


## Generate Python Bindings

After building all platforms, generate Python bindings:

```bash
cd uniffi
cargo run --bin uniffi-bindgen generate \
  --library ../dist/libuniffi_dnssec_prover_linux_x86_64.so \
  --out-dir ../python-bindings \
  --language python
```

## Install Python Package

```bash
cd python-bindings
python setup.py install
```

## Test Installation

```python
import dnssec_prover
print("DNSSEC Prover imported successfully!")
``` 