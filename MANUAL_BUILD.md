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
# Build using Docker with macOS ARM64
docker run --rm --platform darwin/arm64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add aarch64-apple-darwin &&
cargo build --release --target aarch64-apple-darwin --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/aarch64-apple-darwin/release/libdnssec_prover_uniffi.dylib dist/libuniffi_dnssec_prover_darwin_arm64.dylib
"
```

### 2. Build for macOS x86_64 (Intel)

```bash
# Build using Docker with macOS x86_64
docker run --rm --platform darwin/amd64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add x86_64-apple-darwin &&
cargo build --release --target x86_64-apple-darwin --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/x86_64-apple-darwin/release/libdnssec_prover_uniffi.dylib dist/libuniffi_dnssec_prover_darwin_x86_64.dylib
"
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
docker run --rm --platform windows/amd64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add x86_64-pc-windows-msvc &&
cargo build --release --target x86_64-pc-windows-msvc --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/x86_64-pc-windows-msvc/release/dnssec_prover_uniffi.dll dist/libuniffi_dnssec_prover_windows_amd64.dll
"
```


## Complete Build Script

For the ultimate convenience, here's a script that builds everything using Docker:

```bash
# Create complete build script
cat > build-all-platforms.sh << 'EOF'
#!/bin/bash
set -e

echo "Building DNSSEC Prover for all platforms using Docker..."

mkdir -p dist

# macOS builds (Docker)
echo "Building macOS ARM64..."
docker run --rm --platform darwin/arm64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add aarch64-apple-darwin &&
cargo build --release --target aarch64-apple-darwin --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/aarch64-apple-darwin/release/libdnssec_prover_uniffi.dylib dist/libuniffi_dnssec_prover_darwin_arm64.dylib
"

echo "Building macOS x86_64..."
docker run --rm --platform darwin/amd64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add x86_64-apple-darwin &&
cargo build --release --target x86_64-apple-darwin --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/x86_64-apple-darwin/release/libdnssec_prover_uniffi.dylib dist/libuniffi_dnssec_prover_darwin_x86_64.dylib
"

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
docker run --rm --platform windows/amd64 -v $(pwd):/workspace -w /workspace rust:latest bash -c "
rustup target add x86_64-pc-windows-msvc &&
cargo build --release --target x86_64-pc-windows-msvc --manifest-path uniffi/Cargo.toml &&
cp uniffi/target/x86_64-pc-windows-msvc/release/dnssec_prover_uniffi.dll dist/libuniffi_dnssec_prover_windows_amd64.dll
"

echo "All platforms built successfully!"
echo "Libraries in dist/:"
ls -la dist/
EOF

# Make executable and run
chmod +x build-all-platforms.sh
./build-all-platforms.sh
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

## Verify Builds

Check that all libraries were built with correct sizes:

```bash
ls -la dist/
```

Expected output:
```
libuniffi_dnssec_prover_darwin_arm64.dylib     # ~600KB
libuniffi_dnssec_prover_darwin_x86_64.dylib     # ~619KB
libuniffi_dnssec_prover_linux_aarch64.so        # ~646KB
libuniffi_dnssec_prover_linux_armv6l.so         # ~603KB
libuniffi_dnssec_prover_linux_armv7l.so         # ~582KB
libuniffi_dnssec_prover_linux_x86_64.so         # ~665KB
libuniffi_dnssec_prover_windows_amd64.dll        # ~613KB
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