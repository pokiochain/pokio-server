#!/bin/bash

echo "[*] Checking if Rust is installed..."

echo "[*] Installing system dependencies (build-essential, curl, etc)..."
sudo apt-get update
sudo apt-get install -y build-essential curl pkg-config libssl-dev git

if ! command -v rustc &> /dev/null; then
    echo "[*] Rust is not installed. Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "[*] Rust is already installed. Continuing..."
fi

echo "[*] Setting RUSTFLAGS..."
export RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C codegen-units=1 -C panic=abort"

echo "[*] Building with cargo release profile..."
cargo build --release

if [ $? -ne 0 ]; then
    echo "[!] Build failed."
    exit 1
fi

echo "[*] Build successful!"
echo "[*] Output binary:"
echo "    target/release/pokio"
