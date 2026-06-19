# Variables
APP_NAME := telemt
CARGO := cargo

# Targets
AMD64_TARGET := x86_64-unknown-linux-gnu
ARM64_TARGET := aarch64-unknown-linux-gnu

.PHONY: all arm64 amd64 clean help bench bench_clean

## Default target: build for the native architecture (assumed arm64 based on your command)
all: arm64 amd64

release:
	$(CARGO) build --release

arm64:
	@echo "Building for ARM64..."
	$(CARGO) build --target=$(ARM64_TARGET) --release

box:
	@echo "Building for ARM64 (box)..."
	RUSTFLAGS="-C target-cpu=cortex-a53" $(CARGO) build --release
	
amd64:
	@echo "Building for AMD64..."
	$(CARGO) build --target=$(AMD64_TARGET) --release

ali:
	@echo "Building for AMD64..."
	RUSTFLAGS="-C target-cpu=x86-64-v4" $(CARGO) build --target=$(AMD64_TARGET) --release

docker:
	docker build -t telemt:uds .

## Remove build artifacts
clean:
	@echo "Cleaning project..."
	$(CARGO) clean


## Show help
help:
	@      
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  arm64       Build release binary for ARM64 (native)"
	@echo "  amd64       Build release binary for AMD64 (x86_64-unknown-linux-gnu)"
	@echo "  clean       Remove target directory"
