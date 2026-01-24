.PHONY: build build-release run clean test fmt lint check install

# Binary name
BINARY_NAME=ssl-toolkit

# Build debug version
build:
	@echo "Building debug version..."
	@cargo build

# Build release version
build-release:
	@echo "Building release version..."
	@cargo build --release

# Run the application (debug)
run:
	@cargo run

# Run with arguments
run-args:
	@cargo run -- $(ARGS)

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@cargo clean

# Run tests
test:
	@echo "Running tests..."
	@cargo test

# Format code
fmt:
	@echo "Formatting code..."
	@cargo fmt

# Run linter
lint:
	@echo "Running clippy..."
	@cargo clippy -- -D warnings

# Check compilation without building
check:
	@echo "Checking..."
	@cargo check

# Install locally
install:
	@echo "Installing..."
	@cargo install --path .

# Build for all platforms (for releases)
build-all:
	@echo "Building for all platforms..."
	@mkdir -p dist
	@cargo build --release --target x86_64-unknown-linux-gnu
	@cargo build --release --target x86_64-pc-windows-gnu
	@cargo build --release --target x86_64-apple-darwin
	@cargo build --release --target aarch64-apple-darwin
	@cp target/x86_64-unknown-linux-gnu/release/$(BINARY_NAME) dist/$(BINARY_NAME)-linux-amd64
	@cp target/x86_64-pc-windows-gnu/release/$(BINARY_NAME).exe dist/$(BINARY_NAME)-windows-amd64.exe
	@cp target/x86_64-apple-darwin/release/$(BINARY_NAME) dist/$(BINARY_NAME)-darwin-amd64
	@cp target/aarch64-apple-darwin/release/$(BINARY_NAME) dist/$(BINARY_NAME)-darwin-arm64

# Help
help:
	@echo "Available targets:"
	@echo "  build         - Build debug version"
	@echo "  build-release - Build release version"
	@echo "  run           - Run the application"
	@echo "  clean         - Clean build artifacts"
	@echo "  test          - Run tests"
	@echo "  fmt           - Format code"
	@echo "  lint          - Run clippy linter"
	@echo "  check         - Check compilation"
	@echo "  install       - Install locally"
