.PHONY: build run clean test

# Binary name
BINARY_NAME=ssl-toolkit
BUILD_DIR=build

# Build the application
build:
	@echo "Building..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) cmd/ssl-toolkit/main.go

# Run the application
run: build
	@./$(BUILD_DIR)/$(BINARY_NAME)

# Clean build directory
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)

# Run tests
test:
	@go test ./...

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod tidy 