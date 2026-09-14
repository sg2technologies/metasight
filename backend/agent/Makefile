# Variables
BINARY_NAME=metasight-agent
VERSION=1.1.0
BUILD_DIR=dist
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

# AIX Target Setup
AIX_OS=aix
AIX_ARCH=ppc64

.PHONY: all build-aix build-local linux windows mac test clean help

all: build-aix linux windows mac

## build-aix: Compiles the Go binary for IBM AIX (PowerPC 64-bit)
build-aix:
	@echo "Building binary for AIX ($(AIX_OS)/$(AIX_ARCH))..."
	@mkdir -p $(BUILD_DIR)
	GOOS=$(AIX_OS) GOARCH=$(AIX_ARCH) CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-$(AIX_OS)-$(AIX_ARCH) ./cmd/agent

## build-local: Compiles the Go binary for your current machine host
build-local:
	@echo "Building binary for local host..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/agent

## linux: Compiles the Go binary for Linux (amd64 and arm64)
linux:
	@echo "Building binaries for Linux..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/agent

## windows: Compiles the Go binary for Windows (amd64)
windows:
	@echo "Building binary for Windows..."
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/agent

## mac: Compiles the Go binary for macOS (arm64 and amd64)
mac:
	@echo "Building binaries for macOS..."
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/agent
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/agent

## test: Runs all unit tests
test:
	@echo "Running tests..."
	go test -v ./...

## clean: Removes all generated build files
clean:
	@echo "Cleaning up build directory..."
	rm -rf $(BUILD_DIR)

## help: Displays available make targets
help:
	@echo "Available commands:"
	@echo "  build-aix    - Compiles for IBM AIX (PowerPC 64-bit)"
	@echo "  build-local  - Compiles for your current machine host"
	@echo "  linux        - Compiles for Linux (amd64 and arm64)"
	@echo "  windows      - Compiles for Windows"
	@echo "  mac          - Compiles for macOS"
	@echo "  test         - Runs all unit tests"
	@echo "  clean        - Removes all generated build files"
