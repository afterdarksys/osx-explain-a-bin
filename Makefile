.PHONY: build clean install test deps vet fmt check

BINARY=explain-bin
VERSION=2.0.0
BUILD_DIR=build

# main.Version is a real symbol in main.go. It previously was not, so this
# -X flag was silently discarded and --version reported a hardcoded constant.
LDFLAGS=-s -w -X main.Version=$(VERSION)

all: deps build

deps:
	go mod tidy

build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) .

build-all: deps
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 .
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-darwin-amd64 .

install: build
	cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
	@echo "Installed $(BINARY) to /usr/local/bin/"

uninstall:
	rm -f /usr/local/bin/$(BINARY)
	@echo "Uninstalled $(BINARY)"

clean:
	rm -rf $(BUILD_DIR)
	go clean

test:
	go test ./...

test-verbose:
	go test -v ./...

cover:
	go test -cover ./...

vet:
	go vet ./...

fmt:
	go fmt ./...

# Everything CI should gate on.
check: fmt vet test

# Smoke test against binaries with known-good properties: a signed Apple
# platform binary and a notarized third-party app.
smoke: build
	./$(BUILD_DIR)/$(BINARY) /bin/ls
	@echo ""
	./$(BUILD_DIR)/$(BINARY) /usr/bin/curl

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build        - Build the binary"
	@echo "  build-all    - Build for arm64 and amd64"
	@echo "  install      - Install to /usr/local/bin"
	@echo "  uninstall    - Remove from /usr/local/bin"
	@echo "  clean        - Clean build artifacts"
	@echo "  test         - Run tests"
	@echo "  test-verbose - Run tests with -v"
	@echo "  cover        - Run tests with coverage"
	@echo "  vet          - Run go vet"
	@echo "  fmt          - Run go fmt"
	@echo "  check        - fmt + vet + test"
	@echo "  smoke        - Build and run against system binaries"
	@echo "  deps         - Tidy dependencies"
