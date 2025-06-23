#!/bin/bash
# Whatsmeow Shared Library Build Script for Linux

# Define directories
GO_HELPERS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BIN_DIR="$GO_HELPERS_DIR/bin"

# Create bin directory if it doesn't exist
mkdir -p "$BIN_DIR"

echo ""
echo "=== Available commands ==="
echo "build     : Build the whatsmeow shared library"
echo "clean     : Clean the built library"
echo "help      : Show this help"
echo ""

if [ -z "$1" ]; then
    COMMAND="help"
else
    COMMAND="$1"
fi

case "$COMMAND" in
    build)
        echo "Building whatsmeow shared library..."
        echo "Working directory: $GO_HELPERS_DIR"
        echo "Output directory: $BIN_DIR"

        # Check if Go is installed
        if ! command -v go &> /dev/null
        then
            echo "Error: Go not found in PATH"
            echo "Please install Go and ensure it's in your PATH."
            exit 1
        fi
        echo "✓ Go compiler found"

        # Set CGO environment variables
        echo "Enabling CGO..."
        export CGO_ENABLED=1

        # Set OS and architecture
        export GOOS=linux
        export GOARCH=amd64 # Assuming amd64, adjust if needed for other architectures

        # Run go mod tidy to ensure dependencies are resolved
        echo "Running go mod tidy..."
        (cd "$GO_HELPERS_DIR" && go mod tidy)
        if [ $? -ne 0 ]; then
            echo "Failed to run go mod tidy"
            exit 1
        fi

        # Build the shared library
        echo "Building shared library..."
        (cd "$GO_HELPERS_DIR" && go build -buildmode=c-shared -o "$BIN_DIR/libwhatsmeow.so" .)

        if [ $? -ne 0 ]; then
            echo "Failed to build whatsmeow shared library"
            echo ""
            echo "Troubleshooting tips:"
            echo "1. Make sure Go is installed and in PATH"
            echo "2. Check that go.mod file is properly configured"
            echo "3. Ensure all Go source files are valid"
            exit 1
        fi

        echo ""
        echo "✓ Go whatsmeow library built successfully!"
        echo "  Output: $BIN_DIR/libwhatsmeow.so"
        echo "  Header: $BIN_DIR/libwhatsmeow.h" # Go also generates a .h file
        echo ""
        echo "To run tests, navigate to the pymeow directory and run:"
        echo "  python -m pytest pymeow/tests/test_eq -v"
        ;;
    clean)
        echo "Cleaning Go whatsmeow library..."
        if [ -f "$BIN_DIR/libwhatsmeow.so" ]; then
            rm "$BIN_DIR/libwhatsmeow.so"
            echo "Removed libwhatsmeow.so"
        fi
        if [ -f "$BIN_DIR/libwhatsmeow.h" ]; then
            rm "$BIN_DIR/libwhatsmeow.h"
            echo "Removed libwhatsmeow.h"
        fi
        echo "Cleanup complete"
        ;;
    help|*)
        echo "Usage: build_go.sh [command]"
        echo ""
        echo "Commands:"
        echo "  build  - Build the whatsmeow shared library"
        echo "  clean  - Remove built library files"
        echo "  help   - Show this help message"
        echo ""
        echo "The library will be built to: $BIN_DIR/libwhatsmeow.so"
        ;;
esac

exit 0
