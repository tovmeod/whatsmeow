.PHONY: build-go-test-lib test-equivalence clean-go-lib

# Build the Go test shared library
build-go-test-lib:
	cd go_test_helpers && \
	go mod tidy && \
	go build -buildmode=c-shared -o ../bin/libwhatsmeow_test.so binary_encoder.go

# Run equivalence tests
test-equivalence: build-go-test-lib
	cd pymeow && pytest tests/test_eq/test_binary_encoder.py -v

# Clean the built library
clean-go-lib:
	rm -f bin/libwhatsmeow_test.so bin/libwhatsmeow_test.h

# Run all tests
test-all: build-go-test-lib
	cd pymeow && pytest tests/ -v
