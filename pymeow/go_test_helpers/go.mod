module go_test_helpers

go 1.23.0

toolchain go1.24.3

// Use the local whatsmeow module instead of downloading it
replace go.mau.fi/whatsmeow => ../..

require go.mau.fi/whatsmeow v0.0.0-00010101000000-000000000000

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	go.mau.fi/libsignal v0.2.0 // indirect
	go.mau.fi/util v0.8.8 // indirect
	golang.org/x/crypto v0.39.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)
