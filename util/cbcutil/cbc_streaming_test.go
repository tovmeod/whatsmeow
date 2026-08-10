package cbcutil

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// streamKeys returns a deterministic AES-256 key, block-size IV, and HMAC key for test use.
func streamKeys() (key, iv, macKey []byte) {
	key = make([]byte, 32)
	iv = make([]byte, 16)
	macKey = make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range iv {
		iv[i] = byte(i + 100)
	}
	for i := range macKey {
		macKey[i] = byte(i + 200)
	}
	return key, iv, macKey
}

// streamEncrypt encrypts plaintext with EncryptStream and splits the result into the raw
// ciphertext and the trailing 10-byte truncated HMAC tag, matching the WhatsApp media wire
// format DecryptStream is meant to consume.
func streamEncrypt(t *testing.T, key, iv, macKey, plaintext []byte) (ciphertext, tag []byte) {
	t.Helper()
	var out bytes.Buffer
	_, _, _, _, err := EncryptStream(key, iv, macKey, bytes.NewReader(plaintext), &out)
	if err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	full := out.Bytes()
	if len(full) < 10 {
		t.Fatalf("EncryptStream output too short: %d bytes", len(full))
	}
	ciphertext = append([]byte(nil), full[:len(full)-10]...)
	tag = append([]byte(nil), full[len(full)-10:]...)
	return ciphertext, tag
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

func TestDecryptStreamRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"one-block", 16},
		{"multi-chunk", 100 * 1024},
		{"needs-padding", 17},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, iv, macKey := streamKeys()
			plaintext := randomBytes(t, tc.size)

			ciphertext, _ := streamEncrypt(t, key, iv, macKey, plaintext)

			var recovered bytes.Buffer
			plainHash, err := DecryptStream(key, iv, macKey, int64(len(ciphertext)), bytes.NewReader(ciphertext), &recovered)
			if err != nil {
				t.Fatalf("DecryptStream: %v", err)
			}
			if !bytes.Equal(recovered.Bytes(), plaintext) {
				t.Fatalf("recovered plaintext mismatch: got %d bytes, want %d bytes", recovered.Len(), len(plaintext))
			}
			if len(plainHash) == 0 {
				t.Fatalf("DecryptStream returned an empty plainHash")
			}
		})
	}
}

func TestDecryptStreamTruncatedStream(t *testing.T) {
	key, iv, macKey := streamKeys()
	plaintext := randomBytes(t, 100)
	ciphertext, _ := streamEncrypt(t, key, iv, macKey, plaintext)

	// Claim more bytes than the reader actually provides.
	claimedLen := int64(len(ciphertext)) + 16

	var recovered bytes.Buffer
	_, err := DecryptStream(key, iv, macKey, claimedLen, bytes.NewReader(ciphertext), &recovered)
	if err == nil {
		t.Fatalf("expected an error for a truncated stream, got nil")
	}
}
