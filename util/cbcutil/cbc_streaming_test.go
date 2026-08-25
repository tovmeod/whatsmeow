package cbcutil

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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

// TestDecryptStreamNonBlockMultipleLength confirms DecryptStream returns an error, instead of
// panicking in cbc.CryptBlocks, when ciphertextLen is fully satisfiable by the reader but is not
// a multiple of the AES block size -- the exact shape of the ciphertext that caused
// panic: crypto/cipher: input not full blocks in production.
func TestDecryptStreamNonBlockMultipleLength(t *testing.T) {
	key, iv, macKey := streamKeys()
	plaintext := randomBytes(t, 100)
	ciphertext, _ := streamEncrypt(t, key, iv, macKey, plaintext)

	// Claim fewer bytes than the reader actually holds (so io.ReadFull fully succeeds), but not
	// a multiple of 16 (the real ciphertext from streamEncrypt always is, by construction of
	// EncryptStream's own padding).
	claimedLen := int64(len(ciphertext)) - 3

	var recovered bytes.Buffer
	_, err := DecryptStream(key, iv, macKey, claimedLen, bytes.NewReader(ciphertext), &recovered)
	if err == nil {
		t.Fatalf("expected an error for a non-block-multiple chunk length, got nil")
	}
}

// TestDecryptStreamParityWithDecrypt confirms DecryptStream recovers exactly the same
// plaintext as the existing all-at-once Decrypt, for every size class covered above.
func TestDecryptStreamParityWithDecrypt(t *testing.T) {
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

			// Decrypt mutates its ciphertext argument in place, so hand it a copy.
			allAtOnce, err := Decrypt(key, iv, append([]byte(nil), ciphertext...))
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			var recovered bytes.Buffer
			if _, err = DecryptStream(key, iv, macKey, int64(len(ciphertext)), bytes.NewReader(ciphertext), &recovered); err != nil {
				t.Fatalf("DecryptStream: %v", err)
			}

			if !bytes.Equal(allAtOnce, plaintext) {
				t.Fatalf("Decrypt result mismatch: got %d bytes, want %d bytes", len(allAtOnce), len(plaintext))
			}
			if !bytes.Equal(recovered.Bytes(), plaintext) {
				t.Fatalf("DecryptStream result mismatch: got %d bytes, want %d bytes", recovered.Len(), len(plaintext))
			}
			if !bytes.Equal(allAtOnce, recovered.Bytes()) {
				t.Fatalf("Decrypt and DecryptStream disagree")
			}
		})
	}
}

// TestDecryptStreamTamperDetection confirms that corrupting a single ciphertext byte changes
// both the returned plainHash and the HMAC the caller computes over the ciphertext -- the two
// signals Plan 74.12-06 relies on to reject a corrupted download before renaming it into place.
func TestDecryptStreamTamperDetection(t *testing.T) {
	key, iv, macKey := streamKeys()
	plaintext := randomBytes(t, 100*1024)
	ciphertext, _ := streamEncrypt(t, key, iv, macKey, plaintext)

	var goodPlaintext bytes.Buffer
	goodHash, err := DecryptStream(key, iv, macKey, int64(len(ciphertext)), bytes.NewReader(ciphertext), &goodPlaintext)
	if err != nil {
		t.Fatalf("DecryptStream (untampered): %v", err)
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)/2] ^= 0xFF

	var tamperedPlaintext bytes.Buffer
	tamperedHash, err := DecryptStream(key, iv, macKey, int64(len(tampered)), bytes.NewReader(tampered), &tamperedPlaintext)
	if err != nil {
		t.Fatalf("DecryptStream (tampered): %v", err)
	}
	if bytes.Equal(goodHash, tamperedHash) {
		t.Fatalf("plainHash did not change after ciphertext tampering")
	}

	goodMAC := hmac.New(sha256.New, macKey)
	goodMAC.Write(iv)
	goodMAC.Write(ciphertext)

	tamperedMAC := hmac.New(sha256.New, macKey)
	tamperedMAC.Write(iv)
	tamperedMAC.Write(tampered)

	if hmac.Equal(goodMAC.Sum(nil), tamperedMAC.Sum(nil)) {
		t.Fatalf("HMAC over ciphertext did not change after ciphertext tampering")
	}
}
