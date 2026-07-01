// Source: 55.1-RESEARCH.md "Code Examples" -> "D-04 reproduction test (runnable, in-package)",
// package whatsmeow, mirrors bot_resend_blacklist_test.go conventions (bare &Client{}, no socket, no PG).
//
// D-04: encrypted media whose FileSHA256 metadata is absent must still download successfully
// (matching pre-merge ff56bae behavior); a genuinely wrong FileSHA256 must still fail.

package whatsmeow

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.mau.fi/whatsmeow/util/cbcutil"
	waLog "go.mau.fi/whatsmeow/util/log"
)

func TestMediaChecksumRegression(t *testing.T) {
	plaintext := []byte("hello world this is fake media bytes for the repro test 1234567890")
	mediaKey := make([]byte, 32)
	for i := range mediaKey {
		mediaKey[i] = byte(i + 1)
	}
	iv, cipherKey, macKey, _ := getMediaKeys(mediaKey, MediaImage)
	ciphertext, err := cbcutil.Encrypt(cipherKey, iv, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ciphertext)
	body := append(append([]byte{}, ciphertext...), h.Sum(nil)[:10]...)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer srv.Close()

	sum := sha256.Sum256(body)
	fileEncSHA256 := sum[:]
	sum2 := sha256.Sum256(plaintext)
	fileSHA256Correct := sum2[:]

	cli := &Client{mediaHTTP: srv.Client(), Log: waLog.Noop}

	// A media download of encrypted content whose FileSHA256 metadata is absent must succeed,
	// matching pre-merge (ff56bae) behavior (D-04).
	data, err := cli.downloadAndDecrypt(context.Background(), srv.URL, mediaKey, MediaImage, fileEncSHA256, nil)
	if err != nil {
		t.Errorf("missing plaintext hash must succeed after the D-04 fix: %v", err)
	}
	if string(data) != string(plaintext) {
		t.Errorf("missing plaintext hash: data mismatch, got %q want %q", data, plaintext)
	}

	// This must continue to fail after the fix — regression guard in the other direction.
	wrongHash := sha256.Sum256([]byte("not the right plaintext"))
	_, err = cli.downloadAndDecrypt(context.Background(), srv.URL, mediaKey, MediaImage, fileEncSHA256, wrongHash[:])
	if err == nil {
		t.Fatalf("a genuinely wrong hash must still fail after the D-04 fix")
	}

	// Baseline: correct hash must always succeed.
	data, err = cli.downloadAndDecrypt(context.Background(), srv.URL, mediaKey, MediaImage, fileEncSHA256, fileSHA256Correct)
	if err != nil || string(data) != string(plaintext) {
		t.Fatalf("correct hash must succeed: err=%v", err)
	}
}
