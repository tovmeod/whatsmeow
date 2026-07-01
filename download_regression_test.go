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
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
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

// TestDownloadEncryptedMediaChecksumRegression covers the second D-04
// guard (55.1 code-review CR): real inbound media arrives with an absent
// (len 0) fileEncSHA256, which the pre-fix hard precondition on
// downloadEncryptedMedia rejected outright, causing every host retry to
// fail. HMAC authentication (validateMedia, called by the caller with the
// returned mac) is separate and unconditional — untouched by this fix.
func TestDownloadEncryptedMediaChecksumRegression(t *testing.T) {
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
	correctChecksum := sum[:]

	cli := &Client{mediaHTTP: srv.Client(), Log: waLog.Noop}

	// (a) Absent enc-checksum (len 0) must succeed.
	file, mac, err := cli.downloadEncryptedMedia(context.Background(), srv.URL, nil)
	if err != nil {
		t.Errorf("absent enc-checksum must succeed after the fix: %v", err)
	}
	if string(file) != string(ciphertext) || len(mac) != 10 {
		t.Errorf("absent enc-checksum: unexpected file/mac, file match=%v mac len=%d", string(file) == string(ciphertext), len(mac))
	}

	// (b) A correct 32-byte enc-checksum must succeed.
	file, mac, err = cli.downloadEncryptedMedia(context.Background(), srv.URL, correctChecksum)
	if err != nil {
		t.Errorf("correct enc-checksum must succeed: %v", err)
	}
	if string(file) != string(ciphertext) || len(mac) != 10 {
		t.Errorf("correct enc-checksum: unexpected file/mac")
	}

	// (c) A wrong 32-byte enc-checksum must still fail with
	// ErrInvalidMediaEncSHA256 — this also proves the len==32 guard does
	// not panic on the *(*[32]byte)(checksum) cast.
	wrongChecksum := sha256.Sum256([]byte("not the right body"))
	_, _, err = cli.downloadEncryptedMedia(context.Background(), srv.URL, wrongChecksum[:])
	if !errors.Is(err, ErrInvalidMediaEncSHA256) {
		t.Errorf("wrong enc-checksum: err = %v, want ErrInvalidMediaEncSHA256", err)
	}

	// (d) A short, non-nil, non-32-byte checksum must be tolerated like an
	// absent one and must not panic on the [32]byte cast.
	_, _, err = cli.downloadEncryptedMedia(context.Background(), srv.URL, []byte{1, 2, 3})
	if err != nil {
		t.Errorf("short checksum must be tolerated (not panic), got: %v", err)
	}
}

// TestDownloadEncryptedMediaToFileChecksumRegression is the to-file-path
// counterpart of TestDownloadEncryptedMediaChecksumRegression, covering
// the identical guard in downloadEncryptedMediaToFile.
func TestDownloadEncryptedMediaToFileChecksumRegression(t *testing.T) {
	plaintext := []byte("hello world this is fake media bytes for the repro test to-file path 1234567890")
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
	correctChecksum := sum[:]

	cli := &Client{mediaHTTP: srv.Client(), Log: waLog.Noop}

	newTempFile := func(t *testing.T) *os.File {
		t.Helper()
		f, err := os.CreateTemp(t.TempDir(), "media-*")
		if err != nil {
			t.Fatalf("create temp file: %v", err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}

	// (a) Absent enc-checksum (len 0) must succeed.
	mac, err := cli.downloadEncryptedMediaToFile(context.Background(), srv.URL, nil, newTempFile(t))
	if err != nil {
		t.Errorf("absent enc-checksum must succeed after the fix: %v", err)
	}
	if len(mac) != 10 {
		t.Errorf("absent enc-checksum: mac length = %d, want 10", len(mac))
	}

	// (b) A correct 32-byte enc-checksum must succeed.
	mac, err = cli.downloadEncryptedMediaToFile(context.Background(), srv.URL, correctChecksum, newTempFile(t))
	if err != nil {
		t.Errorf("correct enc-checksum must succeed: %v", err)
	}
	if len(mac) != 10 {
		t.Errorf("correct enc-checksum: mac length = %d, want 10", len(mac))
	}

	// (c) A wrong 32-byte enc-checksum must still fail with
	// ErrInvalidMediaEncSHA256.
	wrongChecksum := sha256.Sum256([]byte("not the right body"))
	_, err = cli.downloadEncryptedMediaToFile(context.Background(), srv.URL, wrongChecksum[:], newTempFile(t))
	if !errors.Is(err, ErrInvalidMediaEncSHA256) {
		t.Errorf("wrong enc-checksum: err = %v, want ErrInvalidMediaEncSHA256", err)
	}
}
