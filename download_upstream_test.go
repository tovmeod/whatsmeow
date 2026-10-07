package whatsmeow

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/util/cbcutil"
)

// A missing encrypted checksum does not imply plaintext when a media key is
// present. Exercise the public APIs so upstream's media-key heuristic cannot
// silently bypass the fork's authenticated decryption for these messages.
func TestDownloadMissingEncryptedHashKeepsMediaKey(t *testing.T) {
	plaintext := []byte("fork encrypted media without checksum metadata")
	mediaKey := bytes.Repeat([]byte{7}, 32)
	plainHash := sha256.Sum256(plaintext)
	for _, api := range []string{"memory", "file", "thumbnail"} {
		mediaType := MediaImage
		if api == "thumbnail" {
			mediaType = MediaLinkThumbnail
		}
		iv, cipherKey, macKey, _ := getMediaKeys(mediaKey, mediaType)
		ciphertext, err := cbcutil.Encrypt(cipherKey, iv, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		h := hmac.New(sha256.New, macKey)
		_, _ = h.Write(iv)
		_, _ = h.Write(ciphertext)
		body := append(ciphertext, h.Sum(nil)[:10]...)
		for _, variant := range []string{"nil_hash", "empty_hash", "bad_mac", "bad_plain_hash"} {
			t.Run(api+"/"+variant, func(t *testing.T) {
				served := bytes.Clone(body)
				if variant == "bad_mac" {
					served[len(served)-1] ^= 1
				}
				cli := newHostFailoverClient(&hostFailoverCaptureLogger{}, map[string]hostRoundTripFunc{
					"media.example.test": func(*http.Request) (*http.Response, error) {
						return okResponse(served), nil
					},
				}, "media.example.test")
				var encHash []byte
				if variant == "empty_hash" {
					encHash = []byte{}
				}
				fileHash := bytes.Clone(plainHash[:])
				if variant == "bad_plain_hash" {
					fileHash[0] ^= 1
				}
				msg := &waE2E.ImageMessage{
					DirectPath: proto.String("/media?download=1"), MediaKey: mediaKey,
					FileSHA256: fileHash, FileEncSHA256: encHash,
					ThumbnailDirectPath: proto.String("/thumb?download=1"),
					ThumbnailSHA256:     fileHash, ThumbnailEncSHA256: encHash,
				}
				var data []byte
				var err error
				switch api {
				case "memory":
					data, err = cli.Download(context.Background(), msg)
				case "thumbnail":
					data, err = cli.DownloadThumbnail(context.Background(), &waE2E.ExtendedTextMessage{
						MediaKey: mediaKey, ThumbnailDirectPath: msg.ThumbnailDirectPath,
						ThumbnailSHA256: fileHash, ThumbnailEncSHA256: encHash,
					})
				case "file":
					file, openErr := os.Create(filepath.Join(t.TempDir(), "media"))
					if openErr != nil {
						t.Fatal(openErr)
					}
					defer file.Close()
					err = cli.DownloadToFile(context.Background(), msg, file)
					if err == nil {
						if _, err = file.Seek(0, io.SeekStart); err == nil {
							data, err = io.ReadAll(file)
						}
					}
				}
				if variant == "bad_mac" || variant == "bad_plain_hash" {
					if err == nil {
						t.Fatal("tampered encrypted media was accepted")
					}
				} else if err != nil || !bytes.Equal(data, plaintext) {
					t.Fatalf("missing hash lost encrypted media: %q (%v)", data, err)
				}
			})
		}
	}
}
