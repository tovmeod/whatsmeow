// sessdecode (decoder): read a whatsmeow_sessions or whatsmeow_identity_keys
// capture CSV (header "captured_at,our_jid,their_id,session_b64" or
// "...,identity_b64") and print one summary line per row. Session rows are
// decoded via the fork's real store.UnpackFlatSession and printed as
// structural/comparative ratchet-state fields only -- never raw key material
// (RootKey, ChainKey.Key, SenderRatchetKeyPublic/Private, MessageKeys[].Key,
// RemoteIdentityPublic, LocalIdentityPublic). Identity rows are printed as a
// SHA-256 digest of the decoded bytes, never the raw bytes. Prints a final
// ok=N bad=N summary to stderr; non-zero exit if any row failed to decode.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"go.mau.fi/whatsmeow/store"
)

func main() {
	csvPath := flag.String("csv", "", "path to a sessions or identities capture CSV (required)")
	flag.Parse()
	if *csvPath == "" {
		fmt.Fprintln(os.Stderr, "sessdecode: -csv is required")
		os.Exit(2)
	}

	f, err := os.Open(*csvPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sessdecode: open %s: %v\n", *csvPath, err)
		os.Exit(1)
	}
	defer f.Close()

	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sessdecode: read header: %v\n", err)
		os.Exit(1)
	}
	if len(header) != 4 {
		fmt.Fprintf(os.Stderr, "sessdecode: expected 4 columns, got %d\n", len(header))
		os.Exit(1)
	}

	var isSession bool
	switch header[3] {
	case "session_b64":
		isSession = true
	case "identity_b64":
		isSession = false
	default:
		fmt.Fprintf(os.Stderr, "sessdecode: unrecognized 4th column %q (expected session_b64 or identity_b64)\n", header[3])
		os.Exit(1)
	}

	var ok, bad int
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "sessdecode: read row: %v\n", err)
			bad++
			continue
		}
		if len(row) != 4 {
			fmt.Fprintf(os.Stderr, "sessdecode: row has %d columns, want 4\n", len(row))
			bad++
			continue
		}
		ourJID, theirID, blobB64 := row[1], row[2], row[3]

		raw, err := base64.StdEncoding.DecodeString(blobB64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sessdecode: base64 decode our_jid=%s their_id=%s: %v\n", ourJID, theirID, err)
			bad++
			continue
		}

		if isSession {
			if err := decodeSessionRow(ourJID, theirID, raw); err != nil {
				fmt.Fprintf(os.Stderr, "sessdecode: UnpackFlatSession our_jid=%s their_id=%s: %v\n", ourJID, theirID, err)
				bad++
				continue
			}
		} else {
			decodeIdentityRow(ourJID, theirID, raw)
		}
		ok++
	}

	fmt.Fprintf(os.Stderr, "sessdecode: ok=%d bad=%d\n", ok, bad)
	if bad > 0 {
		os.Exit(1)
	}
}

// decodeSessionRow unpacks a flat-bytea whatsmeow_sessions blob and prints its
// structural/comparative fields. Never prints RootKey, ChainKey.Key,
// SenderRatchetKeyPublic/Private, MessageKeys[].Key, RemoteIdentityPublic, or
// LocalIdentityPublic -- those are live Signal ratchet/identity key material.
func decodeSessionRow(ourJID, theirID string, raw []byte) error {
	sess, err := store.UnpackFlatSession(raw)
	if err != nil {
		return err
	}
	st := sess.SessionState

	var senderChainIndex uint32
	var senderChainSkippedKeys int
	if st.SenderChain != nil {
		senderChainSkippedKeys = len(st.SenderChain.MessageKeys)
		if st.SenderChain.ChainKey != nil {
			senderChainIndex = st.SenderChain.ChainKey.Index
		}
	}

	receiverDetail := "["
	for i, rc := range st.ReceiverChains {
		if i > 0 {
			receiverDetail += ","
		}
		var idx uint32
		if rc.ChainKey != nil {
			idx = rc.ChainKey.Index
		}
		receiverDetail += fmt.Sprintf("idx:%d/msgs:%d", idx, len(rc.MessageKeys))
	}
	receiverDetail += "]"

	fmt.Printf("our_jid=%s\tsession=%s\tsessionVersion=%d\tpreviousCounter=%d\tsenderChainIndex=%d\tsenderChainSkippedKeys=%d\treceiverChains=%d\treceiverChainDetail=%s\tremoteRegID=%d\tlocalRegID=%d\tneedsRefresh=%t\tpreviousStates=%d\n",
		ourJID, theirID,
		st.SessionVersion,
		st.PreviousCounter,
		senderChainIndex,
		senderChainSkippedKeys,
		len(st.ReceiverChains),
		receiverDetail,
		st.RemoteRegistrationID,
		st.LocalRegistrationID,
		st.NeedsRefresh,
		len(sess.PreviousStates),
	)
	return nil
}

// decodeIdentityRow prints a SHA-256 digest of the decoded identity key bytes,
// never the raw bytes themselves.
func decodeIdentityRow(ourJID, theirID string, raw []byte) {
	digest := sha256.Sum256(raw)
	fmt.Printf("our_jid=%s\tidentity=%s\tsha256=%s\n", ourJID, theirID, hex.EncodeToString(digest[:]))
}
