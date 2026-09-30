// skflat (validator): read "group<TAB>sender_id<TAB>flat_hex" on stdin and run
// the fork's real store.UnpackFlat on each flat_hex. Confirms the driver will
// accept a transplanted row. Prints per-record state count + first keyID; final
// summary to stderr. Non-zero exit if any record fails to unpack.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"go.mau.fi/whatsmeow/store"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	var ok, bad int
	for in.Scan() {
		p := strings.Split(in.Text(), "\t")
		if len(p) != 3 {
			continue
		}
		sid := p[1]
		raw, err := hex.DecodeString(p[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "hex %s: %v\n", sid, err)
			bad++
			continue
		}
		st, err := store.UnpackFlat(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "UnpackFlat %s: %v\n", sid, err)
			bad++
			continue
		}
		kid := uint32(0)
		if len(st.SenderKeyStates) > 0 {
			kid = st.SenderKeyStates[0].KeyID
		}
		fmt.Fprintf(os.Stderr, "ok %s states=%d keyID0=%d\n", sid, len(st.SenderKeyStates), kid)
		ok++
	}
	fmt.Fprintf(os.Stderr, "UnpackFlat validation: ok=%d bad=%d\n", ok, bad)
	if bad > 0 {
		os.Exit(1)
	}
}
