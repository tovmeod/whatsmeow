package whatsmeow

import (
	"os"
	"strings"
	"testing"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

func toNode(jid types.JID, encType string) waBinary.Node {
	return waBinary.Node{
		Tag:   "to",
		Attrs: waBinary.Attrs{"jid": jid},
		Content: []waBinary.Node{
			{
				Tag:   "enc",
				Attrs: waBinary.Attrs{"type": encType},
			},
		},
	}
}

func participantsMessageNode(toNodes ...waBinary.Node) *waBinary.Node {
	content := make([]waBinary.Node, len(toNodes))
	copy(content, toNodes)
	return &waBinary.Node{
		Tag: "message",
		Content: []waBinary.Node{
			{
				Tag:     "participants",
				Content: content,
			},
		},
	}
}

func TestBuildSendDebugEmittedDevices(t *testing.T) {
	pnJID := types.NewJID("972552732722", types.DefaultUserServer)
	lidJID := types.NewJID("177790372585681", types.HiddenUserServer)

	t.Run("maps wire jid to its encryption identity", func(t *testing.T) {
		node := participantsMessageNode(toNode(pnJID, "pkmsg"))
		identities := map[types.JID]types.JID{pnJID: lidJID}

		devices := buildSendDebugEmittedDevices(node, identities)

		if len(devices) != 1 {
			t.Fatalf("expected 1 device, got %d", len(devices))
		}
		got := devices[0]
		if got.JID != pnJID {
			t.Errorf("JID = %v, want %v", got.JID, pnJID)
		}
		if got.EncType != "pkmsg" {
			t.Errorf("EncType = %q, want %q", got.EncType, "pkmsg")
		}
		if got.EncryptionIdentity != lidJID {
			t.Errorf("EncryptionIdentity = %v, want %v", got.EncryptionIdentity, lidJID)
		}
	})

	t.Run("missing identity map entry yields zero-value, no panic", func(t *testing.T) {
		node := participantsMessageNode(toNode(pnJID, "pkmsg"))
		identities := map[types.JID]types.JID{}

		devices := buildSendDebugEmittedDevices(node, identities)

		if len(devices) != 1 {
			t.Fatalf("expected 1 device, got %d", len(devices))
		}
		if devices[0].EncryptionIdentity != (types.JID{}) {
			t.Errorf("EncryptionIdentity = %v, want zero value", devices[0].EncryptionIdentity)
		}
	})

	t.Run("multiple to children preserve node order", func(t *testing.T) {
		otherJID := types.NewJID("972535591893", types.DefaultUserServer)
		node := participantsMessageNode(
			toNode(pnJID, "pkmsg"),
			toNode(otherJID, "msg"),
		)
		identities := map[types.JID]types.JID{
			pnJID:    lidJID,
			otherJID: otherJID,
		}

		devices := buildSendDebugEmittedDevices(node, identities)

		if len(devices) != 2 {
			t.Fatalf("expected 2 devices, got %d", len(devices))
		}
		if devices[0].JID != pnJID || devices[1].JID != otherJID {
			t.Fatalf("devices out of order: %+v", devices)
		}
	})

	t.Run("no participants child returns nil", func(t *testing.T) {
		node := &waBinary.Node{Tag: "message"}

		devices := buildSendDebugEmittedDevices(node, map[types.JID]types.JID{})

		if devices != nil {
			t.Fatalf("expected nil, got %+v", devices)
		}
	})
}

// TestSendDMDebugWiring is a source-shape wiring proof (mirrors
// TestNoReceiverProactiveSessionReestablishment's technique): it confirms
// sendDM/SendMessage actually call buildSendDebugEmittedDevices instead of
// just proving the helper works in isolation. The fork has no sqlite/in-memory
// Store fixture and no existing 1:1-session test harness to drive a live
// SendMessage call, so this is the practical alternative (see PATTERNS.md §3).
func TestSendDMDebugWiring(t *testing.T) {
	src, err := os.ReadFile("send.go")
	if err != nil {
		t.Fatalf("read send.go: %v", err)
	}
	source := string(src)

	sendDMStart := strings.Index(source, "func (cli *Client) sendDM(")
	if sendDMStart == -1 {
		t.Fatal("sendDM function not found in send.go")
	}
	sendDMSig := source[sendDMStart:]
	if sigEnd := strings.Index(sendDMSig, ") {"); sigEnd != -1 {
		sendDMSig = sendDMSig[:sigEnd]
	}
	if !strings.Contains(sendDMSig, "debug *GroupSendDebug") {
		t.Fatal("sendDM's signature no longer contains a debug *GroupSendDebug parameter — " +
			"DM sends would silently stop being able to receive a debug capture struct")
	}

	sendDMBodyEnd := strings.Index(source[sendDMStart+1:], "\nfunc ")
	if sendDMBodyEnd == -1 {
		t.Fatal("could not find sendDM's body end (next top-level func)")
	}
	sendDMBody := source[sendDMStart : sendDMStart+1+sendDMBodyEnd]
	if !strings.Contains(sendDMBody, "buildSendDebugEmittedDevices(node, encryptionIdentities)") {
		t.Fatal("sendDM no longer calls buildSendDebugEmittedDevices(node, encryptionIdentities) — " +
			"resp.GroupDebug.EmittedDevices would stop being populated for DM sends")
	}

	sendMessageStart := strings.Index(source, "func (cli *Client) SendMessage(")
	if sendMessageStart == -1 {
		t.Fatal("SendMessage function not found in send.go")
	}
	sendMessageBodyEnd := strings.Index(source[sendMessageStart+1:], "\nfunc ")
	if sendMessageBodyEnd == -1 {
		t.Fatal("could not find SendMessage's body end (next top-level func)")
	}
	sendMessageBody := source[sendMessageStart : sendMessageStart+1+sendMessageBodyEnd]
	if !strings.Contains(sendMessageBody, "cli.sendDM(ctx, ownID, to, req.ID, message, &resp.DebugTimings, groupDebug, extraParams)") {
		t.Fatal("SendMessage no longer passes groupDebug into sendDM — " +
			"resp.GroupDebug would stay nil for every DM send again")
	}
}
