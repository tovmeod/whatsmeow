// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"errors"
	"time"

	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
)

const (
	phonePairingLifetime   = 3 * time.Minute
	maxPhonePairingReplies = 8
)

var (
	errPhonePairingReplaced    = errors.New("phone pairing attempt was replaced")
	errPhonePairingRegistering = errors.New("phone pairing registration is already in progress")
	errPhonePairingFinalizing  = errors.New("pairing confirmation is already being finalized")
	errPhonePairingStaleProof  = errors.New("confirmation did not match the active phone pairing")
)

type phonePairingAttempt struct {
	jid         types.JID
	keyPair     *keys.KeyPair
	linkingCode string
	ready       chan struct{}
}

type phonePairingState struct {
	attempt      *phonePairingAttempt
	ref          string
	expires      time.Time
	replies      []phonePairFinish
	waiting      int
	startedPhone bool
	finalizing   bool
}

// reset invalidates the attempt and wakes any worker waiting for its registration.
func (s *phonePairingState) reset() {
	if s.attempt != nil && s.ref == "" {
		close(s.attempt.ready)
	}
	s.attempt = nil
	s.ref = ""
	s.expires = time.Time{}
	s.replies = nil
	s.waiting = 0
}

// A temporary owner exists only on a connection for an unpaired device.
// Its commands update local state. Network I/O and callbacks run outside it.
type phonePairingOwner struct {
	socket   *socket.NoiseSocket
	commands chan func(*phonePairingState)
	done     chan struct{}
}

func newPhonePairingOwner(sock *socket.NoiseSocket) *phonePairingOwner {
	return &phonePairingOwner{socket: sock, commands: make(chan func(*phonePairingState)), done: make(chan struct{})}
}

func (o *phonePairingOwner) run(disconnected <-chan struct{}) {
	defer close(o.done)
	var state phonePairingState
	defer state.reset()
	for {
		select {
		case <-disconnected:
			return
		case cmd := <-o.commands:
			select {
			case <-disconnected:
				return
			default:
			}
			if state.attempt != nil && !state.expires.IsZero() && !time.Now().Before(state.expires) {
				state.reset()
			}
			cmd(&state)
		}
	}
}

func phonePairingDo[T any](ctx context.Context, owner *phonePairingOwner, fn func(*phonePairingState) (T, error)) (T, error) {
	type result struct {
		value T
		err   error
	}
	resultCh := make(chan result, 1)
	var zero T
	select {
	case <-ctx.Done():
		return zero, ctx.Err()
	case <-owner.done:
		return zero, ErrNotConnected
	case owner.commands <- func(s *phonePairingState) {
		value, err := fn(s)
		resultCh <- result{value, err}
	}:
	}
	// Once accepted, let the owner complete the transition even if this caller
	// is canceled. The owner always returns a result before accepting another command.
	select {
	case r := <-resultCh:
		return r.value, r.err
	case <-owner.done:
		select {
		case r := <-resultCh:
			return r.value, r.err
		default:
			return zero, ErrNotConnected
		}
	}
}

func (o *phonePairingOwner) begin(ctx context.Context, attempt *phonePairingAttempt) error {
	_, err := phonePairingDo(ctx, o, func(s *phonePairingState) (struct{}, error) {
		if s.finalizing {
			return struct{}{}, errPhonePairingFinalizing
		}
		if s.attempt != nil && s.ref == "" {
			// Keep registration IQs in order even when two callers start at once.
			return struct{}{}, errPhonePairingRegistering
		}
		s.reset()
		s.startedPhone = true
		s.attempt = attempt
		return struct{}{}, nil
	})
	return err
}

func (o *phonePairingOwner) register(ctx context.Context, attempt *phonePairingAttempt, ref string) error {
	if ref == "" {
		return errors.New("empty reference for phone pairing registration")
	}
	_, err := phonePairingDo(ctx, o, func(s *phonePairingState) (struct{}, error) {
		if s.attempt != attempt || s.ref != "" {
			return struct{}{}, errPhonePairingReplaced
		}
		s.ref = ref
		s.expires = time.Now().Add(phonePairingLifetime)
		close(attempt.ready)
		return struct{}{}, nil
	})
	return err
}

func (o *phonePairingOwner) abandon(ctx context.Context, attempt *phonePairingAttempt) {
	_, _ = phonePairingDo(ctx, o, func(s *phonePairingState) (struct{}, error) {
		if s.attempt == attempt && !s.finalizing {
			s.reset()
		}
		return struct{}{}, nil
	})
}

// claimPairingSecret selects a matching reply without writing to the device store.
// Once it succeeds, new registrations and other confirmations cannot claim this socket.
func (cli *Client) claimPairingSecret(ctx context.Context, owner *phonePairingOwner, identity *waAdv.ADVSignedDeviceIdentityHMAC, parseErr error) ([]byte, error) {
	if owner == nil {
		if parseErr != nil {
			return nil, parseErr
		}
		if !validPairingHMAC(identity, cli.Store.AdvSecretKey) {
			return nil, ErrPairInvalidDeviceIdentityHMAC
		}
		return cli.Store.AdvSecretKey, nil
	}
	return phonePairingDo(ctx, owner, func(s *phonePairingState) ([]byte, error) {
		if s.finalizing {
			return nil, errPhonePairingFinalizing
		}
		if parseErr != nil {
			return nil, parseErr
		}
		for _, reply := range s.replies {
			if validPairingHMAC(identity, reply.secret) {
				s.finalizing = true
				return reply.secret, nil
			}
		}
		// The independently generated QR secret can still be confirmed if a
		// caller offered both methods. It has never held a phone reply secret.
		if !validPairingHMAC(identity, cli.Store.AdvSecretKey) {
			if s.startedPhone {
				// A stale phone proof can also arrive after switching to passkey.
				return nil, errors.Join(errPhonePairingStaleProof, ErrPairInvalidDeviceIdentityHMAC)
			}
			return nil, ErrPairInvalidDeviceIdentityHMAC
		}
		s.finalizing = true
		return cli.Store.AdvSecretKey, nil
	})
}

// updatePairingSecret coordinates QR rotations and passkey handoff with active
// phone pairing. Only a passkey handoff supersedes the phone-code attempt.
func (cli *Client) updatePairingSecret(ctx context.Context, passkeyHandoff bool, transition func([]byte)) bool {
	owner := cli.phonePairing.Load()
	if owner == nil {
		transition(cli.Store.AdvSecretKey)
		return true
	}
	changed, _ := phonePairingDo(ctx, owner, func(s *phonePairingState) (bool, error) {
		if s.finalizing {
			return false, nil
		}
		secret := cli.Store.AdvSecretKey
		if passkeyHandoff {
			if n := len(s.replies); n > 0 {
				secret = s.replies[n-1].secret
			}
			s.reset()
		}
		transition(secret)
		return true, nil
	})
	return changed
}

func (cli *Client) devicePairingSecret(ctx context.Context) ([]byte, error) {
	owner := cli.phonePairing.Load()
	if owner == nil {
		return cli.Store.AdvSecretKey, nil
	}
	return phonePairingDo(ctx, owner, func(s *phonePairingState) ([]byte, error) {
		if s.finalizing {
			return nil, errPhonePairingFinalizing
		}
		return cli.Store.AdvSecretKey, nil
	})
}
