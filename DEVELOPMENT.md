# PyMeow Development Status

## File Mappings

This section documents the mapping between Go source files and their Python equivalents. The goal is to maintain feature parity with the original WhatsMeow Go implementation.

### Dependency Information

Each file's dependencies are listed in the "Dependencies" column using the following format:
- Dependencies are listed as full .go filenames (e.g., `appstate/decode.go`)
- External dependencies are not shown
- Dependencies are listed in order of importance

### Core Components

| Go File | Python Equivalent | Status | Dependencies | Notes |
|---------|------------------|--------|--------------|-------|
| `client.go` | `client.py` | ✅ | `appstate/appstate.go`, `binary/node.go`, `proto/waE2E.pb.go`, `socket/socket.go`, `store/store.go`, `types/events.go`, `util/keys/keypair.go`, `util/log/logger.go` | Main client implementation |
| `message.go` | `messaging.py` | ✅ | `appstate/appstate.go`, `binary/node.go`, `proto/waE2E.pb.go`, `store/store.go`, `types/events.go` | Core message handling |
| `send.go` | `messaging.py` | ✅ | `binary/node.go`, `proto/waE2E.pb.go`, `types/events.go` | Message sending functionality |
| `receipt.go` | `receipt.py` | ✅ | `binary/node.go`, `types/events.go` | Read/delivery receipts |
| `group.go` | `group.py` | ✅ | `binary/node.go`, `store/store.go`, `types/events.go` | Group management |
| `user.go` | `user.py` | ✅ | `binary/node.go`, `proto/waE2E.pb.go`, `types/events.go` | User information and contacts |
| `handshake.go` | `auth.py` | ✅ | `binary/node.go`, `proto/waE2E.pb.go`, `socket/socket.go`, `util/keys/keypair.go` | Authentication handshake |
| `prekeys.go` | `prekeys.py` | ✅ | `binary/node.go`, `util/keys/keypair.go` | Pre-key management |
| `pair.go` | `pairing.py` | 🟡 | `binary/node.go`, `proto/waE2E.pb.go`, `types/events.go`, `util/keys/keypair.go` | Device pairing |
| `pair-code.go` | `pairing.py` | 🟡 | `binary/node.go`, `util/hkdfutil/hkdf.go`, `util/keys/keypair.go` | Pairing code generation |
| `download.go` | `media.py` | 🟡 | `binary/node.go`, `proto/waE2E.pb.go`, `socket/socket.go`, `util/cbcutil/cbc.go`, `util/hkdfutil/hkdf.go` | Media downloading |
| `download-to-file.go` | `media.py` | 🟡 | `proto/waE2E.pb.go`, `util/cbcutil/cbc.go` | File download handling |
| `upload.go` | `media.py` | 🟡 | `socket/socket.go`, `util/cbcutil/cbc.go` | File upload handling |
| `mediaconn.go` | `media.py` | 🟡 | `binary/node.go` | Media connection management |
| `mediaretry.go` | `media.py` | 🟡 | `binary/node.go`, `proto/waMmsRetry.pb.go`, `types/events.go`, `util/gcmutil/gcm.go`, `util/hkdfutil/hkdf.go` | Media retry logic |
| `broadcast.go` | `broadcast.py` | ❌ | `binary/node.go` | Broadcast messages |
| `call.go` | `call.py` | ❌ | `binary/node.go`, `types/events.go` | Voice/video calls |
| `newsletter.go` | `newsletter.py` | ❌ | `binary/node.go` | Newsletter channels |
| `presence.go` | `presence.py` | ❌ | `binary/node.go`, `types/events.go` | Online presence |
| `privacysettings.go` | `privacy.py` | ❌ | `binary/node.go`, `types/events.go` | Privacy settings |
| `push.go` | `push.py` | ❌ | `binary/node.go` | Push notifications |
| `qrchan.go` | `qr.py` | ❌ | `types/events.go`, `util/log/logger.go` | QR code generation |
| `request.go` | `request.py` | ❌ | `binary/node.go` | Request handling |
| `retry.go` | `retry.py` | ❌ | `binary/node.go`, `proto/waE2E.pb.go`, `types/events.go` | Retry logic |
| `update.go` | `update.py` | ❌ | `socket/socket.go`, `store/store.go` | Update handling |
| `armadillomessage.go` | `armadillo.py` | ❌ | `proto/waArmadillo.pb.go`, `types/events.go` | Armadillo message format |
| `msgsecret.go` | `msgsecret.py` | ❌ | `proto/waE2E.pb.go`, `types/events.go`, `util/gcmutil/gcm.go`, `util/hkdfutil/hkdf.go` | Message secret handling |
| `notification.go` | `notification.py` | ❌ | `appstate/appstate.go`, `binary/node.go`, `proto/waE2E.pb.go`, `store/store.go`, `types/events.go` | Notification handling |
| `connectionevents.go` | `events.py` | 🟡 | `binary/node.go`, `store/store.go`, `types/events.go` | Connection events |
| `errors.go` | `exceptions.py` | ✅ | `binary/node.go` | Custom exceptions |
| `internals.go` | `internals.py` | ❌ | `appstate/appstate.go`, `binary/node.go`, `proto/waE2E.pb.go`, `socket/socket.go`, `store/store.go`, `types/events.go`, `util/keys/keypair.go` | Internal utilities |
| `internals_generate.go` | `internals.py` | ❌ | - | Internal code generation |
| `keepalive.go` | `keepalive.py` | ❌ | `types/events.go` | Connection keepalive |
| `sendfb.go` | `messaging.py` | 🟡 | `binary/node.go`, `proto/waE2E.pb.go`, `types/events.go` | Fallback sending |

### Binary Protocol (`binary/` directory)

| Go File | Python Equivalent | Status | Dependencies | Notes |
|---------|------------------|--------|--------------|-------|
| `node.go` | `binary/node.py` | ✅ | - | Node structure |
| `encoder.go` | `binary/encoder.py` | ✅ | `binary/node.go` | Binary encoding |
| `decoder.go` | `binary/decoder.py` | ✅ | `binary/node.go` | Binary decoding |
| `xml.go` | `binary/xml.py` | ✅ | `binary/node.go` | XML handling |
| `attrs.go` | `binary/attrs.py` | ✅ | - | Attribute handling |
| `token.go` | `binary/token.py` | ✅ | - | Token handling |
| `nopcloser.go` | `binary/nopcloser.py` | ✅ | - | No-op closer |
| `wa_binary.go` | `binary/wa_binary.py` | ✅ | `binary/node.go` | WA binary protocol |

### Store Implementation (`store/` directory)

| Go File | Python Equivalent | Status | Dependencies | Notes |
|---------|------------------|--------|--------------|-------|
| `store.go` | `store/__init__.py` | ✅ | `types/events.go`, `util/keys/keypair.go` | Base store interface |
| `container.go` | `store/container.py` | ✅ | `store/store.go` | Store container |
| `device.go` | `store/device.py` | ✅ | `store/store.go` | Device store |
| `identities.go` | `store/identities.py` | ✅ | `store/store.go` | Identity store |
| `keys.go` | `store/keys.py` | ✅ | `store/store.go`, `util/keys/keypair.go` | Key store |
| `msgsecret.go` | `store/msgsecret.py` | ❌ | `store/store.go` | Message secret store |
| `prekey.go` | `store/prekey.py` | ✅ | `store/store.go`, `util/keys/keypair.go` | Pre-key store |
| `session.go` | `store/session.py` | ✅ | `store/store.go` | Session store |
| `signed_prekey.go` | `store/signed_prekey.py` | ✅ | `store/store.go`, `util/keys/keypair.go` | Signed pre-key store |
| `sqlstore/` | `store/sql/` | ❌ | `store/store.go`, `util/keys/keypair.go` | SQL store implementation |

### Application State (`appstate/` directory)

| Go File | Python Equivalent | Status | Dependencies | Notes |
|---------|------------------|--------|--------------|-------|
| `appstate.go` | `appstate/__init__.py` | ❌ | `binary/node.go`, `proto/waE2E.pb.go`, `store/store.go`, `types/events.go` | App state management |
| `decode.go` | `appstate/decode.py` | ❌ | `appstate/appstate.go`, `util/cbcutil/cbc.go` | State decoding |
| `encode.go` | `appstate/encode.py` | ❌ | `appstate/appstate.go`, `util/cbcutil/cbc.go` | State encoding |
| `hash.go` | `appstate/hash.go` | ❌ | - | Hash management |
| `lthash/` | `appstate/lthash/` | ❌ | - | LT hashing |
| `patch/` | `appstate/patch/` | ❌ | `appstate/appstate.go` | State patching |

### Socket Implementation (`socket/` directory)

| Go File | Python Equivalent | Status | Dependencies | Notes |
|---------|------------------|--------|--------------|-------|
| `client.go` | `socket/client.py` | ✅ | `socket/socket.go`, `util/log/logger.go` | Socket client |
| `frame.go` | `socket/frame.py` | ✅ | - | WebSocket framing |
| `noisehandshake.go` | `socket/noise.py` | ✅ | `crypto/` | Noise protocol |
| `socket.go` | `socket/socket.py` | ✅ | `util/log/logger.go` | Base socket implementation |

### Types (`types/` directory)

| Go File | Python Equivalent | Status | Dependencies | Notes |
|---------|------------------|--------|--------------|-------|
| `events.go` | `types/events.py` | ✅ | - | Event types |
| `message.go` | `types/message.py` | ✅ | - | Message types |
| `node.go` | `types/node.py` | ✅ | - | Node types |
| `notify.go` | `types/notify.py` | ❌ | - | Notification types |
| `protocol.go` | `types/protocol.py` | ✅ | - | Protocol types |

### Utils (`util/` directory)

| Directory | Python Equivalent | Status | Notes |
|-----------|------------------|--------|-------|
| `keys/` | `util/keys/` | ✅ | Key utilities |
| `log/` | `util/log/` | ✅ | Logging utilities |
| `cbcutil/` | `util/cbcutil/` | ✅ | CBC encryption utilities |
| `gcmutil/` | `util/gcmutil/` | ✅ | GCM encryption utilities |
| `hkdfutil/` | `util/hkdfutil/` | ✅ | HKDF utilities |

### Proto Definitions (`proto/` directory)

The protocol buffer definitions are automatically generated from the `.proto` files using `generate_protos.py`.
