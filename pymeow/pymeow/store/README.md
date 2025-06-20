# Signal Protocol Implementation for Pymeow
# Signal Protocol Implementation for Pymeow

This directory contains the Signal protocol implementation for Pymeow, a Python port of the WhatsApp Web multidevice API. The implementation is based on the Go implementation in the whatsmeow project.

## Class Equivalents

The following table shows the equivalents between Go and Python classes:

| Go Class | Python Class |
|----------|-------------|
| `protocol.SignalAddress` | `libsignal.axolotladdress.AxolotlAddress` |
| `protocol.SenderKeyName` | `libsignal.groups.senderkeyname.SenderKeyName` |
| `store.SignalProtocol` | `libsignal.state.axolotlstore.AxolotlStore` |
| `serialize.ProtoBufSerializer` | `pymeow.store.protobufserializer.ProtobufSerializer` |

## Store Implementation

Pymeow uses the standard libsignal `AxolotlStore` interface, which combines all the storage interfaces needed for the Signal protocol:

- `IdentityKeyStore`: For managing identity keys
- `PreKeyStore`: For managing pre-keys
- `SessionStore`: For managing sessions
- `SignedPreKeyStore`: For managing signed pre-keys
- `SenderKeyStore`: For managing sender keys

The `Device` class implements this interface using WhatsApp-specific storage mechanisms.

## Custom Implementations

Unlike the Go implementation, the Python libsignal library already handles serialization internally:

- Go's `serialize.NewProtoBufSerializer()` is not needed in Python
- Python's `SessionRecord` and `SenderKeyRecord` handle serialization when initialized with raw bytes or when calling `.serialize()`

### SenderKeyName vs SenderKeyMessage

It's important to distinguish between these two classes:

- `SenderKeyName`: An identifier for a sender key, composed of a group ID and sender address. Used to lookup keys in the store.
- `SenderKeyMessage`: An encrypted message format used in group communications.

Both of these classes are provided by the libsignal library.
This directory contains the Signal protocol implementation for Pymeow, a Python port of the WhatsApp Web multidevice API. The implementation is based on the Go implementation in the whatsmeow project.

## Class Equivalents

The following table shows the equivalents between Go and Python classes:

| Go Class | Python Class |
|----------|-------------|
| `protocol.SignalAddress` | `libsignal.axolotladdress.AxolotlAddress` |
| `protocol.SenderKeyName` | `pymeow.store.senderkey.SenderKeyName` |
| `store.SignalProtocol` | `pymeow.store.axolotlstore.AxolotlStore` |
| `serialize.ProtoBufSerializer` | `pymeow.store.protobufserializer.ProtobufSerializer` |

## Store Interface Implementation

Pymeow uses the standard libsignal store interfaces:

- `IdentityKeyStore`: For storing identity keys
- `PreKeyStore`: For storing pre-keys
- `SessionStore`: For storing sessions
- `SignedPreKeyStore`: For storing signed pre-keys
- `SenderKeyStore`: For storing sender keys
# WhatsApp Store Package

## Overview

This package provides storage interfaces and implementations for WhatsApp data needed for multidevice functionality. It is a port of the Go implementation in `whatsmeow/store`.

## Structure

- `store.py`: Contains the base `Device` class and all storage interfaces
- `signal.py`: Contains the Signal Protocol implementation mixin
- `__init__.py`: Combines the base `Device` with the Signal Protocol mixin

## Usage

Import the `Device` class from this package to get the full functionality:

```python
from py.pymeow.store import Device
```

This will give you a `Device` class that has all the Signal Protocol methods mixed in, similar to how `signal.go` extends the `Device` struct in the Go implementation.

## Implementation Notes

The structure mirrors the Go implementation:

| Go File | Python File | Description |
|---------|-------------|-------------|
| `store.go` | `store.py` | Base `Device` struct and interfaces |
| `signal.go` | `signal.py` | Signal Protocol implementation |

In Go, methods are added to the `Device` struct in `signal.go`. In Python, we use a mixin class in `signal.py` to add these methods to the `Device` class.

This approach allows us to maintain a clean separation of concerns while still providing a single `Device` class that has all the functionality needed.

## Auth Device vs Store Device

Note that there are two `Device` classes in the codebase:

1. `auth.Device`: Used for authentication/pairing (in `pymeow/pymeow/auth.py`)
2. `store.Device`: Used for storage/Signal Protocol (this package)

Make sure to import the correct one based on your needs.
The `AxolotlStore` interface combines all these interfaces into a single interface that can be implemented by a class that provides all the required functionality.

## Custom Implementations

We provide custom implementations for:

- `SenderKeyName`: To identify sender keys in group contexts
- `ProtobufSerializer`: To serialize and deserialize Signal protocol objects

These are needed because the Python libsignal library doesn't provide direct equivalents for these Go classes.
