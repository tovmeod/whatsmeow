# Protocol Buffer Migration Guide

## Overview

This guide details the process of migrating from hand-implemented protocol classes to generated Protocol Buffer classes in PyMeow.

## Generated Files Structure

The protocol buffer classes are generated in `pymeow/pymeow/generated/` with the following structure:

```
generated/
├── __init__.py                 # Common imports and re-exports
├── waE2E/                      # End-to-end encryption
├── waMsgTransport/            # Message transport
├── waCommon/                  # Common types
└── ... (other packages)
```

## Migration Steps

### 2. Generate Protocol Buffers

Run the generation script:
```bash
python pymeow/tools/generate_protos.py
```

### 3. Migration Process

#### Phase 1: Message Types
1. Replace hand-implemented message classes with generated ones:
   ```python
   # Old
   from py.types import Message

   # New
   from py.generated.waMsgTransport.WAMsgTransport_pb2 import Message
   ```

2. Update message construction:
   ```python
   # Old
   msg = Message(
       conversation="Hello",
       message_type=MessageType.CONVERSATION
   )

   # New
   msg = Message(
       conversation="Hello"
   )
   ```

#### Phase 2: Binary Protocol
1. Update node handling to use generated classes
2. Replace manual XML/binary conversion with protobuf serialization
3. Update attribute handling to use protobuf fields

#### Phase 3: E2E Encryption
1. Migrate to generated E2E classes
2. Update encryption handling to use proper protobuf types
3. Ensure proper serialization/deserialization

## Key Files to Update

1. `pymeow/pymeow/binary/` - Binary protocol handling
   - Replace manual node construction with protobuf
   - Update attribute handling

2. `pymeow/pymeow/message.py` - Message handling
   - Use generated Message types
   - Update serialization

3. `pymeow/pymeow/client.py` - Client implementation
   - Update message construction
   - Modify event handling

## Type Hints

The generated files include `.pyi` stub files with proper type hints:

```python
from py.generated.waAdv.WAAdv_pb2 import ADVEncryptionType
```

## Common Issues and Solutions

### 1. Enums
- Generated enums are different from hand-implemented ones
- Use the generated enum types and values
- Example: `ADVEncryptionType.E2EE` instead of custom enums

### 2. Optional Fields
- Protobuf handles optional fields differently
- Check field presence with `HasField()`
- Use default values appropriately

### 3. Repeated Fields
- Use proper repeated field methods
- Example: `msg.recipients.extend([...])` instead of direct assignment

### 4. Binary Serialization
- Use `SerializeToString()` for binary output
- Use `ParseFromString()` for parsing

## Testing

1. Unit Tests:
   - Update test cases to use generated classes
   - Verify serialization/deserialization
   - Check enum handling

2. Integration Tests:
   - Verify client functionality
   - Test protocol compatibility
   - Validate event handling

## Implementation Order

1. Start with basic message types
2. Move to transport layer
3. Update encryption handling
4. Migrate advanced features

## Notes

- Keep backward compatibility during migration
- Update documentation as you migrate
- Run tests frequently
- Update type hints to match new protobuf types
