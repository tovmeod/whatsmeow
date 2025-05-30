# Request Handling Implementation

## Overview
Implements functionality for sending and receiving requests in WhatsApp, particularly for handling Info Query (IQ) requests and responses.

The Python implementation supports:
1. **Request ID Generation**: Generating unique IDs for requests
2. **Response Handling**: Setting up waiters for responses and handling received responses
3. **Info Query (IQ) Requests**: Sending IQ requests and handling responses
4. **Retry Mechanism**: Retrying requests after disconnections

## Source Files
- **Go Source**: `request.go`
- **Python Equivalent**: `pymeow/pymeow/request.py`

## Dependencies
- **Internal**:
  - `binary/node.go`
  - `types/jid.go`
- **External**:
  - Standard library: `context`, `fmt`, `strconv`, `time`

## Structures

| Structure | ported to python | notes |
|-----------|------------------|-------|
| `infoQueryType` | no | Type for info query types |
| `infoQuery` | no | Structure for info queries |

## Methods

| Method | ported to python | notes |
|--------|------------------|-------|
| `generateRequestID` | no | Generates a unique ID for requests |
| `isDisconnectNode` | no | Checks if a node indicates a disconnection |
| `isAuthErrorDisconnect` | no | Checks if a disconnect node is due to an authentication error |
| `clearResponseWaiters` | no | Clears all response waiters |
| `waitResponse` | no | Sets up a waiter for a response |
| `cancelResponse` | no | Cancels a response waiter |
| `receiveResponse` | no | Handles a received response |
| `sendIQAsyncAndGetData` | no | Sends an info query asynchronously and returns the data |
| `sendIQAsync` | no | Sends an info query asynchronously |
| `sendIQ` | no | Sends an info query and waits for the response |
| `retryFrame` | no | Retries a frame after a disconnection |

## External Dependencies
- Python equivalents:
  - `asyncio`: For asynchronous operations
  - `time`: For timeouts
  - `dataclasses`: For defining data classes
  - `typing`: For type hints
  - `enum`: For enum types
