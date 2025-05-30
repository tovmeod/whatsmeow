"""Store interfaces for WhatsApp data needed for multidevice functionality.

Port of whatsmeow/store/store.go and signal.go
"""

# Import all symbols from store.py
from .store import (
    IdentityStore, SessionStore, PreKeyStore, SenderKeyStore,
    AppStateSyncKey, AppStateSyncKeyStore, AppStateMutationMAC, AppStateStore,
    ContactEntry, ContactStore, ChatSettingsStore, DeviceContainer,
    MessageSecretInsert, MsgSecretStore, PrivacyToken, PrivacyTokenStore,
    BufferedEvent, EventBuffer, LIDMapping, LIDStore,
    AllSessionSpecificStores, AllGlobalStores, AllStores
)

# Import base Device class
from .store import BaseDevice

# Import Signal Protocol mixin
from .signal import SignalProtocolMixin

# Import client payload functions
from .clientpayload import get_client_payload

# Create enhanced Device class with Signal Protocol support
class Device(BaseDevice, SignalProtocolMixin):
    """
    Device class with Signal Protocol store methods added.

    This combines the base Device class from store.py with the Signal Protocol
    methods from signal.py, equivalent to how signal.go extends the Device
    struct in the Go implementation.
    """

    def get_client_payload(self):
        """
        Get the appropriate client payload based on device state.

        Returns:
            ClientPayload for either login or registration
        """
        return get_client_payload(self)

# This makes all the symbols available when importing from store
__all__ = [
    'IdentityStore', 'SessionStore', 'PreKeyStore', 'SenderKeyStore',
    'AppStateSyncKey', 'AppStateSyncKeyStore', 'AppStateMutationMAC', 'AppStateStore',
    'ContactEntry', 'ContactStore', 'ChatSettingsStore', 'DeviceContainer',
    'MessageSecretInsert', 'MsgSecretStore', 'PrivacyToken', 'PrivacyTokenStore',
    'BufferedEvent', 'EventBuffer', 'LIDMapping', 'LIDStore',
    'AllSessionSpecificStores', 'AllGlobalStores', 'AllStores', 'Device',
    'SignalProtocolMixin'
]
