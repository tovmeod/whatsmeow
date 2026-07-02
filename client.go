// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package whatsmeow implements a client for interacting with the WhatsApp web multidevice API.
package whatsmeow

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"go.mau.fi/util/exhttp"
	"go.mau.fi/util/exsync"
	"go.mau.fi/util/ptr"
	"go.mau.fi/util/random"
	"golang.org/x/net/proxy"
	"golang.org/x/sync/semaphore"

	"go.mau.fi/whatsmeow/appstate"
	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waWa6"
	"go.mau.fi/whatsmeow/proto/waWeb"
	"go.mau.fi/whatsmeow/socket"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"go.mau.fi/whatsmeow/util/keys"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// EventHandler is a function that can handle events from WhatsApp.
type EventHandler func(evt any)
type EventHandlerWithSuccessStatus func(evt any) bool
type nodeHandler func(ctx context.Context, node *waBinary.Node)

var nextHandlerID uint32

type wrappedEventHandler struct {
	fn EventHandlerWithSuccessStatus
	id uint32
}

type deviceCache struct {
	devices []types.JID
	dhash   string
}

// Client contains everything necessary to connect to and interact with the WhatsApp web API.
type Client struct {
	Store   *store.Device
	Log     waLog.Logger
	recvLog waLog.Logger
	sendLog waLog.Logger

	socket     *socket.NoiseSocket
	socketLock sync.RWMutex
	socketWait chan struct{}

	isLoggedIn            atomic.Bool
	paired                atomic.Bool
	expectedDisconnect    *exsync.Event
	forceAutoReconnect    atomic.Bool
	EnableAutoReconnect   bool
	InitialAutoReconnect  bool
	LastSuccessfulConnect time.Time
	AutoReconnectErrors   int
	// AutoReconnectHook is called when auto-reconnection fails. If the function returns false,
	// the client will not attempt to reconnect. The number of retries can be read from AutoReconnectErrors.
	AutoReconnectHook func(error) bool
	// If SynchronousAck is set, acks for messages will only be sent after all event handlers return.
	SynchronousAck             bool
	EnableDecryptedEventBuffer bool
	lastDecryptedBufferClear   time.Time

	DisableLoginAutoReconnect bool

	sendActiveReceipts atomic.Uint32

	// EmitAppStateEventsOnFullSync can be set to true if you want to get app state events emitted
	// even when re-syncing the whole state.
	EmitAppStateEventsOnFullSync bool
	AppStateDebugLogs            bool

	AutomaticMessageRerequestFromPhone bool
	pendingPhoneRerequests             map[types.MessageID]context.CancelFunc
	pendingPhoneRerequestsLock         sync.RWMutex

	appStateProc     *appstate.Processor
	appStateSyncLock sync.Mutex

	historySyncNotifications        chan *waE2E.HistorySyncNotification
	historySyncHandlerStarted       atomic.Bool
	ManualHistorySyncDownload       bool
	DisableManualHistorySyncReceipt bool

	uploadPreKeysLock sync.Mutex
	lastPreKeyUpload  time.Time

	mediaConnCache *MediaConn
	mediaConnLock  sync.Mutex

	responseWaiters     map[string]chan<- *waBinary.Node
	responseWaitersLock sync.Mutex

	nodeHandlers      map[string]nodeHandler
	handlerQueue      chan *waBinary.Node
	eventHandlers     []wrappedEventHandler
	eventHandlersLock sync.RWMutex

	// kavtov-fork (35.2-02 D-05/D-08/D-09): bounded (msgID,sender)-keyed retry-attempt store.
	// Replaces the unbounded messageRetries map[string]int. Keyed by retryAttemptKey so different
	// senders for the same msgID get independent counts. Bounded by a ring of size retryStoreSKMsgSize
	// to cap memory growth at ~6000 failures/hr. Value-typed entries (no pointers) per 35.1 GC lesson.
	// Lazy-init under messageRetriesLock so a bare &Client{} never nil-panics.
	retryAttempts     map[retryAttemptKey]retryAttemptEntry
	retryAttemptsList [retryAttemptsListSize]retryAttemptKey
	retryAttemptsPtr  int
	messageRetriesLock sync.Mutex

	// kavtov-fork (35.2-02 D-06): bounded set of message IDs whose content was already
	// recovered via phone-fetch (handlePlaceholderResendResponse success branch). Used by
	// registerRetryAttempt to short-circuit retry receipts for attempts #2+ after content
	// arrives (D-06 short-circuit). Value-typed, lazy-init, bounded ring — same idiom as
	// retryAttempts above. Guarded by recoveredMsgIDsLock.
	recoveredMsgIDs     map[string]struct{}
	recoveredMsgIDsList [recoveredMsgIDsListSize]string
	recoveredMsgIDsPtr  int
	recoveredMsgIDsLock sync.Mutex

	retrySema          *semaphore.Weighted

	incomingRetryRequestCounter     map[incomingRetryKey]int
	incomingRetryRequestCounterLock sync.Mutex

	appStateKeyRequests     map[string]time.Time
	appStateKeyRequestsLock sync.RWMutex

	messageSendLock sync.Mutex

	// kavtov-fork (55.1-02): pending ack/receipt queue for reconnect-durable retry.
	// sendAck/sendMessageReceipt enqueue the built node here instead of dropping it when
	// sendNode returns ErrNotConnected (socket down mid-reconnect); handleConnectSuccess
	// drains and replays the queue in FIFO order once the connection is back up. Mirrors
	// WA Web's own dangling-receipt replay on connect (55.1-INVESTIGATION-websocket.md
	// section 4). Bounded (pendingStanzaCap) with oldest-discard + a throttled overflow
	// ERROR so bounded memory never becomes silent loss. Deduplicated by (tag,id,to) so a
	// re-enqueue of the same ack/receipt does not grow the queue. Lazy-init under
	// pendingStanzasLock; bare &Client{} is safe.
	pendingStanzas                []pendingStanzaEntry
	pendingStanzasSeen            map[pendingStanzaKey]bool
	pendingStanzasLock            sync.Mutex
	pendingStanzasOverflowCount   int
	pendingStanzasLastOverflowLog time.Time

	// sendNodeFunc, when non-nil, replaces cli.sendNode as the transport used by sendAck,
	// sendMessageReceipt, and replayPendingStanzas. Tests install it to simulate send
	// outcomes without a real socket; production code leaves it nil (falls back to
	// cli.sendNode via sendNodeOrHook).
	sendNodeFunc func(ctx context.Context, node waBinary.Node) error

	tcTokenSenderTS            map[types.JID]time.Time
	tcTokenSenderTSLock        sync.Mutex
	lastTCTokenSenderTSCleanup time.Time
	tcTokenDBPruneLock         sync.Mutex
	lastTCTokenDBPrune         time.Time

	privacySettingsCache atomic.Value

	groupCache           map[types.JID]*groupMetaCache
	groupCacheLock       sync.Mutex
	userDevicesCache     map[types.JID]deviceCache
	userDevicesCacheLock sync.Mutex

	recentMessagesMap  map[recentMessageKey]RecentMessage
	recentMessagesList [recentMessagesSize]recentMessageKey
	recentMessagesPtr  int
	recentMessagesLock sync.RWMutex

	// kavtov-fork: P2a group sender-key convergence instrument. Bounded in-memory set of
	// recently-FAILED group decrypt tuples, keyed by the inbound sender's device-qualified
	// signal address + group JID. Populated on the total-miss path (decryptGroupSenderKey
	// returning ErrNoSenderKeyForUser); when a later message from the SAME inbound tuple later
	// decrypts via the KEY path we emit ONE INFO SENDER_KEY_CONVERGED and drop the entry. This is
	// the only honest convergence signal: it distinguishes genuine group-key recovery from PDO
	// content-recovery (which lands content with the key still missing). Same ring-buffer idiom as
	// recentMessages, but dedups on add (tuples repeat heavily under the failure load) and is
	// sized to the distinct-failing-tuple working set. See debug no-sender-key-recurring ch6 (P2a).
	failedSenderKeyTuples     map[failedSenderKeyTuple]struct{}
	failedSenderKeyTuplesList [failedSenderKeyTuplesSize]failedSenderKeyTuple
	failedSenderKeyTuplesPtr  int
	failedSenderKeyTuplesLock sync.Mutex

	// kavtov-fork (38.5): per-account counter of group skmsg decrypt failures per
	// (group, bare-sender). Once the count reaches botResendBlacklistThreshold,
	// sendRetryReceipt suppresses the futile resend-request stanza to that bot while
	// leaving the ack, phone request, and donor scan intact. Cumulative, never reset,
	// no eviction — the active failing-sender set is small. Mirrors the
	// appStateSyncFailures pattern (counter map + dedicated lock).
	botResendBlacklist     map[botResendKey]int
	botResendBlacklistLock sync.Mutex

	// kavtov-fork (D-12): per-collection consecutive ErrMismatchingLTHash failure counter.
	// When the same collection name fails N times in a row, handleAppStateNotification triggers
	// FetchAppState(fullSync=true) to self-heal the divergence. Uses its own lock — NOT
	// appStateSyncLock — so the counter is never held across the long FetchAppState fetch.
	// Collection set is small (bounded by appstate.AllPatchNames, ~10 entries); no ring needed.
	appStateSyncFailures     map[appstate.WAPatchName]int
	appStateSyncFailuresLock sync.Mutex
	// kavtov-fork (D-12 loop fix): per-collection count of fullSync attempts that themselves
	// failed with ErrMismatchingLTHash. Capped by maxAppStateFullSyncFailures so a permanently
	// diverged collection stops re-triggering fullSync. Guarded by appStateSyncFailuresLock.
	appStateFullSyncFailures map[appstate.WAPatchName]int
	// fetchAppStateFunc is the function used by handleAppStateNotification to call FetchAppState.
	// Defaults to cli.FetchAppState in NewClient; tests override it with a spy.
	fetchAppStateFunc func(ctx context.Context, name appstate.WAPatchName, fullSync, onlyIfNotSynced bool) error

	// kavtov-fork (perf 260602): SKDM redundancy dedup. WhatsApp re-bundles the SenderKeyDistribution
	// message with normal group traffic; builder.Process then LoadSenderKey+AddSenderKeyState+
	// StoreSenderKey unconditionally on each arrival, re-writing the row. The dedup is ITERATION-AWARE
	// (not keyID-only): SKDM.Create emits the sender's LIVE SenderChainKey iteration, so a re-bundled
	// SKDM from an active sender can carry a HIGHER iteration — a forward checkpoint that rescues a
	// recipient who fell >2000 behind (ErrTooFarIntoFuture). This map records, per (sender,group,keyID),
	// the highest SKDM iteration we have already processed; an arriving SKDM is skipped ONLY when it is
	// at-or-below that (a true redundant/stale re-broadcast). A higher-iteration SKDM always processes
	// (never drop a rescue). Bypassed entirely when the tuple is in failedSenderKeyTuples, so a deleted/
	// lost key re-installs. Restart empties it (first SKDM per keyID re-confirms). Bounded ring idiom.
	skdmInstalled     map[skdmInstalledKey]uint32
	skdmInstalledList [skdmInstalledSize]skdmInstalledKey
	skdmInstalledPtr  int
	skdmInstalledLock sync.Mutex

	// kavtov-fork (55.1-08, D-11 corrected): per-(sender,group) SKDM parse-fail dedup registry. An
	// SKDM that fails to parse (55.1-INVESTIGATION-skdm.md: two @lid devices emitting a non-conformant
	// 32-byte payload -- proven external format, not a fixable libsignal-version gap) stays VISIBLE
	// and FULLY COUNTED, but re-announcing the identical, already-diagnosed failure as a fresh Error
	// on every single message forever is spam, not vigilance. First sighting per (sender,group) emits
	// the full Error diagnostic; every repeat only increments the per-pair count and the package-wide
	// skdmParseFailTotal (message.go, folded into the periodic SKDM_DEDUP line). Bounded at
	// skdmParseFailPairsSize; unlike skdmInstalled this is NOT a ring -- on overflow a brand-new pair
	// is counted (skdmParseFailOverflow) but does not get its own first-occurrence Error, since
	// today's working set is two senders and the bound exists only to guard a future storm of pairs.
	skdmParseFailSeen     map[skdmParseFailKey]struct{}
	skdmParseFailCounts   map[skdmParseFailKey]uint64
	skdmParseFailOverflow uint64
	skdmParseFailLock     sync.Mutex

	sessionRecreateHistory     map[types.JID]time.Time
	sessionRecreateHistoryLock sync.Mutex
	// GetMessageForRetry is used to find the source message for handling retry receipts
	// when the message is not found in the recently sent message cache.
	// Note: in DMs, the "to" field may be different from what you originally sent to (LID vs phone number),
	// make sure to check both if necessary.
	GetMessageForRetry func(requester, to types.JID, id types.MessageID) *waE2E.Message
	// PreRetryCallback is called before a retry receipt is accepted.
	// If it returns false, the accepting will be cancelled and the retry receipt will be ignored.
	PreRetryCallback func(receipt *events.Receipt, id types.MessageID, retryCount int, msg *waE2E.Message) bool
	// Should whatsmeow store recently sent messages in the database so that retry receipts can be accepted
	// even if the process is restarted? If false, only the in-memory cache and GetMessageForRetry will be used.
	UseRetryMessageStore bool
	lastRetryStoreClear  time.Time

	// kavtov-fork (38.5): process-wide claim map for ask-once phone requests.
	// Injected by the driver (one shared instance across all accounts). nil means
	// the ask-once gate is disabled (safe: phone request fires unconditionally, same
	// as before this feature).
	PhoneRequestClaims *PhoneRequestClaims

	// PrePairCallback is called before pairing is completed. If it returns false, the pairing will be cancelled and
	// the client will disconnect.
	PrePairCallback func(jid types.JID, platform, businessName string) bool

	// GetClientPayload is called to get the client payload for connecting to the server.
	// This should NOT be used for WhatsApp (to change the OS name, update fields in store.BaseClientPayload directly).
	GetClientPayload func() *waWa6.ClientPayload
	QRClientType     PairClientType

	// Should untrusted identity errors be handled automatically? If true, the stored identity and existing signal
	// sessions will be removed on untrusted identity errors, and an events.IdentityChange will be dispatched.
	// If false, decrypting a message from untrusted devices will fail.
	AutoTrustIdentity bool

	// Should SubscribePresence return an error if no privacy token is stored for the user?
	ErrorOnSubscribePresenceWithoutToken bool

	SendReportingTokens bool

	BackgroundEventCtx context.Context

	phoneLinkingCache *phoneLinkingCache

	uniqueID  string
	idCounter atomic.Uint64

	serverTimeOffset atomic.Int64

	mediaHTTP     *http.Client
	websocketHTTP *http.Client
	preLoginHTTP  *http.Client

	// This field changes the client to act like a Messenger client instead of a WhatsApp one.
	//
	// Note that you cannot use a Messenger account just by setting this field, you must use a
	// separate library for all the non-e2ee-related stuff like logging in.
	// The library is currently embedded in mautrix-meta (https://github.com/mautrix/meta), but may be separated later.
	MessengerConfig *MessengerConfig
	RefreshCAT      func(context.Context) error
}

type groupMetaCache struct {
	AddressingMode             types.AddressingMode
	CommunityAnnouncementGroup bool
	Members                    []types.JID
}

type MessengerConfig struct {
	UserAgent    string
	BaseURL      string
	WebsocketURL string
}

// Size of buffer for the channel that all incoming XML nodes go through.
// In general it shouldn't go past a few buffered messages, but the channel is big to be safe.
const handlerQueueSize = 2048

// NewClient initializes a new WhatsApp web client.
//
// The logger can be nil, it will default to a no-op logger.
//
// The device store must be set. A default SQL-backed implementation is available in the store/sqlstore package.
//
//	container, err := sqlstore.New(context.Background(), "sqlite3", "file:yoursqlitefile.db?_foreign_keys=on", nil)
//	if err != nil {
//		panic(err)
//	}
//	// If you want multiple sessions, remember their JIDs and use .GetDevice(jid) or .GetAllDevices() instead.
//	deviceStore, err := container.GetFirstDevice()
//	if err != nil {
//		panic(err)
//	}
//	client := whatsmeow.NewClient(deviceStore, nil)
func NewClient(deviceStore *store.Device, log waLog.Logger) *Client {
	if log == nil {
		log = waLog.Noop
	}
	uniqueIDPrefix := random.Bytes(2)
	baseHTTPClient := &http.Client{
		Transport: (http.DefaultTransport.(*http.Transport)).Clone(),
	}
	cli := &Client{
		mediaHTTP:          ptr.Clone(baseHTTPClient),
		websocketHTTP:      ptr.Clone(baseHTTPClient),
		preLoginHTTP:       ptr.Clone(baseHTTPClient),
		Store:              deviceStore,
		Log:                log,
		recvLog:            log.Sub("Recv"),
		sendLog:            log.Sub("Send"),
		uniqueID:           fmt.Sprintf("%d.%d-", uniqueIDPrefix[0], uniqueIDPrefix[1]),
		responseWaiters:    make(map[string]chan<- *waBinary.Node),
		eventHandlers:      make([]wrappedEventHandler, 0, 1),
		handlerQueue:       make(chan *waBinary.Node, handlerQueueSize),
		appStateProc:       appstate.NewProcessor(deviceStore, log.Sub("AppState")),
		socketWait:         make(chan struct{}),
		expectedDisconnect: exsync.NewEvent(),

		incomingRetryRequestCounter: make(map[incomingRetryKey]int),

		historySyncNotifications: make(chan *waE2E.HistorySyncNotification, 32),

		tcTokenSenderTS:  make(map[types.JID]time.Time),
		groupCache:       make(map[types.JID]*groupMetaCache),
		userDevicesCache: make(map[types.JID]deviceCache),

		recentMessagesMap:      make(map[recentMessageKey]RecentMessage, recentMessagesSize),
		failedSenderKeyTuples:  make(map[failedSenderKeyTuple]struct{}, failedSenderKeyTuplesSize),
		skdmInstalled:          make(map[skdmInstalledKey]uint32, skdmInstalledSize),
		skdmParseFailSeen:      make(map[skdmParseFailKey]struct{}, skdmParseFailPairsSize),
		skdmParseFailCounts:    make(map[skdmParseFailKey]uint64, skdmParseFailPairsSize),
		botResendBlacklist:       make(map[botResendKey]int),
		appStateSyncFailures:     make(map[appstate.WAPatchName]int),
		appStateFullSyncFailures: make(map[appstate.WAPatchName]int),
		sessionRecreateHistory: make(map[types.JID]time.Time),
		GetMessageForRetry:     func(requester, to types.JID, id types.MessageID) *waE2E.Message { return nil },
		appStateKeyRequests:    make(map[string]time.Time),

		pendingPhoneRerequests: make(map[types.MessageID]context.CancelFunc),

		EnableAutoReconnect: true,
		AutoTrustIdentity:   true,

		BackgroundEventCtx: context.Background(),
	}
	cli.fetchAppStateFunc = cli.FetchAppState
	cli.paired.Store(deviceStore.ID != nil)
	cli.nodeHandlers = map[string]nodeHandler{
		"message":      cli.handleEncryptedMessage,
		"appdata":      cli.handleEncryptedMessage,
		"receipt":      cli.handleReceipt,
		"call":         cli.handleCallEvent,
		"chatstate":    cli.handleChatState,
		"presence":     cli.handlePresence,
		"notification": cli.handleNotification,
		"success":      cli.handleConnectSuccess,
		"failure":      cli.handleConnectFailure,
		"stream:error": cli.handleStreamError,
		"iq":           cli.handleIQ,
		"ib":           cli.handleIB,
		// Apparently there's also an <error> node which can have a code=479 and means "Invalid stanza sent (smax-invalid)"
	}
	return cli
}

// SetProxyAddress is a helper method that parses a URL string and calls SetProxy or SetSOCKSProxy based on the URL scheme.
//
// Returns an error if url.Parse fails to parse the given address.
func (cli *Client) SetProxyAddress(addr string, opts ...SetProxyOptions) error {
	if addr == "" {
		cli.SetProxy(nil, opts...)
		return nil
	}
	parsed, err := url.Parse(addr)
	if err != nil {
		return err
	}
	if parsed.Scheme == "http" || parsed.Scheme == "https" {
		cli.SetProxy(http.ProxyURL(parsed), opts...)
	} else if parsed.Scheme == "socks5" {
		px, err := proxy.FromURL(parsed, &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		})
		if err != nil {
			return err
		}
		cli.SetSOCKSProxy(px, opts...)
	} else {
		return fmt.Errorf("unsupported proxy scheme %q", parsed.Scheme)
	}
	return nil
}

type Proxy = func(*http.Request) (*url.URL, error)

// SetProxy sets a HTTP proxy to use for WhatsApp web websocket connections and media uploads/downloads.
//
// Must be called before Connect() to take effect in the websocket connection.
// If you want to change the proxy after connecting, you must call Disconnect() and then Connect() again manually.
//
// By default, the client will find the proxy from the https_proxy environment variable like Go's net/http does.
//
// To disable reading proxy info from environment variables, explicitly set the proxy to nil:
//
//	cli.SetProxy(nil)
//
// To use a different proxy for the websocket and media, pass a function that checks the request path or headers:
//
//	cli.SetProxy(func(r *http.Request) (*url.URL, error) {
//		if r.URL.Host == "web.whatsapp.com" && r.URL.Path == "/ws/chat" {
//			return websocketProxyURL, nil
//		} else {
//			return mediaProxyURL, nil
//		}
//	})
func (cli *Client) SetProxy(proxy Proxy, opts ...SetProxyOptions) {
	var opt SetProxyOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	transport := (http.DefaultTransport.(*http.Transport)).Clone()
	transport.Proxy = proxy
	cli.setTransport(transport, opt)
}

type SetProxyOptions struct {
	// If NoWebsocket is true, the proxy won't be used for the websocket
	NoWebsocket bool
	// If OnlyLogin is true, the proxy will be used for the pre-login websocket, but not the post-login one
	OnlyLogin bool
	// If NoMedia is true, the proxy won't be used for media uploads/downloads
	NoMedia bool
}

// SetSOCKSProxy sets a SOCKS5 proxy to use for WhatsApp web websocket connections and media uploads/downloads.
//
// Same details as SetProxy apply, but using a different proxy for the websocket and media is not currently supported.
func (cli *Client) SetSOCKSProxy(px proxy.Dialer, opts ...SetProxyOptions) {
	var opt SetProxyOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	transport := (http.DefaultTransport.(*http.Transport)).Clone()
	pxc := px.(proxy.ContextDialer)
	transport.DialContext = pxc.DialContext
	cli.setTransport(transport, opt)
}

func (cli *Client) setTransport(transport *http.Transport, opt SetProxyOptions) {
	if !opt.NoWebsocket {
		cli.preLoginHTTP.Transport = transport
		if !opt.OnlyLogin {
			cli.websocketHTTP.Transport = transport
		}
	}
	if !opt.NoMedia {
		cli.mediaHTTP.Transport = transport
	}
}

// SetMediaHTTPClient sets the HTTP client used to download media.
// This will overwrite any set proxy calls.
func (cli *Client) SetMediaHTTPClient(h *http.Client) {
	cli.mediaHTTP = h
}

// SetWebsocketHTTPClient sets the HTTP client used to establish the websocket connection for logged-in sessions.
// This will overwrite any set proxy calls.
func (cli *Client) SetWebsocketHTTPClient(h *http.Client) {
	cli.websocketHTTP = h
}

// SetPreLoginHTTPClient sets the HTTP client used to establish the websocket connection before login.
// This will overwrite any set proxy calls.
func (cli *Client) SetPreLoginHTTPClient(h *http.Client) {
	cli.preLoginHTTP = h
}

// SetMaxParallelRetryReceiptHandling sets how many retry receipts can be handled in parallel.
// Defaults to unlimited. This should only be set before connecting, changing it afterwards can cause data races.
func (cli *Client) SetMaxParallelRetryReceiptHandling(n int64) {
	if n <= 0 {
		cli.retrySema = nil
	} else {
		cli.retrySema = semaphore.NewWeighted(n)
	}
}

func (cli *Client) getSocketWaitChan() <-chan struct{} {
	cli.socketLock.RLock()
	ch := cli.socketWait
	cli.socketLock.RUnlock()
	return ch
}

func (cli *Client) closeSocketWaitChan() {
	cli.socketLock.Lock()
	close(cli.socketWait)
	cli.socketWait = make(chan struct{})
	cli.socketLock.Unlock()
}

func (cli *Client) getOwnID() types.JID {
	if cli == nil {
		return types.EmptyJID
	}
	return cli.Store.GetJID()
}

func (cli *Client) getOwnLID() types.JID {
	if cli == nil {
		return types.EmptyJID
	}
	return cli.Store.GetLID()
}

func (cli *Client) WaitForConnection(timeout time.Duration) bool {
	if cli == nil {
		return false
	}
	timeoutChan := time.After(timeout)
	cli.socketLock.RLock()
	for cli.socket == nil || !cli.socket.IsConnected() || !cli.IsLoggedIn() {
		ch := cli.socketWait
		cli.socketLock.RUnlock()
		select {
		case <-ch:
		case <-timeoutChan:
			return false
		case <-cli.expectedDisconnect.GetChan():
			return false
		}
		cli.socketLock.RLock()
	}
	cli.socketLock.RUnlock()
	return true
}

// Connect connects the client to the WhatsApp web websocket. After connection, it will either
// authenticate if there's data in the device store, or emit a QREvent to set up a new link.
func (cli *Client) Connect() error {
	return cli.ConnectContext(cli.BackgroundEventCtx)
}

func isRetryableConnectError(err error) bool {
	if exhttp.IsNetworkError(err) {
		return true
	}

	var statusErr socket.ErrWithStatusCode
	if errors.As(err, &statusErr) {
		switch statusErr.StatusCode {
		case 408, 500, 501, 502, 503, 504:
			return true
		default:
			return false
		}
	}

	return errors.Is(err, socket.ErrDialFailed)
}

func (cli *Client) ConnectContext(ctx context.Context) error {
	if cli == nil {
		return ErrClientIsNil
	}

	cli.socketLock.Lock()
	defer cli.socketLock.Unlock()

	err := cli.unlockedConnect(ctx)
	if isRetryableConnectError(err) && cli.InitialAutoReconnect && cli.EnableAutoReconnect {
		cli.Log.Errorf("Initial connection failed but reconnecting in background (%v)", err)
		go cli.dispatchEvent(&events.Disconnected{})
		go cli.autoReconnect(ctx)
		return nil
	}
	return err
}

func (cli *Client) connect(ctx context.Context) error {
	cli.socketLock.Lock()
	defer cli.socketLock.Unlock()

	return cli.unlockedConnect(ctx)
}

func (cli *Client) unlockedConnect(ctx context.Context) error {
	if cli.Store.Deleted {
		return store.ErrDeviceDeleted
	}
	if cli.socket != nil {
		if !cli.socket.IsConnected() {
			cli.unlockedDisconnect()
		} else {
			return ErrAlreadyConnected
		}
	}

	cli.resetExpectedDisconnect()
	client := cli.websocketHTTP
	if cli.Store.ID == nil {
		client = cli.preLoginHTTP
	}
	fs := socket.NewFrameSocket(cli.Log.Sub("Socket"), client)
	// 55.1-12: readPump uses this to classify a routine EOF read-error as handled lifecycle
	// only when auto-reconnect is actually enabled at the time of the failure.
	fs.AutoReconnectEnabled = func() bool { return cli.EnableAutoReconnect }
	if cli.MessengerConfig != nil {
		fs.URL = cli.MessengerConfig.WebsocketURL
		fs.HTTPHeaders.Set("Origin", cli.MessengerConfig.BaseURL)
		fs.HTTPHeaders.Set("User-Agent", cli.MessengerConfig.UserAgent)
		fs.HTTPHeaders.Set("Cache-Control", "no-cache")
		fs.HTTPHeaders.Set("Pragma", "no-cache")
		//fs.HTTPHeaders.Set("Sec-Fetch-Dest", "empty")
		//fs.HTTPHeaders.Set("Sec-Fetch-Mode", "websocket")
		//fs.HTTPHeaders.Set("Sec-Fetch-Site", "cross-site")
	}
	if err := fs.Connect(ctx); err != nil {
		fs.Close(0)
		return err
	} else if err = cli.doHandshake(ctx, fs, *keys.NewKeyPair()); err != nil {
		fs.Close(0)
		return fmt.Errorf("noise handshake failed: %w", err)
	}
	go cli.keepAliveLoop(ctx, fs.Context())
	go cli.handlerQueueLoop(ctx, fs.Context())
	return nil
}

// IsLoggedIn returns true after the client is successfully connected and authenticated on WhatsApp.
func (cli *Client) IsLoggedIn() bool {
	return cli != nil && cli.isLoggedIn.Load()
}

func (cli *Client) onDisconnect(ctx context.Context, ns *socket.NoiseSocket, remote bool) {
	ns.Stop(false, false)
	cli.socketLock.Lock()
	defer cli.socketLock.Unlock()
	if cli.socket == ns {
		cli.socket = nil
		cli.clearResponseWaiters(xmlStreamEndNode)
		if !cli.isExpectedDisconnect() && (cli.forceAutoReconnect.Swap(false) || remote) {
			cli.Log.Debugf("Emitting Disconnected event")
			go cli.dispatchEvent(&events.Disconnected{})
			go cli.autoReconnect(ctx)
		} else if remote {
			cli.Log.Debugf("OnDisconnect() called, but it was expected, so not emitting event")
		} else {
			cli.Log.Debugf("OnDisconnect() called after manual disconnection")
		}
	} else {
		cli.Log.Debugf("Ignoring OnDisconnect on different socket")
	}
}

func (cli *Client) expectDisconnect() {
	cli.forceAutoReconnect.Store(false)
	cli.expectedDisconnect.Set()
}

func (cli *Client) resetExpectedDisconnect() {
	cli.forceAutoReconnect.Store(false)
	cli.expectedDisconnect.Clear()
}

func (cli *Client) isExpectedDisconnect() bool {
	return cli.expectedDisconnect.IsSet()
}

// maxAutoReconnectDelay caps the auto-reconnect backoff (55.1-02). autoReconnectDelay
// previously grew linearly (AutoReconnectErrors * 2s) with no maximum, so a long-failing
// account retried at an ever-growing interval. WA Web's own client caps its Fibonacci
// backoff at 15 minutes (55.1-INVESTIGATION-websocket.md section 3), but a ride-dispatch
// driver account that CAN reconnect must not wait minutes; a 60s steady-state retry is
// used instead — the cap value is an engineering choice, the protocol-grounded
// requirement is only that a cap exists.
const maxAutoReconnectDelay = 60 * time.Second

// autoReconnectDelayFor computes the auto-reconnect backoff for a given AutoReconnectErrors
// count, capped at maxAutoReconnectDelay. Extracted from autoReconnect so tests can assert
// the cap without running the reconnect loop.
func autoReconnectDelayFor(autoReconnectErrors int) time.Duration {
	delay := time.Duration(autoReconnectErrors) * 2 * time.Second
	if delay > maxAutoReconnectDelay {
		delay = maxAutoReconnectDelay
	}
	return delay
}

func (cli *Client) autoReconnect(ctx context.Context) {
	if !cli.EnableAutoReconnect || cli.Store.ID == nil {
		return
	}
	for {
		autoReconnectDelay := autoReconnectDelayFor(cli.AutoReconnectErrors)
		cli.Log.Debugf("Automatically reconnecting after %v", autoReconnectDelay)
		cli.AutoReconnectErrors++
		if cli.expectedDisconnect.WaitTimeoutCtx(ctx, autoReconnectDelay) == nil {
			cli.Log.Debugf("Cancelling automatic reconnect due to expected disconnect")
			return
		} else if ctx.Err() != nil {
			cli.Log.Debugf("Cancelling automatic reconnect due to context cancellation")
			return
		}
		err := cli.connect(ctx)
		if errors.Is(err, ErrAlreadyConnected) {
			cli.Log.Debugf("Connect() said we're already connected after autoreconnect sleep")
			return
		} else if err != nil {
			if cli.expectedDisconnect.IsSet() {
				cli.Log.Debugf("Autoreconnect failed, but disconnect was expected, not reconnecting")
				return
			}
			cli.Log.Errorf("Error reconnecting after autoreconnect sleep: %v", err)
			if cli.AutoReconnectHook != nil && !cli.AutoReconnectHook(err) {
				cli.Log.Debugf("AutoReconnectHook returned false, not reconnecting")
				return
			}
		} else {
			return
		}
	}
}

// IsConnected checks if the client is connected to the WhatsApp web websocket.
// Note that this doesn't check if the client is authenticated. See the IsLoggedIn field for that.
func (cli *Client) IsConnected() bool {
	if cli == nil {
		return false
	}
	cli.socketLock.RLock()
	connected := cli.socket != nil && cli.socket.IsConnected()
	cli.socketLock.RUnlock()
	return connected
}

// Disconnect disconnects from the WhatsApp web websocket.
//
// This will not emit any events, the Disconnected event is only used when the
// connection is closed by the server or a network error.
func (cli *Client) Disconnect() {
	if cli == nil {
		return
	}
	cli.socketLock.Lock()
	cli.expectDisconnect()
	cli.unlockedDisconnect()
	cli.socketLock.Unlock()
	cli.clearDelayedMessageRequests()
}

// ResetConnection disconnects from the WhatsApp web websocket and forces an automatic reconnection.
// This will not do anything if the socket is already disconnected or if EnableAutoReconnect is false.
func (cli *Client) ResetConnection() {
	if cli == nil {
		return
	}
	cli.socketLock.Lock()
	cli.forceAutoReconnect.Store(true)
	if cli.socket != nil {
		cli.socket.Stop(true, true)
		cli.clearResponseWaiters(xmlStreamEndNode)
	}
	cli.socketLock.Unlock()
}

// Disconnect closes the websocket connection.
func (cli *Client) unlockedDisconnect() {
	if cli.socket != nil {
		cli.socket.Stop(true, false)
		cli.socket = nil
		cli.clearResponseWaiters(xmlStreamEndNode)
	}
}

// Logout sends a request to unlink the device, then disconnects from the websocket and deletes the local device store.
//
// If the logout request fails, the disconnection and local data deletion will not happen either.
// If an error is returned, but you want to force disconnect/clear data, call Client.Disconnect() and Client.Store.Delete() manually.
//
// Note that this will not emit any events. The LoggedOut event is only used for external logouts
// (triggered by the user from the main device or by WhatsApp servers).
func (cli *Client) Logout(ctx context.Context) error {
	if cli == nil {
		return ErrClientIsNil
	} else if cli.MessengerConfig != nil {
		return errors.New("can't logout with Messenger credentials")
	}
	ownID := cli.getOwnID()
	if ownID.IsEmpty() {
		return ErrNotLoggedIn
	}
	_, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "md",
		Type:      "set",
		To:        types.ServerJID,
		Content: []waBinary.Node{{
			Tag: "remove-companion-device",
			Attrs: waBinary.Attrs{
				"jid":    ownID,
				"reason": "user_initiated",
			},
		}},
	})
	if err != nil {
		return fmt.Errorf("error sending logout request: %w", err)
	}
	cli.Disconnect()
	err = cli.Store.Delete(ctx)
	if err != nil {
		return fmt.Errorf("error deleting data from store: %w", err)
	}
	return nil
}

// AddEventHandler registers a new function to receive all events emitted by this client.
//
// The returned integer is the event handler ID, which can be passed to RemoveEventHandler to remove it.
//
// All registered event handlers will receive all events. You should use a type switch statement to
// filter the events you want:
//
//	func myEventHandler(evt any) {
//		switch v := evt.(type) {
//		case *events.Message:
//			fmt.Println("Received a message!")
//		case *events.Receipt:
//			fmt.Println("Received a receipt!")
//		}
//	}
//
// If you want to access the Client instance inside the event handler, the recommended way is to
// wrap the whole handler in another struct:
//
//	type MyClient struct {
//		WAClient *whatsmeow.Client
//		eventHandlerID uint32
//	}
//
//	func (mycli *MyClient) register() {
//		mycli.eventHandlerID = mycli.WAClient.AddEventHandler(mycli.myEventHandler)
//	}
//
//	func (mycli *MyClient) myEventHandler(evt any) {
//		// Handle event and access mycli.WAClient
//	}
func (cli *Client) AddEventHandler(handler EventHandler) uint32 {
	return cli.AddEventHandlerWithSuccessStatus(func(evt any) bool {
		handler(evt)
		return true
	})
}

func (cli *Client) AddEventHandlerWithSuccessStatus(handler EventHandlerWithSuccessStatus) uint32 {
	nextID := atomic.AddUint32(&nextHandlerID, 1)
	cli.eventHandlersLock.Lock()
	cli.eventHandlers = append(cli.eventHandlers, wrappedEventHandler{handler, nextID})
	cli.eventHandlersLock.Unlock()
	return nextID
}

// RemoveEventHandler removes a previously registered event handler function.
// If the function with the given ID is found, this returns true.
//
// N.B. Do not run this directly from an event handler. That would cause a deadlock because the
// event dispatcher holds a read lock on the event handler list, and this method wants a write lock
// on the same list. Instead run it in a goroutine:
//
//	func (mycli *MyClient) myEventHandler(evt any) {
//		if noLongerWantEvents {
//			go mycli.WAClient.RemoveEventHandler(mycli.eventHandlerID)
//		}
//	}
func (cli *Client) RemoveEventHandler(id uint32) bool {
	cli.eventHandlersLock.Lock()
	defer cli.eventHandlersLock.Unlock()
	for index := range cli.eventHandlers {
		if cli.eventHandlers[index].id == id {
			if index == 0 {
				cli.eventHandlers[0].fn = nil
				cli.eventHandlers = cli.eventHandlers[1:]
				return true
			} else if index < len(cli.eventHandlers)-1 {
				copy(cli.eventHandlers[index:], cli.eventHandlers[index+1:])
			}
			cli.eventHandlers[len(cli.eventHandlers)-1].fn = nil
			cli.eventHandlers = cli.eventHandlers[:len(cli.eventHandlers)-1]
			return true
		}
	}
	return false
}

// RemoveEventHandlers removes all event handlers that have been registered with AddEventHandler
func (cli *Client) RemoveEventHandlers() {
	cli.eventHandlersLock.Lock()
	cli.eventHandlers = make([]wrappedEventHandler, 0, 1)
	cli.eventHandlersLock.Unlock()
}

// handleXMLStreamEnd processes a received xmlstreamend frame (55.1-12).
//
// Sourced from WA Web's own client (~/work/wa_protocol,
// WAWebCommsHandleLoggedInStanza.js:141-142): its xmlstreamend handler only logs
// ("Comms.handleStanza received xmlstreamend, return NO_ACK") and does NOT proactively close
// the socket -- only a handler that explicitly returns "CLOSE_SOCKET" does that
// (WAComms.js:161-168), and xmlstreamend's handler isn't one of them. WA Web relies on the
// transport-level close the server sends immediately after to drive the reconnect, via its own
// deadSocketTimer/onclose plumbing outside handleStanza. The fork's existing
// conn.Read()-failure -> onDisconnect -> autoReconnect chain (socket/framesocket.go readPump,
// client.go onDisconnect) IS that same transport-level path, so no new teardown call is added
// here -- the prior "TODO should we do something else?" is answered: no, this already matches
// WA Web. Only the observability (counter) and the alarming Warnf were the actual gap.
func (cli *Client) handleXMLStreamEnd() {
	if cli.isExpectedDisconnect() {
		return
	}
	if n := connectionLifecycleEvents.Add(1); n%connectionLifecycleEventsLogEvery == 0 {
		cli.Log.Infof("CONNECTION_LIFECYCLE_HANDLED count=%d", n)
	}
	cli.Log.Debugf("Received stream end frame (handled lifecycle; reconnect follows the transport-level close, same as WA Web's own client)")
}

func (cli *Client) handleFrame(ctx context.Context, data []byte) {
	decompressed, err := waBinary.Unpack(data)
	if err != nil {
		cli.Log.Warnf("Failed to decompress frame: %v", err)
		cli.Log.Debugf("Errored frame hex: %s", hex.EncodeToString(data))
		return
	}
	node, err := waBinary.Unmarshal(decompressed)
	if err != nil {
		cli.Log.Warnf("Failed to decode node in frame: %v", err)
		cli.Log.Debugf("Errored frame hex: %s", hex.EncodeToString(decompressed))
		return
	}
	cli.recvLog.Debugf("%s", node)
	if node.Tag == "xmlstreamend" {
		cli.handleXMLStreamEnd()
	} else if cli.receiveResponse(ctx, node) {
		// handled
	} else if _, ok := cli.nodeHandlers[node.Tag]; ok {
		select {
		case cli.handlerQueue <- node:
		case <-ctx.Done():
		default:
			cli.Log.Warnf("Handler queue is full, message ordering is no longer guaranteed")
			go func() {
				select {
				case cli.handlerQueue <- node:
				case <-ctx.Done():
				}
			}()
		}
	} else if node.Tag != "ack" {
		cli.Log.Debugf("Didn't handle WhatsApp node %s", node.Tag)
	}
}

func (cli *Client) handlerQueueLoop(evtCtx, connCtx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	ticker.Stop()
	cli.Log.Debugf("Starting handler queue loop")
Loop:
	for {
		select {
		case node := <-cli.handlerQueue:
			doneChan := make(chan struct{})
			start := time.Now()
			go func() {
				cli.nodeHandlers[node.Tag](evtCtx, node)
				duration := time.Since(start)
				close(doneChan)
				if duration > 5*time.Second {
					cli.Log.Warnf("Node handling took %s for %s", duration, node)
				}
			}()
			ticker.Reset(30 * time.Second)
			for i := 0; i < 10; i++ {
				select {
				case <-doneChan:
					ticker.Stop()
					continue Loop
				case <-ticker.C:
					cli.Log.Warnf("Node handling is taking long for %s (started %s ago)", node, time.Since(start))
				}
			}
			cli.Log.Warnf("Continuing handling of %s in background as it's taking too long", node)
			ticker.Stop()
		case <-connCtx.Done():
			cli.Log.Debugf("Closing handler queue loop")
			return
		}
	}
}

func (cli *Client) sendNodeAndGetData(ctx context.Context, node waBinary.Node) ([]byte, error) {
	if cli == nil {
		return nil, ErrClientIsNil
	}
	cli.socketLock.RLock()
	sock := cli.socket
	cli.socketLock.RUnlock()
	if sock == nil {
		return nil, ErrNotConnected
	}

	payload, err := waBinary.Marshal(node)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal node: %w", err)
	}

	cli.sendLog.Debugf("%s", &node)
	return payload, sock.SendFrame(ctx, payload)
}

func (cli *Client) sendNode(ctx context.Context, node waBinary.Node) error {
	_, err := cli.sendNodeAndGetData(ctx, node)
	return err
}

// sendNodeOrHook sends node via cli.sendNodeFunc if a test has installed one, otherwise via
// the real cli.sendNode. See the sendNodeFunc field doc.
func (cli *Client) sendNodeOrHook(ctx context.Context, node waBinary.Node) error {
	if cli.sendNodeFunc != nil {
		return cli.sendNodeFunc(ctx, node)
	}
	return cli.sendNode(ctx, node)
}

// pendingStanzaCap bounds the reconnect-durable ack/receipt queue (55.1-02) — far above any
// observed disconnect window's ack volume.
const pendingStanzaCap = 10000

// pendingStanzaOverflowLogInterval throttles the queue-full ERROR so a sustained overflow
// logs periodically instead of once per discarded entry.
const pendingStanzaOverflowLogInterval = time.Minute

type pendingStanzaKey struct {
	Tag string
	ID  string
	To  string
}

type pendingStanzaEntry struct {
	key  pendingStanzaKey
	node waBinary.Node
}

func pendingStanzaKeyFromNode(node waBinary.Node) pendingStanzaKey {
	return pendingStanzaKey{
		Tag: node.Tag,
		ID:  fmt.Sprintf("%v", node.Attrs["id"]),
		To:  fmt.Sprintf("%v", node.Attrs["to"]),
	}
}

// enqueuePendingStanza queues an ack/receipt node that failed to send because the socket was
// down (ErrNotConnected), for replay on the next successful connect (replayPendingStanzas).
// Deduplicated by (tag,id,to); at pendingStanzaCap the oldest entry is discarded and a
// throttled ERROR reports the overflow count so bounded memory never becomes silent loss.
func (cli *Client) enqueuePendingStanza(node waBinary.Node) {
	key := pendingStanzaKeyFromNode(node)
	cli.pendingStanzasLock.Lock()
	defer cli.pendingStanzasLock.Unlock()
	if cli.pendingStanzasSeen == nil {
		cli.pendingStanzasSeen = make(map[pendingStanzaKey]bool)
	}
	if cli.pendingStanzasSeen[key] {
		return
	}
	if len(cli.pendingStanzas) >= pendingStanzaCap {
		discarded := cli.pendingStanzas[0]
		cli.pendingStanzas = cli.pendingStanzas[1:]
		delete(cli.pendingStanzasSeen, discarded.key)
		cli.pendingStanzasOverflowCount++
		if time.Since(cli.pendingStanzasLastOverflowLog) >= pendingStanzaOverflowLogInterval {
			cli.Log.Errorf("Pending ack/receipt queue full (cap %d): discarded %d oldest entries since last report", pendingStanzaCap, cli.pendingStanzasOverflowCount)
			cli.pendingStanzasOverflowCount = 0
			cli.pendingStanzasLastOverflowLog = time.Now()
		}
	}
	cli.pendingStanzas = append(cli.pendingStanzas, pendingStanzaEntry{key: key, node: node})
	cli.pendingStanzasSeen[key] = true
}

// replayPendingStanzas drains the pending ack/receipt queue and re-sends each node in FIFO
// order. Called from handleConnectSuccess once the connection is active again. An entry that
// hits ErrNotConnected again (connect raced another drop) is re-enqueued along with every
// entry after it, preserving order, and replay stops there; an entry rejected with any other
// error is logged (Warnf) and discarded.
func (cli *Client) replayPendingStanzas(ctx context.Context) {
	cli.pendingStanzasLock.Lock()
	pending := cli.pendingStanzas
	cli.pendingStanzas = nil
	cli.pendingStanzasSeen = nil
	cli.pendingStanzasLock.Unlock()

	for i, entry := range pending {
		err := cli.sendNodeOrHook(ctx, entry.node)
		if err == nil {
			continue
		}
		if errors.Is(err, ErrNotConnected) {
			for _, remaining := range pending[i:] {
				cli.enqueuePendingStanza(remaining.node)
			}
			return
		}
		cli.Log.Warnf("Failed to replay pending %s %s: %v", entry.node.Tag, entry.node.Attrs["id"], err)
	}
}

func (cli *Client) dispatchEvent(evt any) (handlerFailed bool) {
	cli.eventHandlersLock.RLock()
	defer func() {
		cli.eventHandlersLock.RUnlock()
		err := recover()
		if err != nil {
			cli.Log.Errorf("Event handler panicked while handling a %T: %v\n%s", evt, err, debug.Stack())
		}
	}()
	for _, handler := range cli.eventHandlers {
		if !handler.fn(evt) {
			return true
		}
	}
	return false
}

// ParseWebMessage parses a WebMessageInfo object into *events.Message to match what real-time messages have.
//
// The chat JID can be found in the Conversation data:
//
//	chatJID, err := types.ParseJID(conv.GetId())
//	for _, historyMsg := range conv.GetMessages() {
//		evt, err := cli.ParseWebMessage(chatJID, historyMsg.GetMessage())
//		yourNormalEventHandler(evt)
//	}
func (cli *Client) ParseWebMessage(chatJID types.JID, webMsg *waWeb.WebMessageInfo) (*events.Message, error) {
	var err error
	if chatJID.IsEmpty() {
		chatJID, err = types.ParseJID(webMsg.GetKey().GetRemoteJID())
		if err != nil {
			return nil, fmt.Errorf("no chat JID provided and failed to parse remote JID: %w", err)
		}
	}
	info := types.MessageInfo{
		MessageSource: types.MessageSource{
			Chat:     chatJID,
			IsFromMe: webMsg.GetKey().GetFromMe(),
			IsGroup:  chatJID.Server == types.GroupServer,
		},
		ID:        webMsg.GetKey().GetID(),
		PushName:  webMsg.GetPushName(),
		Timestamp: time.Unix(int64(webMsg.GetMessageTimestamp()), 0),
	}
	if info.IsFromMe {
		if webMsg.GetOriginalSelfAuthorUserJIDString() != "" {
			info.Sender, err = types.ParseJID(webMsg.GetOriginalSelfAuthorUserJIDString())
		} else {
			info.Sender = cli.getOwnID().ToNonAD()
			if info.Sender.IsEmpty() {
				return nil, ErrNotLoggedIn
			}
		}
	} else if chatJID.Server == types.DefaultUserServer || chatJID.Server == types.HiddenUserServer || chatJID.Server == types.NewsletterServer {
		info.Sender = chatJID
	} else if webMsg.GetParticipant() != "" {
		info.Sender, err = types.ParseJID(webMsg.GetParticipant())
	} else if webMsg.GetKey().GetParticipant() != "" {
		info.Sender, err = types.ParseJID(webMsg.GetKey().GetParticipant())
	} else {
		return nil, fmt.Errorf("couldn't find sender of message %s", info.ID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse sender of message %s: %v", info.ID, err)
	}
	if pk := webMsg.GetCommentMetadata().GetCommentParentKey(); pk != nil {
		info.MsgMetaInfo.ThreadMessageID = pk.GetID()
		info.MsgMetaInfo.ThreadMessageSenderJID, _ = types.ParseJID(pk.GetParticipant())
	}
	evt := &events.Message{
		RawMessage:   webMsg.GetMessage(),
		SourceWebMsg: webMsg,
		Info:         info,
	}
	evt.UnwrapRaw()
	if evt.Message.GetProtocolMessage().GetType() == waE2E.ProtocolMessage_MESSAGE_EDIT {
		evt.Info.ID = evt.Message.GetProtocolMessage().GetKey().GetID()
		evt.Message = evt.Message.GetProtocolMessage().GetEditedMessage()
	}
	return evt, nil
}

func (cli *Client) StoreLIDPNMapping(ctx context.Context, first, second types.JID) {
	var lid, pn types.JID
	if first.Server == types.HiddenUserServer && second.Server == types.DefaultUserServer {
		lid = first
		pn = second
	} else if first.Server == types.DefaultUserServer && second.Server == types.HiddenUserServer {
		lid = second
		pn = first
	} else {
		return
	}
	err := cli.Store.LIDs.PutLIDMapping(ctx, lid, pn)
	if err != nil {
		cli.Log.Errorf("Failed to store LID-PN mapping for %s -> %s: %v", lid, pn, err)
	}
}

const unifiedOffset = 3 * 24 * time.Hour
const week = 7 * 24 * time.Hour

func (cli *Client) getUnifiedSessionID() string {
	unifiedTS := time.Now().
		Add(time.Duration(cli.serverTimeOffset.Load())).
		Add(unifiedOffset)
	unifiedID := unifiedTS.UnixMilli() % week.Milliseconds()
	return strconv.FormatInt(unifiedID, 10)
}

func (cli *Client) sendUnifiedSession() {
	if cli == nil {
		return
	}

	node := waBinary.Node{
		Tag:   "ib",
		Attrs: waBinary.Attrs{},
		Content: []waBinary.Node{{
			Tag: "unified_session",
			Attrs: waBinary.Attrs{
				"id": cli.getUnifiedSessionID(),
			},
		}},
	}

	err := cli.sendNode(cli.BackgroundEventCtx, node)
	if err != nil {
		cli.Log.Debugf("Failed to send unified_session telemetry: %v", err)
	}
}
