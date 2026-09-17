# core:vpn

A local VPN-based network traffic interception engine for Android. It creates a TUN interface, intercepts all TCP and UDP packets from the device, optionally performs TLS man-in-the-middle (MitM) inspection, and persists decoded sessions, connections, HTTP requests, and responses to the Room database.

---

## Table of Contents

- [Overview](#overview)
- [Package Structure](#package-structure)
- [Architecture](#architecture)
- [Packet Lifecycle](#packet-lifecycle)
  - [Outbound (device → internet)](#outbound-device--internet)
  - [Inbound (internet → device)](#inbound-internet--device)
- [Component Reference](#component-reference)
  - [ComponentManager](#componentmanager)
  - [Thread Layer](#thread-layer)
  - [Transport Layer](#transport-layer)
  - [Encryption Layer](#encryption-layer)
  - [Application Layer](#application-layer)
  - [Inet Layer — IP Packet Builders](#inet-layer--ip-packet-builders)
  - [Caches](#caches)
  - [MitM Infrastructure](#mitm-infrastructure)
  - [Database Connector](#database-connector)
- [TLS MitM Deep Dive](#tls-mitm-deep-dive)
- [Threading Model](#threading-model)
- [Configuration](#configuration)
- [Key Dependencies](#key-dependencies)

---

## Overview

When the Heimdall VPN service is active, all IP traffic from the device is routed into a TUN file descriptor. This module reads those raw packets, proxies TCP connections and UDP datagrams to their real destinations over regular Android sockets, and (when MitM is enabled) intercepts TLS sessions to expose plaintext HTTP traffic for logging.

The module is structured as a layered protocol stack. Each layer has a clean interface to the layer above and below it, making it straightforward to add new protocol handlers.

---

## Package Structure

```
core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/
│
├── components/                     Threads, handlers, and the central orchestrator
│   ├── ComponentManager.kt         Creates and wires all threads/caches/MitM state
│   ├── DevicePollThread.kt         Reads raw IP packets from the TUN interface
│   ├── DeviceWriteThread.kt        Writes response packets back to the TUN interface
│   ├── OutboundTrafficHandler.kt   Dispatches outbound packets to transport-layer connections
│   ├── InboundTrafficHandler.kt    Polls remote sockets via NIO Selector for inbound data
│   ├── DatabaseConnector.kt        Interface for all database persistence operations
│   └── RoomDatabaseConnector.kt    Room implementation of DatabaseConnector
│
├── cache/
│   └── ConnectionCache.kt          5-tuple keyed map of active transport-layer connections
│
├── metadata/
│   ├── DnsCache.kt                 TTL-aware IP→hostname map populated from DNS responses
│   └── TlsPassthroughCache.kt      Per-(appId, hostname) set of connections to skip MitM
│
├── connection/
│   ├── transportLayer/
│   │   ├── TransportLayerConnection.kt   Abstract base; factory; connection state machine
│   │   ├── TcpConnection.kt              Full TCP sequence-number tracking + handshake
│   │   └── UdpConnection.kt              Stateless UDP proxy; DNS ephemeral-close handling
│   │
│   ├── encryptionLayer/
│   │   ├── EncryptionLayerConnection.kt  Protocol detection (TLS / QUIC / plaintext); factory
│   │   ├── TlsConnection.kt              Dual SSLEngine MitM with TLS record reassembly
│   │   ├── PlaintextConnection.kt        Passthrough for unencrypted traffic
│   │   └── QuicConnection.kt             QUIC detection placeholder (passthrough; no MitM)
│   │
│   ├── appLayer/
│   │   ├── AppLayerConnection.kt         Protocol detection (HTTP / DNS / raw); factory
│   │   ├── HttpConnection.kt             HTTP request/response parsing and persistence
│   │   ├── DnsConnection.kt              Populates DnsCache from DNS response packets
│   │   └── RawConnection.kt              Passthrough for unrecognised application protocols
│   │
│   └── inetLayer/
│       ├── IpPacketBuilder.kt            Abstract factory for constructing IP response packets
│       ├── IpV4PacketBuilder.kt          IPv4 packet construction (Pcap4j)
│       └── IpV6PacketBuilder.kt          IPv6 packet construction (Pcap4j)
│
└── mitm/
    ├── Authority.kt                      CA metadata and file-path conventions
    ├── CertificateHelper.kt              BouncyCastle RSA/X.509 certificate generation
    ├── KeyStoreHelper.kt                 PKCS12 keystore lifecycle; PEM/Magisk export
    ├── SSLEngineSource.kt                SSLEngine factory; per-host certificate caching
    ├── CertificateSniffingMitmManager.kt Top-level MitM coordinator; reads upstream certs
    ├── SubjectAlternativeNameHolder.kt   SAN list builder for generated certificates
    ├── MergeTrustManager.kt              Accepts certs from both Heimdall CA and system CAs
    └── nio/
        └── NioSslPeer.kt                 NIO TLS handshake state machine (utility base)
```

---

## Architecture

The module is a layered protocol stack. Each connection object owns the layer below it and calls up through a delegate when data is ready.

```
┌─────────────────────────────────────────────┐
│              ComponentManager               │  (orchestrator + global state)
├─────────────────────────────────────────────┤
│           Thread / Handler Layer            │
│  DevicePollThread   DeviceWriteThread       │
│  OutboundTrafficHandler  InboundTrafficHandler│
├─────────────────────────────────────────────┤
│           Transport Layer                   │
│  TcpConnection       UdpConnection          │
├─────────────────────────────────────────────┤
│           Encryption Layer                  │
│  TlsConnection   PlaintextConnection        │
│  QuicConnection  (passthrough)              │
├─────────────────────────────────────────────┤
│           Application Layer                 │
│  HttpConnection  DnsConnection  RawConnection│
└─────────────────────────────────────────────┘
```

Each layer exposes two symmetric methods:

| Method | Direction | Meaning |
|---|---|---|
| `unwrapOutbound(payload)` | device → internet | Strip lower-layer framing, pass payload up |
| `unwrapInbound()` | internet → device | Read from socket, pass payload up |
| `wrapOutbound(payload)` | app-layer → internet | Add lower-layer framing, send to server |
| `wrapInbound(payload)` | app-layer → device | Add lower-layer framing, write to TUN |

---

## Packet Lifecycle

### Outbound (device → internet)

```
TUN fd (FileInputStream)
  │
  ▼
DevicePollThread.poll()
  │  Os.poll() on TUN fd + interrupter pipe
  │  Pcap4j: parse raw bytes → IpV4Packet / IpV6Packet
  │  Drops broadcasts (255.255.255.255), non-TCP/UDP
  │
  ▼ Handler message (what=6 TCP, what=17 UDP)
OutboundTrafficHandler
  │  Looks up or creates TransportLayerConnection in ConnectionCache
  │  Calls connection.unwrapOutbound(transportPayload)
  │
  ▼
TcpConnection / UdpConnection
  │  TCP: tracks sequence numbers, drives connect/SYN-ACK handshake
  │  UDP: immediately connected; DNS gets ephemeral close after first reply
  │  Calls passOutboundToEncryptionLayer(payload)
  │
  ▼
EncryptionLayerConnection.getInstance()   [created on first payload]
  │  Detects TLS (byte 0 = 0x16), QUIC (long-header version check), or plaintext
  │  Calls encryptionLayer.unwrapOutbound(payload)
  │
  ▼
TlsConnection / PlaintextConnection / QuicConnection
  │  TLS: reassembles fragmented records; extracts SNI; drives dual SSLEngine MitM
  │  Plaintext / QUIC: direct passthrough
  │  Calls passOutboundToAppLayer(plaintext)
  │
  ▼
AppLayerConnection.getInstance()          [created on first payload]
  │  Port 53 → DnsConnection
  │  Payload starts with HTTP verb → HttpConnection
  │  Otherwise → RawConnection
  │  Calls appLayer.unwrapOutbound(payload)
  │
  ▼
HttpConnection / DnsConnection / RawConnection
  │  HttpConnection: reassembles headers + body; persists to DB; forwards
  │  DnsConnection: forwards query unchanged
  │  RawConnection: forwards unchanged
  │  Calls encryptionLayer.wrapOutbound(payload)
  │
  ▼  (back down through encryption → transport)
SocketChannel.write() / DatagramChannel.send()   →   Remote server
```

### Inbound (internet → device)

```
Remote server   →   SocketChannel / DatagramChannel
  │
  ▼
InboundTrafficHandler (NIO Selector loop)
  │  selector.select() blocks until any registered channel has data
  │  Retrieves TransportLayerConnection from SelectionKey attachment
  │  Calls connection.unwrapInbound()
  │
  ▼
TcpConnection / UdpConnection
  │  TCP: OP_CONNECT completes handshake; OP_READ reads bytes from channel
  │  UDP: reads single datagram; DNS closes channel after first response
  │  Calls passInboundToEncryptionLayer(payload)
  │
  ▼ … (mirrors outbound path upward, then back down) …
  │
  ▼
encryptionLayer.wrapInbound(payload)
  │
  ▼
transportLayer.wrapInbound(payload)
  │  TcpConnection: builds TCP PSH+ACK segments; may split large payloads
  │  UdpConnection: wraps in UDP datagram
  │  Calls deviceWriter.sendMessage(ipPacket)
  │
  ▼
DeviceWriteThread
  │  Writes ipPacket.rawData to FileOutputStream (TUN fd)
  │
  ▼
TUN fd → Device app
```

---

## Component Reference

### ComponentManager

**`components/ComponentManager.kt`**

The single point of wiring for the entire module. It is instantiated once by `HeimdallVpnService` and passed to every thread and connection object that needs shared state.

**Responsibilities:**
- Creates and starts all four threads in the correct order (write → inbound+outbound → poll)
- Initialises the NIO `Selector` used by `InboundTrafficHandler`
- Initialises `CertificateSniffingMitmManager` (the MitM root CA and certificate factory)
- Holds the `DnsCache`, `TlsPassthroughCache`, and `ConnectionCache` singletons
- Builds the tracker-hostname `Trie` from the bundled Steven Black hosts file
- Persists the VPN session record on start; updates its end time on stop

**Key properties:**

| Property | Type | Purpose |
|---|---|---|
| `doMitm` | `Boolean` | Master switch for TLS interception |
| `sessionId` | `Int` | Room ID of the current VPN session |
| `selector` | `Selector` | NIO selector shared by inbound handler and transport connections |
| `selectorMonitor` | `Any` | Lock protecting concurrent selector modifications |
| `dnsCache` | `DnsCache` | IP→hostname map, populated by DnsConnection |
| `tlsPassthroughCache` | `TlsPassthroughCache` | (appId, hostname) pairs that skip MitM |
| `mitmManager` | `CertificateSniffingMitmManager?` | null when `doMitm = false` |
| `trackerTrie` | `Trie<String>` | Trie of ad/tracker domains for `isTracker` labelling |
| `appFinder` | `AppFinder` | Resolves socket UID → package name |
| `databaseConnector` | `DatabaseConnector` | Abstracts all Room persistence |
| `maxPacketSize` | `Int` | VPN interface MTU (default 16 413 bytes) |

---

### Thread Layer

#### DevicePollThread

**`components/DevicePollThread.kt`**

Runs at `THREAD_PRIORITY_FOREGROUND`. Calls `Os.poll()` on two file descriptors: the TUN `inputStream` and a one-shot interrupter pipe used for graceful shutdown. On each readable event, reads up to `maxPacketSize` bytes into a reused buffer, calls Pcap4j to parse the raw bytes into an `IpPacket`, and sends a `Handler` message to `OutboundTrafficHandler`.

Silently drops:
- IPv6 extension headers and anything that isn't TCP (6) or UDP (17)
- IPv4 broadcast packets to `255.255.255.255`
- Packets whose stated length does not match the read length

#### DeviceWriteThread

**`components/DeviceWriteThread.kt`**

A `HandlerThread`. Receives `IpPacket` objects via its `Handler`. Writes `packet.rawData` directly to the TUN `FileOutputStream`. Fires a callback (`handlerReadyListener`) once its `Looper` is prepared so `ComponentManager` knows the write path is ready before starting the inbound/outbound handlers.

#### OutboundTrafficHandler

**`components/OutboundTrafficHandler.kt`**

A `HandlerThread`. Receives messages from `DevicePollThread` (`msg.what` = protocol number, `msg.obj` = `IpPacket`). Calls `TransportLayerConnection.getInstance()` to find or create a connection, then calls `unwrapOutbound()` on it.

#### InboundTrafficHandler

**`components/InboundTrafficHandler.kt`**

A plain `Thread` running a continuous `selector.select()` loop. For each ready `SelectionKey`, retrieves the `TransportLayerConnection` stored as the key's attachment and calls `unwrapInbound()`. Acquires `ComponentManager.selectorMonitor` while iterating to prevent races with connections registering new keys.

---

### Transport Layer

#### TransportLayerConnection (abstract)

**`connection/transportLayer/TransportLayerConnection.kt`**

Base class for all per-connection state. Tracks:

```kotlin
enum class TransportLayerState { CONNECTING, CONNECTED, CLOSING, CLOSED, ABORTED }
```

**Factory (`getInstance`):** Checks `ConnectionCache` first. On a miss, resolves the hostname from `DnsCache`, chooses `TcpConnection` or `UdpConnection`, registers it with the NIO `Selector`, adds it to the cache, and persists a `Connection` entity to the database (skipped for DNS port 53).

TCP packets carrying FIN/ACK/RST flags for connections that have no cache entry trigger a synthesised RST sent back to the device.

#### TcpConnection

**`connection/transportLayer/TcpConnection.kt`**

Implements the minimal TCP state machine needed to act as a transparent proxy:

- **SYN received:** Opens a non-blocking `SocketChannel` to the remote host, registers `OP_CONNECT`.
- **OP_CONNECT fires (via InboundTrafficHandler):** Calls `finishConnect()`, sends SYN-ACK to device, re-registers for `OP_READ`, transitions to `CONNECTED`.
- **ACK + data received:** Sends an empty ACK back to device immediately, forwards data to the encryption layer.
- **FIN / FIN-ACK received:** Runs a four-way close sequence, transitions to `CLOSED`.

Sequence numbers are tracked per connection. Large inbound payloads are automatically split into multiple TCP segments to respect the client's window size.

#### UdpConnection

**`connection/transportLayer/UdpConnection.kt`**

A `DatagramChannel` connected to the remote host. Because UDP is stateless, the connection is considered `CONNECTED` immediately after construction. DNS connections (port 53) are ephemeral: the channel is closed and the cache entry removed after the first inbound datagram.

---

### Encryption Layer

#### EncryptionLayerConnection (abstract)

**`connection/encryptionLayer/EncryptionLayerConnection.kt`**

**Protocol detection (first outbound payload only):**

| Protocol | Detection rule |
|---|---|
| TLS | Byte 0 = `0x16` (Handshake record type), byte 5 = `0x01` (ClientHello) |
| QUIC | Long-header form (`byte[0] & 0xC0 == 0xC0`), version bytes 1–4 = `0x00000001` or `0x00000000` |
| Plaintext | Anything else |

Lazily creates an `AppLayerConnection` on the first decoded payload.

#### TlsConnection

**`connection/encryptionLayer/TlsConnection.kt`**

The most complex class in the module. Manages two independent `SSLEngine` instances—one facing the remote server (client mode) and one facing the device (server mode)—to perform a transparent MitM intercept.

See [TLS MitM Deep Dive](#tls-mitm-deep-dive) below.

#### PlaintextConnection

**`connection/encryptionLayer/PlaintextConnection.kt`**

Zero-overhead passthrough. Forwards payloads directly to/from the application layer.

#### QuicConnection

**`connection/encryptionLayer/QuicConnection.kt`**

Detects QUIC packets and sets `doMitm = false`. Forwards without decryption. Full QUIC interception is not implemented.

---

### Application Layer

#### AppLayerConnection (abstract)

**`connection/appLayer/AppLayerConnection.kt`**

**Protocol detection (first decoded payload):**

| Protocol | Detection rule |
|---|---|
| DNS | `remotePort == 53` |
| HTTP | First 11 bytes contain a HTTP method keyword (`GET`, `POST`, `HTTP`, etc.) |
| Raw | Anything else |

Inbound-only connections (created as fallback before the outbound side is known) always use `RawConnection`.

#### HttpConnection

**`connection/appLayer/HttpConnection.kt`**

Reassembles HTTP/1.x messages from a stream of payloads:
1. Accumulates data until `\r\n\r\n` (end of headers) is seen.
2. Parses `Content-Length` or `Transfer-Encoding: chunked` to determine body boundaries.
3. Once a complete message is assembled (up to 1 MB), persists it to the database and forwards the raw bytes to the layer below.

Bodies larger than 1 MB are logged as `<too large: N bytes>`.

Chunked transfer encoding is decoded with `dechunkHttpMessage()` before database persistence.

Requests and responses are correlated by passing the database `requestId` through a `Channel<Int>` between the outbound and inbound coroutines.

#### DnsConnection

**`connection/appLayer/DnsConnection.kt`**

On inbound responses, parses the DNS packet (Pcap4j `DnsPacket`) and inserts each answer record (`A`/`AAAA`) into `ComponentManager.dnsCache` with its TTL. This lets the transport layer resolve IP addresses to hostnames for later connections to the same host.

#### RawConnection

**`connection/appLayer/RawConnection.kt`**

Passthrough for unrecognised protocols. Logs a warning if MitM is enabled (indicating a protocol that escapes inspection).

---

### Inet Layer — IP Packet Builders

**`connection/inetLayer/`**

`IpPacketBuilder` is an abstract factory selected by `TransportLayerConnection` based on the IP version of the initial packet. Subclasses (`IpV4PacketBuilder`, `IpV6PacketBuilder`) hold the local and remote addresses, swap source and destination when building response packets, and copy protocol-specific fields (TOS, flow label, etc.) from the initial packet. The `identification` counter in `IpV4PacketBuilder` is incremented for each constructed packet.

---

### Caches

#### ConnectionCache

**`cache/ConnectionCache.kt`**

A `HashMap` keyed by a 32-bit XOR hash of `(remoteAddress, protocol, localPort, remotePort)`. Provides `findConnection`, `addConnection`, `removeConnection`, and `closeAllAndClear` (calls `closeSoft()` on every entry before clearing). Used as a module-level singleton via its companion object.

#### DnsCache

**`metadata/DnsCache.kt`**

A size-bounded `LinkedHashMap` with TTL-based expiry. Maximum 1 000 entries; default TTL 60 seconds. Expired entries are evicted lazily on `get()`. Oldest entries are dropped when the map is full.

#### TlsPassthroughCache

**`metadata/TlsPassthroughCache.kt`**

A `HashSet<TlsPassthroughCacheEntry>` guarded by a `ReentrantReadWriteLock`. Each entry is a `(appId: Int, hostname: String)` pair. When a TLS ClientHello is received and the (appId, SNI hostname) pair is present, the `TlsConnection` forwards all data without decryption.

---

### MitM Infrastructure

#### Authority

**`mitm/Authority.kt`**

A plain data class that defines the root CA's identity and file locations:

| Field | Default value |
|---|---|
| `alias` | `"heimdallmitm"` |
| `password` | `"changeit"` |
| `issuerCN / O / OU` | `"Heimdall"` / `"TU Berlin"` / `"SNET"` |
| `subjectCN / O / OU` | `"Heimdall"` / `"HeimdallCert"` / `"HeimdallCertUnit"` |

`Authority.generateCertificate(file)` is the entry point that triggers root CA creation.

#### CertificateHelper

**`mitm/CertificateHelper.kt`**

All cryptographic operations via BouncyCastle:

- **`createRootCertificate(authority)`** — Generates a 2 048-bit RSA key pair, builds an X.509v3 self-signed CA certificate (key usage: `keyCertSign`, `digitalSignature`, `keyEncipherment`; `BasicConstraints: CA:true`), and returns a PKCS12 `KeyStore`.
- **`createServerCertificate(commonName, sans, authority, caCert, caPrivateKey)`** — Generates a 2 048-bit RSA key pair for the impersonated host, issues an X.509v3 certificate signed by the root CA, adds the provided SANs (DNS names and IP addresses), and returns a `KeyStore` containing the leaf cert and the CA cert in the chain.

Certificate validity window: one year back to one year forward for the root CA; one day for leaf certificates.

Signature algorithm: `SHA512WithRSAEncryption` on 64-bit JVMs, `SHA256WithRSAEncryption` on 32-bit.

#### KeyStoreHelper

**`mitm/KeyStoreHelper.kt`**

Manages keystore persistence:

- **`initialiseOrLoadKeyStore(authority)`** — On first run generates the root CA via `CertificateHelper` and saves it as a `.p12` file plus a `.pem` export. On subsequent runs loads from the `.p12` file.
- **`initializeServerCertificates(...)`** — Writes per-host key and certificate chain to individual PEM files.
- **`exportRootCertificate(context, keyStore, authority)`** — Exports the root CA to a `.crt` file in the app's cache directory for manual device installation.
- **`createMagiskModuleWithCertificate(context, keyStore, authority)`** — Packages the root CA into a Magisk module ZIP so it can be installed as a system certificate, avoiding the need for manual user installation on rooted devices.

#### SSLEngineSource

**`mitm/SSLEngineSource.kt`**

Factory for `SSLEngine` instances. Server-specific `SSLContext` objects (one per impersonated hostname) are cached using Guava's `CacheBuilder` with a 5-minute expiry and 16 concurrency segments.

- **`newSSLEngine(remoteHost, remotePort)`** — Client-mode engine for the upstream server connection. Sets SNI via `SSLParameters.serverNames` and enables endpoint algorithm `"HTTPS"` for hostname verification.
- **`createCertForHost(commonName, sans)`** — Checks the Guava cache. On a miss calls `CertificateHelper.createServerCertificate()`, builds a new `SSLContext`, caches it, and returns a server-mode engine for the device-facing half of the MitM.

When `trustAllServers = true`, Netty's `InsecureTrustManagerFactory` is used for the upstream connection (useful for debugging apps that use certificate pinning through alternate means).

#### CertificateSniffingMitmManager

**`mitm/CertificateSniffingMitmManager.kt`**

Top-level coordinator, used as a singleton. Bridges the transport-layer TLS handshake with the certificate infrastructure:

- **`createServerSSLEngine(peerHost, peerPort)`** — Returns a client-mode engine for the upstream TLS handshake.
- **`createClientSSLEngineFor(serverSSLSession)`** — Extracts the upstream server's `X509Certificate`, reads its CN and SANs, and delegates to `SSLEngineSource.createCertForHost()` to obtain a server-mode engine presenting a dynamically generated impersonating certificate.

#### SubjectAlternativeNameHolder

**`mitm/SubjectAlternativeNameHolder.kt`**

Parses the `subjectAlternativeNames` collection from an upstream `X509Certificate` (a `Collection<List<*>>` where each inner list is `[tag: Int, value: String]`) and converts it to a BouncyCastle `GeneralNames` extension that is copied into the generated leaf certificate.

#### MergeTrustManager

**`mitm/MergeTrustManager.kt`**

An `X509TrustManager` that chains Heimdall's own `KeyStore`-based trust manager with the device's default system trust manager. This allows `SSLEngineSource` to accept certificates signed by both the Heimdall CA and standard public CAs when evaluating the upstream server connection.

---

### Database Connector

**`components/DatabaseConnector.kt` / `components/RoomDatabaseConnector.kt`**

`DatabaseConnector` is an interface with `suspend` methods for every persistence operation:

| Method | Persists |
|---|---|
| `persistSession` / `updateSession` | VPN session start/end timestamps |
| `persistTransportLayerConnection` | TCP/UDP connection with app attribution, tracker flag |
| `deleteTransportLayerConnection` | Removes a connection (e.g., DNS) that was created speculatively |
| `persistHttpRequest` | Full HTTP request with headers, body, method, path |
| `persistHttpResponse` | Full HTTP response correlated with a request ID |

`RoomDatabaseConnector` implements this interface using the Room DAOs from `core:database`. All methods run on `Dispatchers.IO`. Failures are logged via Timber and return `-1`.

---

## TLS MitM Deep Dive

`TlsConnection` uses two independent `SSLEngine` instances to perform a transparent intercept:

```
Device ──── clientSSLEngine ──── TlsConnection ──── serverSSLEngine ──── Remote server
           (server mode)                            (client mode)
           fake cert for SNI                        real server cert
```

**State machine:**

```
NEW
 │
 │  ClientHello received from device
 ▼
SERVER_HANDSHAKE   ← serverSSLEngine.beginHandshake() → sends ClientHello to remote server
 │
 │  ServerHello / Certificate / … received from remote server
 ▼
SERVER_ESTABLISHED ← upstream TLS session complete; upstream cert extracted
 │
 │  initiateClientHandshake(): creates fake cert for upstream CN+SANs
 ▼
CLIENT_HANDSHAKE   ← clientSSLEngine.beginHandshake() → sends ServerHello/Cert to device
 │
 │  Device completes handshake
 ▼
CLIENT_ESTABLISHED ← both sessions live; app data can now flow in plaintext
```

**TLS record reassembly:**

TCP is a stream protocol; TLS records can be fragmented across multiple TCP segments and multiple records can be packed into one segment. `TlsConnection` maintains `remainingBytes` and `cache` lists for both directions and reassembles complete records before processing them.

**SNI extraction:**

`findSni(clientHello)` manually parses the TLS ClientHello message to extract the `server_name` extension (type `0x0000`) before any `SSLEngine` state is created. The SNI is used both as the Common Name for the generated leaf certificate and as the key for `TlsPassthroughCache` lookups.

**Buffer management:**

Each `TlsConnection` holds 8 `ByteBuffer` instances—application and network buffers for each direction of each engine. Buffers are grown dynamically when `SSLEngineResult.Status.BUFFER_OVERFLOW` is returned.

---

## Threading Model

| Thread | Type | Blocking primitive |
|---|---|---|
| `DevicePollThread` | Plain `Thread` | `Os.poll()` (native) |
| `DeviceWriteThread` | `HandlerThread` | `MessageQueue.next()` |
| `OutboundTrafficHandler` | `HandlerThread` | `MessageQueue.next()` |
| `InboundTrafficHandler` | Plain `Thread` | `Selector.select()` |

**Synchronisation:**

- `ComponentManager.selectorMonitor`: coarse lock protecting `Selector.select()` / `wakeup()` / key-registration races between `InboundTrafficHandler` and `TransportLayerConnection` constructors.
- `TlsPassthroughCache`: `ReentrantReadWriteLock` for concurrent reads with occasional writes.
- Everything else: the `Handler` message queues provide natural serialisation per connection.

**Coroutines:**

`TlsConnection` launches `Dispatchers.IO` coroutines for the blocking parts of TLS handshakes. `HttpConnection` launches coroutines for database persistence to avoid blocking the handler threads. `ComponentManager` uses `runBlocking` for session persistence during startup/shutdown.

---

## Configuration

All configuration is passed into `ComponentManager` at construction time by `HeimdallVpnService`. There are no runtime-settable properties.

| Parameter | Default | Effect |
|---|---|---|
| `doMitm` | `false` | Enable TLS interception |
| `maxPacketSize` | `16 413` | Read buffer size for TUN interface |
| `keyStoreDir` | app files dir | Where `.p12` / `.pem` / key files are stored |
| `protectSocket` | no-op | Called on each new `Socket` to exclude it from VPN routing |
| `protectDatagramSocket` | no-op | Same for `DatagramSocket` |

**TLS / certificate constants** (in `CertificateHelper`):

| Constant | Value |
|---|---|
| Key size (root CA + leaf) | 2 048 bits RSA |
| Root CA validity | −1 year to +1 year |
| Leaf certificate validity | −1 day to +1 day |
| TLS context protocol | `TLSv1.3` (fallback `TLSv1`) |
| Signature algorithm | `SHA512WithRSAEncryption` (64-bit), `SHA256WithRSAEncryption` (32-bit) |

**DNS cache:** max 1 000 entries, default TTL 60 s.

**Per-host SSL context cache:** max size unbounded; 5-minute write-expiry; 16 concurrency segments.

**HTTP body cap:** 1 048 576 bytes (1 MB). Larger bodies are replaced with `<too large: N bytes>` in the database.

---

## Key Dependencies

| Library | Version | Used for |
|---|---|---|
| **Pcap4j** (`pcap4j-core`, `pcap4j-packetfactory-static`) | 1.7.6 | Parsing raw IP/TCP/UDP/DNS packets; constructing response packets |
| **BouncyCastle** (`bcpkix-jdk15on`) | 1.69 | X.509 certificate generation; PEM serialisation |
| **Guava** | — | `CacheBuilder` for per-host `SSLContext` caching |
| **Netty** (`netty-all`) | 4.1.58 | `InsecureTrustManagerFactory` for upstream trust bypass |
| **Room KTX** | 2.7.1 | Database persistence via `RoomDatabaseConnector` |
| **Lifecycle Runtime KTX** | — | Coroutine scopes in connection classes |
| **Timber** | 4.7.1 | Logging throughout |
| **`core:database`** | internal | Room DAOs and entity types |
| **`core:util`** | internal | `AppFinder` (UID→package), `Trie` (tracker hostname lookup) |
