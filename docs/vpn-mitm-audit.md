# VPN / MitM audit — `core:vpn`

**Date:** 2026-09-28 · **Scope:** `core/vpn` (packet pipeline, transport/encryption/app-layer
connection handling, and the certificate-sniffing MitM engine), plus `app/.../HeimdallVpnService.kt`
and `app/src/main/AndroidManifest.xml` where relevant.

This document is a findings register plus a set of **independently-committable packets**, in the
same format as `docs/database-schema-audit.md`. Each packet stands on its own: it lists what it
resolves, which files it touches, how to verify it, and a suggested commit message. Nothing here
has been implemented — no file under `core/vpn` was changed while producing this audit.

All file:line references were verified against the source at the time of writing (2026-09-28).
Line numbers drift — use the surrounding quoted code to re-locate if they no longer match.

---

## 1. Findings register

Severity: **C** critical (security bypass / connection-breaking data corruption / whole-VPN
crash) · **H** high (leaks, races, protocol-handling gaps with routine, real-world triggers) ·
**M** medium (robustness under edge/adversarial input, narrower triggers) · **L** low (hygiene,
dead code, misleading comments — see the Appendix, not given a full write-up here).

| ID | Sev | Finding |
|---|---|---|
| V-01 | C | Hardcoded `"changeit"` keystore password protects the CA private key, and the app allows backup |
| V-02 | C | `trustAllServers = true` is hardcoded — the proxy never validates the real upstream server's certificate |
| V-03 | C | Certificate serial numbers are generated from a predictable, collision-prone PRNG |
| V-10 | C | No exception isolation around per-packet/per-connection processing — one bad packet can crash the whole VPN |
| V-14 | C | `TcpConnection.wrapInbound()` inflates the sequence number on any split (>~16KB) response |
| V-04 | H | CA cert's real validity is ~1 year despite a "hundred years" comment; never checked or renewed |
| V-05 | H | A keystore reuse check that ignores a missing `.pem` silently regenerates (and invalidates) the CA |
| V-06 | H | `SubjectAlternativeNameHolder` mishandles `byte[]`-valued SAN types from the untrusted upstream cert |
| V-11 | H | `handleUnwrap`'s `BUFFER_UNDERFLOW` retry can recurse unboundedly on the same input |
| V-12 | H | A ClientHello (or other handshake message) split across multiple TLS records kills the connection |
| V-13 | H | Handshake-setup coroutines have no exception handling — a cert-gen failure escapes uncaught |
| V-15 | H | Graceful TCP close sends a self-contradictory RST *and* FIN-ACK to the device |
| V-16 | H | A client-initiated RST is never inspected once a connection exists |
| V-18 | H | `HttpConnection` shares one reassembly state machine between both traffic directions |
| V-21 | H | `SocketChannel` file descriptor leaks on the common remote-initiated-close path |
| V-22 | H | UDP "connections" are never idle-reaped — unbounded growth for the life of a VPN session |
| V-07 | M | Per-host fake-cert cache is keyed only by CN, ignoring the actual SAN set |
| V-08 | M | `getCommonName()` naively substring-scans the untrusted upstream cert's Subject DN |
| V-09 | M | Leaf certs omit `KeyUsage`/`ExtendedKeyUsage`/`AuthorityKeyIdentifier` |
| V-17 | M | No validation of incoming TCP segments against the tracked sequence number |
| V-19 | M | `dechunkHttpMessage` corrupts (persisted-only) bodies whose chunk data contains a literal CRLF |
| V-20 | M | `HttpConnection`'s request/response correlation channel has no key and can leak or mismatch |
| V-23 | M | `TlsPassthroughCache` is an unbounded `HashSet` with no eviction |
| V-24 | M | `ConnectionCache.getKey()`'s bit-packing has overlapping ranges — structurally collision-prone |
| V-25 | M | `TcpConnection`'s sequence numbers and `state` are read/written by two threads with no synchronization |
| V-26 | M | `TlsConnection`'s eight buffers and `state` are mutated from both the I/O thread and untracked coroutines |
| V-29 | M | `detectQuic()`'s bit-math is wrong for real QUIC versions; only versions 0/1 are recognized |
| V-27 | L | `InboundTrafficHandler` leaks a stale selector key on the null-attachment branch |
| V-28 | L | VPN teardown never joins `InboundTrafficHandler` before clearing the connection cache |
| V-30 | L | `detectTls()`'s length guard is one byte stricter than what it actually needs |
| V-31 | L | `AppLayerConnection`'s HTTP-sniff guard is off by one, silently swallowed by a broad catch |

---

### V-01 — Hardcoded keystore password + `allowBackup="true"` (Critical)

```kotlin
// core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/mitm/Authority.kt:52
password = "changeit".toCharArray(),
```
This is the notoriously well-known Java default cacerts password, and it protects the PKCS12
keystore holding the CA's RSA private key (`KeyStoreHelper.kt:54-55`,
`keyStore.store(outputStream, authority.password)`). The same literal is duplicated at
`Authority.kt:73` in `generateCertificate()`. Combined with:
```xml
<!-- app/src/main/AndroidManifest.xml:27 -->
android:allowBackup="true"
```
the keystore file (`context.filesDir/keystore/heimdallmitm.p12`, per
`HeimdallVpnService.kt:226`) is potentially extractable via `adb backup`/Auto Backup on
pre-Android-12 devices or a misconfigured backup agent, and trivially decryptable once
extracted. Whoever holds the private key can forge a certificate for any host that trusts this
CA — a total compromise of the MitM's integrity, not just of this one app's traffic.

**Recommendation:** derive the keystore password from `Android Keystore`-protected random
material generated on first run (or, at minimum, a per-install random password stored via
`EncryptedSharedPreferences`), and set `android:allowBackup="false"` for the keystore
directory at least (a `fullBackupContent` exclusion rule, or `allowBackup="false"` app-wide if
nothing else needs backup).

### V-02 — Upstream server certificates are never validated (Critical)

```kotlin
// core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/mitm/CertificateSniffingMitmManager.kt:17
SSLEngineSource(authority, trustAllServers = true, sendCerts = true)
```
which drives `SSLEngineSource.initialiseSSLContext()` to select an insecure trust manager:
```kotlin
// SSLEngineSource.kt:139-146
val trustManagers: Array<TrustManager> = if (trustAllServers) {
    InsecureTrustManagerFactory.INSTANCE.trustManagers
} else {
    arrayOf(MergeTrustManager(ks))
}
```
`trustAllServers` is a constructor parameter but is never actually wired to anything
configurable — `CertificateSniffingMitmManager` is the only caller and always passes `true`. The
proxy's connection to the *real* remote server therefore accepts any certificate: no chain
validation, no expiry check, no hostname check. A network-level attacker between the phone and
the real server is invisible to Heimdall and to the user, who still sees a "valid" TLS session
because the *locally* generated leaf cert (signed by the trusted Heimdall CA) checks out on the
client side. `MergeTrustManager.kt` already implements the correct merge-trust-store behavior
but is unreachable dead code.

**Recommendation:** make `trustAllServers` a real (default-`false`) toggle wired through to a
user-facing "Trust all upstream certificates" setting, defaulting to strict validation via
`MergeTrustManager`.

### V-03 — Predictable, collision-prone certificate serial numbers (Critical)

```kotlin
// core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/mitm/CertificateHelper.kt:315-324
private fun initRandomSerial(): Long {
    val rnd = Random()
    rnd.setSeed(System.currentTimeMillis())
    // prevent browser certificate caches, cause of doubled serial numbers
    // using 48bit random number
    var sl = rnd.nextInt().toLong() shl 32 or (rnd.nextInt().toLong() and 0xFFFFFFFFL)
    // let reserve of 16 bit for increasing, serials have to be positive
    sl = sl and 0x0000FFFFFFFFFFFFL
    return sl
}
```
`java.util.Random()`'s no-arg constructor already seeds itself uniquely, but the very next line
overwrites that with `setSeed(System.currentTimeMillis())` — a guessable, millisecond-granularity
seed feeding a well-known LCG. Used for both the root CA (`CertificateHelper.kt:112`) and every
leaf cert (`:181`). Two certs generated within the same millisecond — plausible when several
HTTPS connections open concurrently, which is routine — get an **identical serial number**,
directly contradicting the comment's own stated goal.

**Recommendation:** drop the `setSeed()` call (or seed from `SecureRandom` instead), and/or use
`SecureRandom.getInstanceStrong()` /`BigInteger(128, SecureRandom())`-style generation instead of
`java.util.Random`.

### V-10 — No exception isolation around per-packet processing (Critical)

The two threads that process every connection's traffic call straight into per-connection code
with no guard:
```kotlin
// core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/components/InboundTrafficHandler.kt:30-49
synchronized(ComponentManager.selectorMonitor) {
    if (selectedChannels > 0) {
        val iterator = componentManager.selector.selectedKeys().iterator()
        while (iterator.hasNext()) {
            val key = iterator.next()
            val attachment = key.attachment()
            if (attachment == null) { ... continue }
            if (attachment is TransportLayerConnection) {
                attachment.unwrapInbound()   // <-- unguarded
            } else { ... }
            iterator.remove()
        }
    }
}
```
```kotlin
// core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/components/OutboundTrafficHandler.kt:41-46
private fun handleMessageImpl(msg: Message) {
    if((msg.what == 6 || msg.what == 17) && msg.obj is IpPacket) {
        val ipPacket = msg.obj as IpPacket
        TransportLayerConnection.getInstance(ipPacket, componentManager, deviceWriter)?.unwrapOutbound(ipPacket.payload)  // <-- unguarded
    }
}
```
and `DevicePollThread.poll()` calls `parsePacket(rawPacket)` (`DevicePollThread.kt:99`) with no
try/catch around the pcap4j parse calls it makes (`IpV4Packet.newPacket`/`IpV6Packet.newPacket`,
`:156,158`). `unwrapInbound()`/`unwrapOutbound()` descend through the transport, encryption, and
app layers for **one connection**, but `InboundTrafficHandler` and `OutboundTrafficHandler` are
singleton threads shared by **every** connection. Confirmed concrete triggers that reach this
unguarded call chain:
- a cert-generation exception during a TLS handshake (V-13) — no try/catch anywhere between it
  and this call site;
- unbounded recursion / `OutOfMemoryError` from V-11;
- a malformed raw packet that passes `parsePacket`'s manual length/version checks but still
  throws inside pcap4j.

Any one of these permanently kills the thread that services every other connection — and on
Android, an uncaught exception on any thread crashes the process by default unless a custom
`UncaughtExceptionHandler` is installed (none is). This is the highest-blast-radius issue in the
whole audit: **one bad packet from one app can take down the entire VPN, or the app itself.**

**Recommendation:** wrap each per-connection dispatch (`attachment.unwrapInbound()`,
`unwrapOutbound(...)`, and the packet-parsing call in `DevicePollThread`) in a
`try { ... } catch (e: Throwable) { Timber.e(e, ...); <tear down just this connection> }` so a
single connection's failure can't take the shared thread down with it.

### V-14 — TCP sequence number corruption on split inbound payloads (Critical)

```kotlin
// core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/connection/transportLayer/TcpConnection.kt:231-244
val largeBuffer = ByteBuffer.wrap(payload)
while(largeBuffer.hasRemaining()) {
    val temp = ByteArray(minOf(largeBuffer.limit() - largeBuffer.position(), componentManager.maxPacketSize))
    largeBuffer.get(temp)
    Timber.d("tcp$id Writing split payload (${temp.size} bytes, ${largeBuffer.limit() - largeBuffer.position()} remaining)")
    val ackDataPacket = ipPacketBuilder.buildPacket(buildDataAck(temp))
    increaseOurSeqNum(payload.size)   // BUG: should be temp.size
    writeToDevice(ackDataPacket)
}
```
`increaseOurSeqNum` is called with the size of the **entire original payload**, not the segment
(`temp`) just written, on every loop iteration. For N segments this inflates `ourSeqNum` by
`(N-1) * payload.size` bytes beyond what was actually sent to the device. `maxPacketSize`
defaults to 16413 bytes (`ComponentManager.kt:50`), so this fires on any MitM'd response body
over ~16KB — routine for HTTPS. Every subsequent packet on the connection (further data, ACKs,
FIN) carries a sequence number that doesn't match what the device's TCP stack actually received,
desyncing and typically stalling or resetting the stream.

**Recommendation:** `increaseOurSeqNum(temp.size)`.

### V-04 — CA cert validity is ~1 year, not "hundred years"; never checked (High)

```kotlin
// core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/mitm/CertificateHelper.kt:65-72
/**
 * The maximum possible value in X.509 specification: 9999-12-31 23:59:59,
 * new Date(253402300799000L), but Apple iOS 8 fails with a certificate
 * expiration date grater than Mon, 24 Jan 6084 02:07:59 GMT (issue #6).
 *
 * Hundred years in the future from starting the proxy should be enough.
 */
private val NOT_AFTER = Date(System.currentTimeMillis() + ONE_DAY * 365)
```
`ONE_DAY * 365` is one year, not the "hundred years" the comment claims (would need
`* 365 * 100`). This is what's used for the root CA in `createRootCertificate`
(`CertificateHelper.kt:118-119`). Compounding it, keystore reuse only checks file
*existence*, never validity:
```kotlin
// KeyStoreHelper.kt:38
return if (authority.aliasFile(KEY_STORE_FILE_EXTENSION).exists() && authority.aliasFile(".pem").exists()) {
```
Once the CA cert actually expires roughly a year after first install (assuming the user never
deletes the keystore), MITM starts silently failing every TLS handshake, with no diagnostic
anywhere in this path.

**Recommendation:** fix the arithmetic (`ONE_DAY * 365 * 100` if a long-lived CA is really
wanted, or a deliberately shorter/rotatable lifetime), and have `initialiseOrLoadKeyStore` check
`x509Cert.checkValidity()` before deciding to reuse an existing keystore, regenerating (and
prompting the user to reinstall the CA) on expiry.

### V-05 — Missing `.pem` alone silently forces CA regeneration (High)

```kotlin
// KeyStoreHelper.kt:33-64
return if (authority.aliasFile(KEY_STORE_FILE_EXTENSION).exists() && authority.aliasFile(".pem").exists()) {
    // reuse existing keystore
    ...
} else {
    // create a brand-new CA key + cert, overwriting the .p12
    val keyStore = CertificateHelper.createRootCertificate(authority, KEY_STORE_TYPE)
    ...
}
```
Reuse requires **both** the authoritative `.p12` keystore and the derived `.pem` export to
exist. If only the `.pem` goes missing (storage cleanup, partial write, manual deletion) while
the `.p12` — and its key material — is intact, the `else` branch generates a **brand-new CA key
and certificate**, overwriting the still-good `.p12`. Any CA cert the user had already installed
into the system/user trust store or a Magisk module becomes untrusted, silently breaking every
MITM'd connection until the new cert is reinstalled — with no code path that instead just
re-exports the missing `.pem` from the still-valid `.p12`.

**Recommendation:** check the `.p12` alone for reuse; if it exists but the `.pem` doesn't,
re-export the `.pem` from the loaded keystore instead of regenerating the CA.

### V-06 — `SubjectAlternativeNameHolder` mishandles non-`String` SAN values (High)

```kotlin
// core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/mitm/SubjectAlternativeNameHolder.kt:36-60
fun addAll(subjectAlternativeNames: Collection<List<*>>?) {
    if (subjectAlternativeNames != null) {
        for (each in subjectAlternativeNames) {
            if (isValidNameEntry(each)) {
                val tag = each[0].toString().toInt()
                val name = each[1].toString()
                sans.add(GeneralName(tag, name))
            } else {
                Timber.w("Invalid name entry ignored: %s", each)
            }
        }
    }
}

private fun isValidNameEntry(nameEntry: List<*>?): Boolean {
    if (nameEntry == null || nameEntry.size != 2) return false
    val tag = nameEntry[0].toString()
    return Pattern.compile("[012345678]").matcher(tag).matches()
}
```
Called directly with the real, **untrusted** remote server's certificate data:
```kotlin
// CertificateSniffingMitmManager.kt:56-57
val san = SubjectAlternativeNameHolder()
san.addAll(upstreamCert.subjectAlternativeNames)
```
Per the JDK contract for `X509Certificate.getSubjectAlternativeNames()`, GeneralName types 0
(`otherName`), 3 (`x400Address`), 5 (`ediPartyName`), and 8 (`registeredID`) are returned as a
raw `byte[]`, not a `String`. `isValidNameEntry`'s regex accepts all of these tags, and
`each[1].toString()` on a `byte[]` yields garbage like `[B@1a2b3c4d`, fed straight into
`GeneralName(tag, name)`. A remote server whose certificate contains any of these SAN types
deterministically breaks fake-cert generation for that host (typically an exception inside
BouncyCastle's ASN.1 encoder) — which, per V-10/V-13, is currently an unguarded crash path, not
just a failed connection. Untested: `SubjectAlternativeNameHolderTest` only exercises
String-typed SAN tags (dNSName/iPAddress).

**Recommendation:** in `isValidNameEntry`, restrict accepted tags to the `String`-valued ones
Heimdall actually needs (dNSName=2, iPAddress=7, rfc822Name=1, uniformResourceIdentifier=6), and
log-and-skip the rest instead of forwarding raw `byte[]` data through `.toString()`.

### V-11 — Unbounded `BUFFER_UNDERFLOW` retry recursion (High)

```kotlin
// core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/connection/encryptionLayer/TlsConnection.kt:731-740
SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
    Timber.w("tls$id handleUnwrap ($direction) buffer underflow, increasing netBuffer capacity and retrying")
    if(isOutbound) {
        clientNetBufferUnwrap = ByteBuffer.allocate(clientNetBufferUnwrap.capacity() + record.size)
    } else {
        serverNetBufferUnwrap = ByteBuffer.allocate(serverNetBufferUnwrap.capacity() + record.size)
    }
    return handleUnwrap(record, isOutbound, resizeFactor)
}
```
Per the JSSE contract, `unwrap()`'s `BUFFER_UNDERFLOW` means the engine doesn't have enough
*source* bytes to make progress — it is not, in general, fixed by growing the destination
buffer while re-feeding the exact same `record` bytes. This genuinely happens when a handshake
message needs data from a TLS record that hasn't arrived yet (see V-12). Because `record` never
changes across retries, if that's the actual cause, this recurses forever: each call reallocates
an even larger `ByteBuffer` and recurses again, with no maximum retry count or size cap — risking
unbounded allocation (`OutOfMemoryError`) or a `StackOverflowError`, both uncaught here and
feeding directly into V-10's crash path. (The symmetric branch in `handleWrap`,
`TlsConnection.kt:614-622`, has the same shape, though `wrap()` is not documented to return
`BUFFER_UNDERFLOW` in normal operation — it's defensive code that would have the identical bug
if ever triggered.)

**Recommendation:** cap the retry count (or total buffer growth) and call `closeConnection()`
once exceeded, rather than recursing indefinitely.

### V-12 — A handshake message split across multiple TLS records breaks the connection (High)

`prepareRecords` (`TlsConnection.kt:825-946`) correctly reassembles a single **TLS record**
fragmented across multiple transport-layer payloads (the `remainingBytes`/`cache` logic,
`:833-873`). It does **not** reassemble a single **handshake message** that itself spans more
than one TLS record — legal per RFC 8446 §5.1 and used by real clients whenever a ClientHello
(or 0-RTT early-data flight sent right after it) exceeds the 16KB record-size limit, e.g. very
large ClientHellos with many extensions/session tickets/hybrid PQC key shares, or a TLS 1.3
client sending 0-RTT application data immediately.

Concretely: record #1 (recognized as `HANDSHAKE_CLIENT_HELLO` via `payload[5] == 0x01`) reaches
`handleOutboundRecord` while `state == NEW`, which calls `initiateServerHandshake(record)`
(`:299-310`) — this stores the **incomplete** message as `originalClientHello` and asynchronously
kicks off `setupServerSSLEngine()`, transitioning state to `SERVER_HANDSHAKE`. Record #2 (the
continuation, or 0-RTT data) then arrives as a **separate** outbound record while state is `NEW`
or `SERVER_HANDSHAKE`/`SERVER_ESTABLISHED` — and those states only accept a fresh
`HANDSHAKE_CLIENT_HELLO` (in `NEW`) or reject everything else outright:
```kotlin
// TlsConnection.kt:182-186
ConnectionState.SERVER_HANDSHAKE, ConnectionState.SERVER_ESTABLISHED -> {
    Timber.e("tls$id handleOutboundRecord Invalid outbound record ($recordType in state $state)")
    Timber.e("tls$id ${ByteUtils.bytesToHex(record)}")
    closeConnection()
}
```
The connection is force-closed. (Note: this is specific to **outbound** records arriving before
the client-facing handshake state can accept arbitrary continuation data via `continueHandshake`.
The *inbound* side handles multi-record handshake messages correctly during `SERVER_HANDSHAKE` —
any inbound record in that state is fed straight to `continueHandshake`/`handleUnwrap`, and
`SSLEngine.unwrap()` is designed to buffer partial handshake messages internally across
record-by-record calls.)

**Recommendation:** either buffer outbound records that arrive in `NEW`/`SERVER_HANDSHAKE` after
the first ClientHello record and feed them to the server-facing engine once it's ready (treating
them the way `continueHandshake` already treats inbound continuation records), or explicitly
detect and reassemble multi-record ClientHellos before calling `initiateServerHandshake`.

### V-13 — Handshake-setup coroutines have no exception handling (High)

```kotlin
// TlsConnection.kt:306-309
CoroutineScope(Dispatchers.IO).launch {
    setupServerSSLEngine()
    continueHandshake(handshakeStatus = SSLEngineResult.HandshakeStatus.NEED_WRAP, isClientFacing = false)
}
```
```kotlin
// TlsConnection.kt:320-323
CoroutineScope(Dispatchers.IO).launch {
    setupClientSSLEngine()
    continueHandshake(originalClientHello, RecordType.HANDSHAKE_CLIENT_HELLO, true, SSLEngineResult.HandshakeStatus.NEED_UNWRAP)
}
```
Neither coroutine body has a try/catch. `setupClientSSLEngine()` calls
`componentManager.mitmManager.createClientSSLEngineFor(...)`
(`CertificateSniffingMitmManager.kt:46-67`), which throws `FakeCertificateException` on any
cert-generation failure — including V-06's SAN bug, disk I/O errors, or a cache-wrapped
`ExecutionException` from `SSLEngineSource.createCertForHost`. An uncaught exception here
propagates via the coroutine's default (uncaught) exception handling, landing in the same
process-crash risk described in V-10. If it somehow doesn't crash the process, the connection is
left permanently stuck — it never reaches `switchState(...)` or `closeConnection()`, so it's a
silent leak on top of the crash risk. (By contrast, the `NEED_TASK` coroutine
(`TlsConnection.kt:406-418`) *does* wrap its work in try/catch and calls `closeConnection()` on
failure — this specific gap is limited to the two handshake-initiation coroutines above.)

**Recommendation:** wrap both coroutine bodies in try/catch, calling `closeConnection()` (and
logging) on failure, matching the pattern already used in the `NEED_TASK` branch.

### V-15 — Graceful close sends a contradictory RST + FIN-ACK (High)

```kotlin
// core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/connection/transportLayer/TransportLayerConnection.kt:216-227
fun closeSoft() {
    ...
    state = TransportLayerState.CLOSING
    try {
        selectionKey?.cancel()
        selectableChannel.close()
    } catch (e: Exception) { ... }
    closeClientSession()
    state = TransportLayerState.CLOSED
}
```
```kotlin
// TcpConnection.kt:398-402
override fun closeClientSession() {
    state = TransportLayerState.ABORTED
    val rstResponse = ipPacketBuilder.buildPacket(buildRst())
    writeToDevice(rstResponse)
}
```
`closeSoft()` unconditionally calls `closeClientSession()`, which sends an RST — but `closeSoft()`
is also what the **graceful**, app-initiated close path calls:
```kotlin
// TcpConnection.kt:306-318
private fun handleFin() {
    if (state == TransportLayerState.CLOSED || state == TransportLayerState.ABORTED) {
        closeHard()
    } else {
        closeSoft()                                            // sends an RST (above)
        increaseTheirSeqNum(1)
        val finAckResponse = ipPacketBuilder.buildPacket(buildFinAck())
        increaseOurSeqNum(1)
        writeToDevice(finAckResponse)                          // ...then also sends a FIN-ACK
    }
}
```
Every normal app-initiated TCP close results in the device receiving an RST *and* a FIN-ACK for
the same connection — self-contradictory, and liable to confuse the device's own TCP stack
(varies by implementation, but RST is meant to signal an abrupt abort, not follow a clean
FIN-ACK for the same segment).

**Recommendation:** give `closeSoft()` a mode (or have `handleFin()` skip straight to sending
just the FIN-ACK) so the RST-sending `closeClientSession()` path is reserved for genuine aborts,
not the graceful close handshake.

### V-16 — Client-initiated RST is never handled (High)

```kotlin
// TcpConnection.kt:137-156
override fun unwrapOutbound(outgoingPacket: Packet) {
    if(state == TransportLayerState.ABORTED) return
    val tcpHeader = outgoingPacket.header as TcpPacket.TcpHeader
    if (tcpHeader.ack) { ... }
    else if (tcpHeader.fin) { handleFin() }
}
```
`tcpHeader.rst` is checked only in `TransportLayerConnection.getInstance()` to drop *unsolicited*
RSTs before a connection exists — once a connection is registered, an RST sent by the app is
silently ignored; no branch handles it. The proxy keeps the remote socket open and the
connection stays in `ConnectionCache` indefinitely, still relaying traffic the client has
already abandoned.

**Recommendation:** add an `else if (tcpHeader.rst)` branch calling `closeHard()`.

### V-18 — `HttpConnection` shares reassembly state across both directions (High)

```kotlin
// core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/connection/appLayer/HttpConnection.kt:25-35
private var previousPayload: ByteArray = ByteArray(0)
private val chunkCache = mutableListOf<ByteArray>()
private var overflowing = false
private var chunked = false
private var statedContentLength = -1
private var remainingContentLength = -1
```
```kotlin
// HttpConnection.kt:50-62
override fun unwrapOutbound(payload: ByteArray) {
    handleData(payload, true)
    encryptionLayer.wrapOutbound(payload)
}
override fun unwrapInbound(payload: ByteArray) {
    handleData(payload, false)
    encryptionLayer.wrapInbound(payload)
}
```
These fields are single instance state, not tracked per-direction, but `handleData` (`:64-156`)
is called for both. HTTP/1.1 keep-alive is full-duplex: it's routine for the client to start
request N+1 while the response to request N is still streaming in, or simply for a large
request body and an in-flight response to interleave in read order on the same connection.
Because both directions drive the same `chunkCache`/`overflowing`/`remainingContentLength`
fields, an inbound response chunk arriving while an outbound request is mid-reassembly (or vice
versa) gets appended to the wrong `chunkCache` (`:126,133`), decrements
`remainingContentLength` against bytes from the other direction (`:138`), and is ultimately
persisted via `persistMessage(...)` with a garbled, cross-direction byte stream — under a common
condition, not an edge case.

**Recommendation:** duplicate the six reassembly fields (or wrap them in a small per-direction
state holder) so `handleData` tracks outbound and inbound reassembly independently.

### V-21 — `SocketChannel` leaks on the common remote-initiated-close path (High)

```kotlin
// TcpConnection.kt:347-362
recordBytesIn(totalBytesRead)

// SocketChannel is closed
if (bytesRead == -1) {
    selectionKey?.cancel()
    if (state == TransportLayerState.CLOSING) {
        state = TransportLayerState.CLOSED
        ConnectionCache.removeConnection(this)
    } else {
        Timber.d("tcp$id SocketChannel closed, state transition $state -> CLOSING")
        state = TransportLayerState.CLOSING
        val finPacket = ipPacketBuilder.buildPacket(buildFin())
        increaseOurSeqNum(1)
        writeToDevice(finPacket)
    }
}
```
and the matching state transition in `handleAckEmpty()`:
```kotlin
// TcpConnection.kt:275-279
TransportLayerState.CLOSING -> {
    state = TransportLayerState.CLOSED
    ConnectionCache.removeConnection(this)
}
```
Neither branch calls `selectableChannel.close()` — only `selectionKey?.cancel()`, which
deregisters the channel from the selector without closing the underlying socket/fd. The only
code path that actually closes the channel is `closeSoft()`/`closeHard()`, reached from the
app-initiated `handleFin()` — not from this remote-EOF path. Since a remote-initiated close
(server hangs up first — HTTP keep-alive timeouts, `Connection: close`, etc.) is the majority
real-world case, this leaks one `SocketChannel`/fd per such connection until GC finalization
eventually runs (not timely on ART). Over a long VPN session this risks exhausting the process's
fd limit.

**Recommendation:** call `selectableChannel.close()` in both branches above (or route through
`closeSoft()`) before/alongside cancelling the `SelectionKey`.

### V-22 — No idle-reaping for UDP connections (High)

`UdpConnection` is only ever removed from `ConnectionCache` in two cases: the DNS special-case
(port 53, closes after the first reply — `UdpConnection.kt:207-215`) or when
`selectableChannel.read()` returns `-1` (`:218-221`), which for a connected `DatagramChannel`
rarely happens in practice. There is no idle timer and nothing in `ComponentManager` sweeps
`ConnectionCache` for stale UDP entries. Every other UDP 4-tuple — QUIC/HTTP3 on 443, WebRTC,
mDNS, games — stays registered on the selector and resident in the cache, each holding its own
`DatagramChannel` fd plus two `ByteBuffer`s sized to `maxPacketSize` (16413 bytes default,
~32KB/connection), until `ComponentManager.stopComponents()` tears down the whole VPN session.
Unbounded growth for any long-running session.

**Recommendation:** track a last-activity timestamp per `UdpConnection` and add a periodic sweep
(e.g. in `ComponentManager`, on a lightweight scheduled coroutine) that calls `closeHard()` on
entries idle past a threshold (a few minutes is typical for NAT/UDP session timeouts elsewhere).

---

## Medium-severity findings (V-07/08/09/17/19/20/23/24/25/26/29)

Each gets a short writeup — full code was verified for all of them during this audit, but they're
kept terse here since their packets (below) carry the fix detail.

- **V-07** — `SSLEngineSource.createCertForHost` caches fake certs by CN alone
  (`SSLEngineSource.kt:181-195`, Guava `Cache<String?, SSLContext>`). Two upstream certs sharing
  a CN but differing in SANs (shared hosting/CDN, or a mid-session cert rotation) mean whichever
  request populates the cache first wins for the 5-minute TTL window; later requests silently get
  the wrong SAN set.
- **V-08** — `getCommonName()` (`CertificateSniffingMitmManager.kt:82-93`) manually
  `indexOf("CN=")`/`indexOf(",")`-scans `X509Certificate.subjectDN.name` (deprecated API) on the
  **untrusted** upstream cert, fragile against RDN ordering or a comma-containing quoted value.
- **V-09** — Leaf certs (`CertificateHelper.createServerCertificate`, `:199-207`) add
  `subjectKeyIdentifier` and `basicConstraints(false)` but no `KeyUsage`, `ExtendedKeyUsage`
  (id_kp_serverAuth), or `AuthorityKeyIdentifier` — a deviation from RFC 5280/CA-Browser-Forum
  baseline expectations that stricter TLS validators could reject.
- **V-17** — Nowhere in `TcpConnection.kt` is an incoming segment's actual
  `tcpHeader.sequenceNumberAsLong` compared against the locally tracked `theirSeqNum`.
  `handleAckData`/`handleAckEmpty`/etc. blindly trust in-order, non-duplicated delivery and
  increment counters by payload length without validation — a retransmitted or duplicate segment
  is re-forwarded upstream as if new.
- **V-19** — `dechunkHttpMessage` (`HttpConnection.kt:277-321`) splits the *entire* chunked body
  on every literal `"\r\n"` and walks `chunks[i]`/`chunks[i+1]` as alternating size/data pairs.
  Any chunk whose data itself contains a CRLF (routine for multi-line text/JSON/HTML bodies)
  desyncs the pairing from that point on. Only the *persisted/logged* reconstruction is affected —
  `unwrapInbound`/`unwrapOutbound` always forward the original raw bytes unmodified to the
  transport layer regardless of parsing success.
- **V-20** — `HttpConnection.requestIdChannel` (`:42`, `Channel<Long>()`, rendezvous, capacity 0)
  is used from independently-launched `CoroutineScope(Dispatchers.IO).launch` blocks per message
  (`:170-211`) with no correlation key. Under pipelining, concurrent sends/receives have no
  ordering guarantee relative to each other and can pair a response with the wrong request; if a
  request's coroutine calls `send()` and the connection is torn down before any response arrives,
  that `send()` suspends forever — a permanent coroutine leak (nothing ever calls
  `requestIdChannel.close()` or cancels it).
- **V-23** — `TlsPassthroughCache` (`core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/metadata/TlsPassthroughCache.kt:14`)
  is a plain `HashSet<TlsPassthroughCacheEntry>` with no size cap or expiry — every distinct
  `(uid, hostname)` pair accumulates for the process's lifetime. `DnsCache` right next to it
  (`metadata/DnsCache.kt:20-24`) is correctly bounded (size + TTL via `LinkedHashMap`'s
  `removeEldestEntry`) — the gap is specific to `TlsPassthroughCache`.
- **V-24** — `ConnectionCache.getKey()` (`core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/cache/ConnectionCache.kt:78-85`):
  `remoteAddress.hashCode() xor (protocol shl 16) xor (localPort shl 8) xor remotePort` — the bit
  range `localPort shl 8` (bits 8-23) overlaps `remotePort` (bits 0-15) in bits 8-15, so this is
  structurally collision-prone, not just low-probability (e.g. `localPort=1, remotePort=0` and
  `localPort=0, remotePort=256` collide for any fixed address/protocol). A collision silently
  overwrites a live entry (`addConnection`, `:26-34`, logs `"Flow overwritten"` and replaces it) —
  the overwritten connection is orphaned: still open/registered, never reachable via the cache
  again. (`ConnectionCache` itself is a proper `ConcurrentHashMap` — no separate thread-safety
  issue here, only the key-collision one.)
- **V-25** — `TcpConnection`'s `ourSeqNum`/`theirSeqNum` (`:52-53`) and the inherited `state`
  (`TransportLayerConnection.kt:106`) are plain, non-`volatile`, non-atomic fields read and
  mutated by `unwrapOutbound()` (called from `OutboundTrafficHandler`'s `HandlerThread`) and
  `unwrapInbound()` (called from `InboundTrafficHandler`'s selector thread) concurrently, for
  bidirectional traffic on the same connection. No `synchronized`/`volatile`/atomic protection
  anywhere — compounds V-14's effects with lost updates, and risks stale-visibility bugs on
  check-then-act reads of `state` (e.g. `handleAckData`'s `if (state != CONNECTED)`).
- **V-26** — Same class of race in `TlsConnection`: `state`, the eight `ByteBuffer` fields
  (`:52-59`), and the reassembly caches (`:40-47`) are mutated both synchronously from whichever
  thread calls `unwrapOutbound`/`unwrapInbound`/`wrapOutbound`/`wrapInbound`, and asynchronously
  from the `Dispatchers.IO` coroutines in `initiateServerHandshake`/`initiateClientHandshake`/
  `NEED_TASK` (V-13's coroutines), which themselves call back into `handleWrap`/`handleUnwrap`
  mutating the same buffers. `ByteBuffer` is explicitly not thread-safe; there's no dispatcher
  confinement or lock ensuring these two call paths never interleave for the same connection.
- **V-29** — `EncryptionLayerConnection.detectQuic()` (`:148-163`):
  ```kotlin
  val version = rawPayload[1].toUByte().toInt() shl 24 or
          rawPayload[2].toUByte().toInt() shl 16 or
          rawPayload[3].toUByte().toInt() shl 8 or
          rawPayload[4].toUByte().toInt()
  ```
  Kotlin's named infix functions (`shl`, `or`) share one precedence level and evaluate strictly
  left-to-right — there is no "`shl` binds tighter than `or`" the way `<<`/`|` behave in
  Java/C. This evaluates as `((((b1 shl 24) or b2) shl 16) or b3) shl 8) or b4`, not the intended
  OR-of-four-shifted-bytes. For the only two values actually checked (QUIC version `0`/`1`, where
  bytes 1-3 are zero) it happens to still compute correctly — but is objectively wrong for any
  other version (QUIC v2 `0x6b3343cf`, IETF draft versions like `0xff00001d`), and only versions
  `0`/`1` are recognized at all, so real-world QUIC traffic falls through to `PlaintextConnection`
  mislabeling regardless.

---

## 2. Packets

### PKT-01 — Fix the TCP split-payload sequence number bug

- **Priority:** Critical (trivial) · **Depends on:** —
- **Resolves:** V-14
- **Approach:** `increaseOurSeqNum(temp.size)` instead of `increaseOurSeqNum(payload.size)` in
  `TcpConnection.wrapInbound()`'s split-payload loop.
- **Files:** `core/vpn/.../connection/transportLayer/TcpConnection.kt`.
- **Tests:** add a case to `core/vpn/src/test/java/de/tomcory/heimdall/core/vpn/connection/encryptionLayer/TlsRecordHandlingTest.kt` or a new transport-layer test driving `wrapInbound()` with a payload larger than `maxPacketSize` and asserting the built packets' sequence numbers increase by each segment's actual size, summing to the total payload size.
- **Commit:** `fix(vpn): stop inflating TCP sequence numbers on split inbound payloads`

### PKT-02 — Separate graceful close from hard abort; handle client RST

- **Priority:** Critical · **Depends on:** —
- **Resolves:** V-15, V-16
- **Approach:** give `TransportLayerConnection.closeSoft()` a parameter (or split into
  `closeGraceful()`/`closeAbort()`) so `handleFin()`'s app-initiated close path doesn't also send
  an RST via `closeClientSession()`; reserve the RST path for genuine aborts (`closeHard()` from
  error conditions). Add an `else if (tcpHeader.rst) { closeHard() }` branch to
  `TcpConnection.unwrapOutbound()`.
- **Files:** `TransportLayerConnection.kt`, `TcpConnection.kt`.
- **Tests:** extend `core/vpn/src/test/java/de/tomcory/heimdall/core/vpn/integration/ConnectionTeardownTest.kt` with cases for (a) app-initiated FIN close asserting only a FIN-ACK is written to the device, not an RST, and (b) an app-sent RST asserting the connection is removed from `ConnectionCache` and the remote channel is closed.
- **Commit:** `fix(vpn): stop sending a contradictory RST on graceful TCP close; handle client RST`

### PKT-03 — Exception isolation around per-packet/per-connection processing

- **Priority:** Critical · **Depends on:** —
- **Resolves:** V-10 (and removes the crash escalation path for V-06, V-11, V-13)
- **Approach:** wrap `attachment.unwrapInbound()` in `InboundTrafficHandler.run()`, the
  `unwrapOutbound(...)` call in `OutboundTrafficHandler.handleMessageImpl()`, and the
  `parsePacket(rawPacket)` call in `DevicePollThread.poll()` each in a
  `try { ... } catch (e: Throwable) { Timber.e(e, "..."); <best-effort teardown of just this connection> }`.
  For the two traffic handlers, a caught exception should trigger `closeHard()` on the specific
  connection where possible, not just be logged and dropped.
- **Files:** `components/InboundTrafficHandler.kt`, `components/OutboundTrafficHandler.kt`,
  `components/DevicePollThread.kt`.
- **Tests:** extend `core/vpn/src/test/java/de/tomcory/heimdall/core/vpn/integration/MalformedInputRobustnessTest.kt` with a case that forces an exception inside one connection's `unwrapInbound()`/`unwrapOutbound()` (e.g. a connection whose encryption-layer mock throws) and asserts a second, unrelated connection on the same handler threads keeps working afterward — today nothing in this suite exercises the "does one bad connection take down the shared thread" scenario specifically.
- **Commit:** `fix(vpn): isolate per-connection exceptions so one bad packet can't kill the VPN`

### PKT-04 — Guard TLS handshake-setup coroutines and cap `BUFFER_UNDERFLOW` retries

- **Priority:** High · **Depends on:** PKT-03 (belt-and-suspenders; this fixes the two specific
  known trigger points it would otherwise catch)
- **Resolves:** V-11, V-13
- **Approach:** wrap the bodies of `initiateServerHandshake`'s and `initiateClientHandshake`'s
  `CoroutineScope(Dispatchers.IO).launch { ... }` blocks in try/catch, calling
  `closeConnection()` on failure — mirroring the existing `NEED_TASK` branch's pattern
  (`TlsConnection.kt:406-418`). Add a retry counter/cap to both `handleWrap`'s and
  `handleUnwrap`'s `BUFFER_UNDERFLOW` branches (e.g. bail to `closeConnection()` after N retries
  or once buffer size exceeds a sane ceiling).
- **Files:** `connection/encryptionLayer/TlsConnection.kt`.
- **Tests:** `core/vpn/src/test/java/de/tomcory/heimdall/core/vpn/connection/encryptionLayer/TlsRecordHandlingTest.kt` — add a case feeding `handleUnwrap` a scenario that would recurse under the old code (same record repeatedly under-full) and assert it terminates via `closeConnection()` rather than growing without bound; add a case where `setupClientSSLEngine()`/`setupServerSSLEngine()` is made to throw and assert the connection is torn down rather than left stuck.
- **Commit:** `fix(vpn): bound TLS buffer-underflow retries and guard handshake-setup coroutines`

### PKT-05 — Reassemble (or accept) multi-record handshake messages on the outbound path

- **Priority:** High · **Depends on:** PKT-04 · **Open design question — read before starting**
- **Resolves:** V-12
- **Approach, option A (buffer and defer):** when an outbound record arrives while
  `state == NEW` and it isn't a `HANDSHAKE_CLIENT_HELLO`, or while
  `state == SERVER_HANDSHAKE`/`SERVER_ESTABLISHED`, buffer it (similar to `outboundCache`) instead
  of closing the connection, and replay the buffered records into `continueHandshake` once the
  server-facing engine is ready.
- **Approach, option B (detect and combine before dispatch):** in `prepareRecords`, detect when a
  handshake record's declared *handshake* length (bytes 1-3 of the handshake message inside the
  record, once past the 5-byte TLS record header) exceeds what a single TLS record can carry, and
  hold subsequent handshake-type records for combination before calling `handleOutboundRecord`.
- Recommend option A — it reuses the state machine's existing "not ready yet" handling instead of
  teaching `prepareRecords` about handshake-message framing on top of record framing. Flag this
  back before implementing if there's a reason to prefer B.
- **Files:** `connection/encryptionLayer/TlsConnection.kt`.
- **Tests:** add a case to `TlsRecordHandlingTest.kt` that splits a single ClientHello across two
  outbound `unwrapOutbound()` calls (two independently-framed TLS records) and asserts the
  connection reaches `SERVER_HANDSHAKE` instead of being closed.
- **Commit:** `fix(vpn): handle outbound TLS handshake messages that span multiple records`

### PKT-06 — Stop hardcoding the CA keystore password; tighten backup exposure

- **Priority:** Critical · **Depends on:** —
- **Resolves:** V-01
- **Approach:** generate a random per-install password on first CA creation (e.g. via
  `SecureRandom`) and persist it through Android Keystore-backed `EncryptedSharedPreferences`
  rather than a literal constant; exclude the keystore directory from Android auto-backup (a
  `dataExtractionRules`/`fullBackupContent` XML resource with an `<exclude>` for the keystore
  path is available even with `allowBackup="true"` left on for the rest of the app, if the app
  relies on backup elsewhere).
- **Files:** `mitm/Authority.kt`, `app/src/main/AndroidManifest.xml`, a new backup-rules XML
  resource.
- **Tests:** no existing `Authority`/`KeyStoreHelper` test file — add one asserting two separate
  `Authority.getDefaultInstance()`-driven keystore creations use different passwords.
- **Commit:** `fix(vpn): stop hardcoding the MitM CA keystore password; exclude it from backups`

### PKT-07 — Make upstream certificate validation real (or an explicit, defaulted-off opt-out)

- **Priority:** High · **Depends on:** — · **Open product question — read before starting**
- **Resolves:** V-02
- **Approach:** wire `trustAllServers` through to a real, default-`false` setting so
  `MergeTrustManager(ks)` (already implemented, currently dead) is used by default; keep an
  explicit opt-out for users who understand the tradeoff (e.g. testing against a server with an
  untrusted/self-signed cert). Since Heimdall's MitM decrypts the *user's own* device traffic for
  privacy analysis rather than proxying third-party traffic, there's a real question of how much
  upstream-validation strictness is wanted vs. how much it would break inspection of apps hitting
  internal/self-signed endpoints — flag this back rather than assuming "always strict" is correct
  before implementing.
- **Files:** `mitm/CertificateSniffingMitmManager.kt`, `mitm/SSLEngineSource.kt`, wherever VPN
  settings are surfaced to the user (`core/datastore`/`app/.../ui`).
- **Tests:** a `MergeTrustManager` unit test (none currently exists) asserting it rejects an
  untrusted upstream cert and accepts one signed by a CA in its keystore.
- **Commit:** `fix(vpn): make upstream TLS validation a real, defaulted-safe setting`

### PKT-08 — Fix certificate serial number generation

- **Priority:** Critical (small) · **Depends on:** —
- **Resolves:** V-03
- **Approach:** remove the `rnd.setSeed(System.currentTimeMillis())` call (a fresh
  `java.util.Random()` already seeds uniquely) or, better, generate the serial directly from
  `SecureRandom` bytes instead of `java.util.Random`.
- **Files:** `mitm/CertificateHelper.kt`.
- **Tests:** add a test asserting `initRandomSerial()` (or a small wrapper making it testable)
  produces distinct values across many calls made in rapid succession within the same
  millisecond.
- **Commit:** `fix(vpn): stop seeding certificate serial numbers from wall-clock time`

### PKT-09 — Fix CA/leaf validity-period arithmetic; check validity on keystore reuse

- **Priority:** High · **Depends on:** —
- **Resolves:** V-04
- **Approach:** fix `NOT_AFTER`'s arithmetic to actually match the intended lifetime (decide: a
  genuinely long-lived CA per the comment, or a shorter/rotatable one — flag which is wanted).
  Have `KeyStoreHelper.initialiseOrLoadKeyStore` load the CA cert and call
  `checkValidity()` before deciding to reuse it, regenerating (and surfacing a
  "reinstall the Heimdall CA certificate" prompt to the user) on expiry instead of failing
  handshakes silently.
- **Files:** `mitm/CertificateHelper.kt`, `mitm/KeyStoreHelper.kt`.
- **Tests:** a `KeyStoreHelper` test (none exists today) using a stubbed/short-lived cert to
  assert an expired keystore triggers regeneration rather than being reused.
- **Commit:** `fix(vpn): correct CA validity period and check it before reusing the keystore`

### PKT-10 — Fix keystore reuse to not require the `.pem` export

- **Priority:** High · **Depends on:** PKT-09 (touches the same reuse check)
- **Resolves:** V-05
- **Approach:** check only `authority.aliasFile(KEY_STORE_FILE_EXTENSION).exists()` for reuse;
  if the `.pem` is separately missing, re-export it from the loaded keystore
  (`exportPem(authority.aliasFile(".pem"), keyStore.getCertificate(authority.alias))`) instead of
  falling into the regeneration branch.
- **Files:** `mitm/KeyStoreHelper.kt`.
- **Tests:** a `KeyStoreHelper` test asserting that deleting only the `.pem` file and calling
  `initialiseOrLoadKeyStore` again re-exports it without changing the CA's serial number/public
  key.
- **Commit:** `fix(vpn): don't regenerate the CA just because its .pem export is missing`

### PKT-11 — Make `SubjectAlternativeNameHolder` safe against non-`String` SAN types

- **Priority:** High · **Depends on:** —
- **Resolves:** V-06
- **Approach:** restrict `isValidNameEntry`'s accepted tags to the `String`-valued GeneralName
  types Heimdall actually forwards (dNSName=2, iPAddress=7, rfc822Name=1,
  uniformResourceIdentifier=6); log-and-skip other tags instead of `.toString()`-ing a `byte[]`.
- **Files:** `mitm/SubjectAlternativeNameHolder.kt`.
- **Tests:** extend `core/vpn/src/test/java/de/tomcory/heimdall/core/vpn/mitm/SubjectAlternativeNameHolderTest.kt` with a case passing an `otherName`-tagged (`byte[]`-valued) entry and asserting it's skipped rather than corrupting the resulting SAN set or throwing.
- **Commit:** `fix(vpn): don't forward byte[]-valued SAN types as strings into GeneralName`

### PKT-12 — Close the leaked `SocketChannel` on remote-initiated TCP close

- **Priority:** High · **Depends on:** —
- **Resolves:** V-21
- **Approach:** call `selectableChannel.close()` alongside `selectionKey?.cancel()` in both the
  `bytesRead == -1` branches of `unwrapInboundReadable()` and the `CLOSING -> CLOSED` transition
  in `handleAckEmpty()` — or simply route both through the existing `closeSoft()`/`closeHard()`
  helpers, which already close the channel correctly.
- **Files:** `connection/transportLayer/TcpConnection.kt`.
- **Tests:** extend `ConnectionTeardownTest.kt` with a case simulating a remote-initiated close
  (server-side EOF) and asserting the `SocketChannel` is actually closed (`isOpen == false`), not
  just deregistered from the selector.
- **Commit:** `fix(vpn): close the socket channel on remote-initiated TCP close, not just the selection key`

### PKT-13 — Idle-reap stale UDP connections

- **Priority:** High · **Depends on:** —
- **Resolves:** V-22
- **Approach:** add a last-activity timestamp to `UdpConnection` (updated on `wrapOutbound`/
  `unwrapInbound`), and a periodic sweep — a coroutine on a `ComponentManager`-scoped
  `CoroutineScope` ticking every N seconds — that calls `closeHard()` on `ConnectionCache`
  entries whose `protocol == Protocol.UDP` and last activity exceeds a timeout (e.g. 2-5
  minutes, matching typical NAT UDP session timeouts). Needs a way to enumerate cache entries by
  protocol/type — check whether `ConnectionCache` should expose that or whether tracking a
  separate `Set<UdpConnection>` in `ComponentManager` is simpler.
- **Files:** `connection/transportLayer/UdpConnection.kt`, `components/ComponentManager.kt`,
  possibly `cache/ConnectionCache.kt`.
- **Tests:** extend `core/vpn/src/test/java/de/tomcory/heimdall/core/vpn/integration/ConcurrentConnectionsTest.kt` (or a new test) asserting a UDP connection with no activity past the timeout is closed and removed from the cache by the sweep.
- **Commit:** `fix(vpn): idle-reap UDP connections instead of holding them for the whole session`

### PKT-14 — Bound `TlsPassthroughCache` like `DnsCache`

- **Priority:** Medium · **Depends on:** —
- **Resolves:** V-23
- **Approach:** replace the backing `HashSet` with the same bounded-`LinkedHashMap`
  pattern `DnsCache` already uses (size cap via `removeEldestEntry`, or a Guava
  `Cache`-with-`expireAfterAccess` like `SSLEngineSource`'s cert cache already does elsewhere in
  this codebase).
- **Files:** `metadata/TlsPassthroughCache.kt`.
- **Tests:** extend `core/vpn/src/test/java/de/tomcory/heimdall/core/vpn/metadata/TlsPassthroughCacheTest.kt` with a case inserting more than the cap and asserting the oldest entries are evicted.
- **Commit:** `fix(vpn): bound TlsPassthroughCache size instead of growing it forever`

### PKT-15 — Fix `ConnectionCache.getKey()`'s bit-packing collision

- **Priority:** Medium · **Depends on:** —
- **Resolves:** V-24
- **Approach:** widen the key to a non-colliding packing — e.g. combine
  `remoteAddress.hashCode()`, `protocol`, `localPort`, and `remotePort` via
  `java.util.Objects.hash(...)` (or a `data class` used directly as the map key) instead of
  hand-rolled XOR/shift bit-packing into a single `Int`.
- **Files:** `cache/ConnectionCache.kt`.
- **Tests:** a `ConnectionCache` unit test (none exists today) asserting the two previously
  colliding tuples (`localPort=1,remotePort=0` vs. `localPort=0,remotePort=256`, same
  address/protocol) now produce distinct keys, and that `addConnection` for both doesn't log
  `"Flow overwritten"`.
- **Commit:** `fix(vpn): stop ConnectionCache's key from colliding on distinct port pairs`

### PKT-16 — Synchronize `TcpConnection`'s sequence-number/state fields

- **Priority:** Medium · **Depends on:** PKT-01 (fix the arithmetic bug first, then make the
  now-correct updates thread-safe)
- **Resolves:** V-25
- **Approach:** make `ourSeqNum`/`theirSeqNum` `@Volatile` at minimum (single-writer-style
  updates from either thread, always read fresh); if true read-modify-write concurrency between
  the two handler threads for the same connection turns out to be possible (confirm via the
  actual call graph), use `AtomicLong` instead. Same treatment for `state`
  (`TransportLayerConnection.kt:106`) if it turns out to be read-then-branched-on across threads
  in a way `@Volatile` alone doesn't make safe.
- **Files:** `connection/transportLayer/TcpConnection.kt`, `connection/transportLayer/TransportLayerConnection.kt`.
- **Tests:** extend `core/vpn/src/test/java/de/tomcory/heimdall/core/vpn/integration/ConcurrentConnectionsTest.kt` with a stress case driving simultaneous inbound and outbound traffic on one connection and asserting the final sequence numbers match the total bytes actually transferred.
- **Commit:** `fix(vpn): make TcpConnection's sequence counters and state visible across threads`

### PKT-17 — Split `HttpConnection`'s reassembly state per direction; fix request/response correlation

- **Priority:** High · **Depends on:** —
- **Resolves:** V-18, V-20
- **Approach:** duplicate `previousPayload`/`chunkCache`/`overflowing`/`chunked`/
  `statedContentLength`/`remainingContentLength` into per-direction copies (or a small
  `ReassemblyState` data class held twice), and have `handleData` operate on the copy matching
  its `isOutbound` argument. For correlation, replace the bare rendezvous `Channel<Long>` with an
  ordered queue (e.g. `ArrayDeque<Long>` guarded by the connection's existing single-threaded
  access pattern per direction, or a `Channel` with enough buffer plus an explicit sequence
  number) so pipelined requests/responses pair correctly, and ensure it's cancelled/drained on
  connection teardown so an unanswered request doesn't leak a suspended coroutine forever.
- **Files:** `connection/appLayer/HttpConnection.kt`.
- **Tests:** extend `core/vpn/src/test/java/de/tomcory/heimdall/core/vpn/connection/appLayer/HttpParsingTest.kt` with a case interleaving inbound response bytes between two halves of an outbound request body and asserting both are persisted correctly and un-corrupted; a pipelining case asserting two outbound requests followed by two inbound responses correlate in the right order.
- **Commit:** `fix(vpn): stop HttpConnection from sharing reassembly state between directions`

### PKT-18 — Fix `dechunkHttpMessage` to respect declared chunk sizes

- **Priority:** Medium · **Depends on:** —
- **Resolves:** V-19
- **Approach:** walk the chunked body using the declared `chunkSize` byte count to slice exactly
  that many bytes as the chunk's data (advancing a byte offset), rather than splitting the whole
  body on every `"\r\n"` and assuming the next "line" is the chunk's entire data.
- **Files:** `connection/appLayer/HttpConnection.kt`.
- **Tests:** extend `HttpParsingTest.kt` with a chunked body whose chunk data contains an
  embedded `\r\n` (e.g. a multi-line JSON chunk) and assert the dechunked result matches the
  original content exactly.
- **Commit:** `fix(vpn): dechunk HTTP bodies by declared chunk size, not by splitting on every CRLF`

### PKT-19 — Fix the three protocol-detection off-by-ones/bit-math bugs

- **Priority:** Medium · **Depends on:** —
- **Resolves:** V-29, V-30, V-31
- **Approach:** in `EncryptionLayerConnection.detectQuic()`, parenthesize the byte-combination
  expression explicitly (`(b1 shl 24) or (b2 shl 16) or (b3 shl 8) or b4`) and broaden the
  accepted version set beyond just `0`/`1` (at minimum QUIC v1 `0x00000001` is already covered;
  add v2 `0x6f0d5eb1`/version-negotiation `0x00000000` and consider treating any long-header
  packet as "don't MITM" rather than requiring an exact version match, since the goal here is
  just "don't attempt doomed interception," not full QUIC version parsing). In `detectTls()`,
  relax the length guard from `rawPayload.size > 6` to `rawPayload.size > 5` to match what
  `rawPayload[5]` actually requires. In `AppLayerConnection.getInstance()` (both overloads),
  change the HTTP-sniff guard from `payload.size > 7` to `payload.size >= 11` to match what
  `sliceArray(0..10)` requires, or slice defensively (`payload.sliceArray(0 until minOf(11, payload.size))`).
- **Files:** `connection/encryptionLayer/EncryptionLayerConnection.kt`,
  `connection/appLayer/AppLayerConnection.kt`.
- **Tests:** extend `core/vpn/src/test/java/de/tomcory/heimdall/core/vpn/connection/encryptionLayer/ProtocolDetectionTest.kt` with cases for a real QUIC v2 long-header packet, a minimal 6-byte TLS ClientHello-prefix, and an 8/9/10-byte first HTTP payload — asserting each is now correctly classified instead of falling through to `PlaintextConnection`/`RawConnection`.
- **Commit:** `fix(vpn): fix QUIC version bit-math and off-by-one length guards in protocol detection`

**Deferred / lower priority (V-07, V-08, V-09, V-17, V-26, V-27, V-28):** each is real but either
narrow-trigger (V-07 needs a CN shared across differing-SAN certs within a 5-minute window; V-17
needs an actively hostile or badly-behaved TCP peer; V-27/V-28 are minor selector/teardown
hygiene with no correctness impact observed) or a genuinely open architectural question (V-26,
confining all of a `TlsConnection`'s mutation to a single-threaded per-connection dispatcher, is
a bigger refactor than a packet — worth a dedicated design pass rather than a quick fix). Revisit
after PKT-01 through PKT-19 land.

---

## Appendix — low-severity / code smell (not given full packets)

- **Debug scaffolding in production `TlsConnection`:** `System.err.println(...)` calls plus a
  12-frame `Thread.currentThread().stackTrace` dump on *every* `closeConnection()`
  (`TlsConnection.kt:437-438`), and two more `System.err.println` sites (`:411`, `:416`, `:710`),
  alongside a hardcoded `private val log = true` (`:67`) that unconditionally enables very
  verbose per-record `Timber.d` logging (including full hex dumps). Strip the `System.err`
  lines and make `log` a build-variant/remote-config flag rather than a hardcoded `true`.
- **Dead commented-out files:** `mitm/nio/NioSslServer.java` (242 lines, entirely a commented-out
  class body past line 30) and `mitm/nio/NioSslClient.java` (182 lines, same shape). Delete or
  restore — as-is they're pure dead weight.
- **Unused/unsynchronized singleton:** `CertificateSniffingMitmManager.createSingleton`/
  `getSingleton` (`:96-110`) has no locking around the write and isn't used in production —
  `ComponentManager.kt:77` constructs `CertificateSniffingMitmManager(authority)` directly. The
  only other reference repo-wide is `app/src/test/java/de/tomcory/heimdall/DirectHttpTest.kt`,
  which imports `de.tomcory.heimdall.vpn.mitm.Authority` — a package path that doesn't exist
  (the real package is `de.tomcory.heimdall.core.vpn.mitm.Authority`) — this test is stale/dead
  and won't compile if it's ever included in a build.
- **Latent plaintext private-key export:** `KeyStoreHelper.initializeServerCertificates`
  (`:71-93`) writes a per-host leaf certificate's private key to an unencrypted PEM file
  (`exportPem(authority.aliasFile("-$commonName-key.pem"), key)`, `:91`) with the hostname in the
  filename. No callers found anywhere in the repo today — dead code, but a latent
  plaintext-key-leak if it's ever wired up.
- **Stale comments:** `SSLEngineSource.kt:159-166`'s doc claims "Generates an 1024 bit RSA key
  pair using SHA1PRNG"; the actual key size (`CertificateHelper.FAKE_KEY_SIZE`) is 2048.
  `CertificateSniffingMitmManager.kt:51-54`'s comment argues using the upstream CN/SAN "is not
  necessary" directly above code that does exactly that.
- **CA cert extension hygiene:** `KeyUsage` is added non-critical (`false` at
  `CertificateHelper.kt:135`) where RFC 5280 §4.2.1.3 recommends critical for a CA; the CA's
  `ExtendedKeyUsage` includes `KeyPurposeId.anyExtendedKeyUsage` (`:141`) alongside specific
  purposes, which is atypical for a CA cert and weakens the constraint EKU is meant to assert.
- **Legacy explicit `SecureRandom` algorithm:** `CertificateHelper.kt:37,275` pins
  `SecureRandom.getInstance("SHA1PRNG")` instead of the platform-default `SecureRandom()`.
- **Dead-but-latent-unsafe code in `prepareRecords`:** `TlsConnection.kt:829` computes
  `val recordType = payload[0].toInt()` unconditionally before branching on
  `remainingBytes > 0`; in that branch, `payload` is a raw continuation chunk of a record's
  *body*, so `recordType` is never actually used there — dead, and if `payload` were ever empty
  at this point, `payload[0]` would throw uncaught (mitigated in practice by callers never
  passing empty payloads, but worth a defensive `payload.isNotEmpty()` guard given V-10).
- **Weak initial sequence number range:** `TcpConnection.kt:51`,
  `(Math.random() * 0xFFFFFFF).toLong()` — `0xFFFFFFF` is 28 bits (~268M), not the full 32-bit ISN
  space (`0xFFFFFFFF`, ~4.29B) a real ISN should draw from.
- **Hardcoded 1500-byte device-read buffer:** `DevicePollThread.kt:32`,
  `val packet = ByteArray(1500) //TODO: actually implement a reusable buffer`, vs.
  `maxPacketSize = 16413` used everywhere else (`ComponentManager.kt:50`). `parsePacket`'s
  stated-length check (`DevicePollThread.kt:127-135`) fails safe (drops the packet) if the TUN
  device ever delivers something larger than 1500 bytes, but the data is silently lost rather
  than handled — worth revisiting alongside confirming `HeimdallVpnService`'s `Builder` sets an
  explicit MTU.
- **`printStackTrace()` instead of `Timber`; CA-generation failure swallowed to `""`:**
  `Authority.kt:33-38` uses `e.printStackTrace()` (not captured by production log pipelines)
  where the rest of the file uses `Timber`; `Authority.generateCertificate` (`:81-88`) catches
  any exception during CA creation and returns `""`, giving callers no way to distinguish
  "legitimately empty" from "generation failed."

---

## Test coverage gaps

- `mitm/KeyStoreHelper.kt` has no dedicated test file — the reuse-vs-regenerate heuristic (V-05)
  and the validity check this audit recommends adding (V-04/PKT-09) are both completely
  unverified today.
- `mitm/Authority.kt` has no dedicated test file — `aliasFile`'s side-effecting placeholder-file
  creation is unverified.
- `SubjectAlternativeNameHolderTest.kt` (`core/vpn/src/test/java/de/tomcory/heimdall/core/vpn/mitm/`)
  only feeds String-typed SAN tags (dNSName, iPAddress) — never the `byte[]`-valued tags that
  trigger V-06.
- `SSLEngineSource.createCertForHost`'s cache keying/concurrency (V-07) isn't exercised anywhere;
  `ConcurrentConnectionsTest.kt` covers TCP-level concurrency, not concurrent/duplicate cert
  generation for the same-or-same-CN-different-SAN hosts.
- No negative-path test exists for a cert-generation failure mid-handshake (V-13) — what happens
  to a `TlsConnection` when `setupClientSSLEngine()`/`setupServerSSLEngine()` throws.
- `MergeTrustManager` has no test file at all (relevant if PKT-07 makes it reachable).
- `ConnectionCache` has no dedicated test file — V-24's key-collision behavior is unverified.
- `ConnectionTeardownTest.kt` has exactly one test case ("closing a connection mid-flight
  releases the socket and removes it from the cache") — it doesn't specifically exercise the
  remote-initiated-close path (V-21) or the graceful-close RST/FIN-ACK conflict (V-15).
- `MalformedInputRobustnessTest.kt`'s three existing cases (garbage TCP bytes, empty DNS
  response, malformed HTTP status line) each assert their specific input doesn't crash the
  connection — none of them test whether a crash in *one* connection can take down the shared
  `InboundTrafficHandler`/`OutboundTrafficHandler` threads that every other connection depends on
  (V-10's actual blast-radius claim).
