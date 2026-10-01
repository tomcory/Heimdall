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

**Addendum 2026-09-30:** V-32–V-35 / PKT-20–PKT-24, found during the QUIC analysis
(`docs/quic_mitm.md`), plus V-36 / PKT-25, found while implementing PKT-23. References were checked against branch `bugfix/mitm-vpn` at `cb7cc22`.

**Addendum 2026-10-01:** V-37–V-41 / PKT-26–PKT-29 and PKT-46–PKT-49, the implementation
packets for phases Q0 to Q2 of `docs/quic_mitm.md` (detection hardening, passive Initial
inspection, QUIC block policy). References were checked against `bugfix/mitm-vpn` at `3454f48`.
PKT-26 to PKT-29 are implemented; PKT-46 to PKT-49 are not.

**Addendum 2026-10-01 (traffic script):** V-42–V-46 / PKT-30–PKT-33 and PKT-36, found by running
`scripts/emulator-traffic.sh` against a rooted emulator. They are numbered ahead of the remaining
QUIC packets, which moved from PKT-30–PKT-33 to PKT-46–PKT-49, because they should be done first.
References for V-42–V-45 were checked against `bugfix/mitm-vpn` at `4eb2013`, for V-46 at
`84667ca`. PKT-30 to PKT-33 are implemented; PKT-36 is not.

**Addendum 2026-10-01 (stress test):** V-47–V-56 / PKT-34, PKT-35 and PKT-37–PKT-45, found by
stress-testing the VPN on a rooted emulator with `scripts/stress/run-stress.sh` (see "Stress-test
findings"). V-17 is raised from Medium to High on the same evidence. The packets are numbered in
the order they should be done, so the packet for V-46 moved from PKT-34 to PKT-36 and the QUIC
packets to PKT-46–PKT-49. References were checked against `bugfix/mitm-vpn` at `ebba1f8`. None
of them is implemented.

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
| V-17 | H | No validation of incoming TCP segments against the tracked sequence number (raised from M on 2026-10-01, see "V-17 revisited") |
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
| V-32 | L | `core:vpn` depends on all of `netty-all` 4.1.58 solely for `InsecureTrustManagerFactory` |
| V-33 | L | Stray-RST device writes use an undeclared magic message code `6` |
| V-34 | H | `TlsPassthroughCache` is read but never written — apps rejecting the forged cert fail on every connection |
| V-35 | M | MitM app/host scope preferences are editable in the UI but never read by the VPN |
| V-36 | H | Handshake records arriving while delegated tasks are pending are silently dropped — the MitM handshake hangs |
| V-37 | M | `detectQuic()` accepts any long-header packet: version 0, non-Initial types, undersized datagrams |
| V-38 | M | The encryption-layer protocol (PLAIN/TLS/QUIC), SNI and ALPN are never persisted |
| V-39 | M | `remoteHost`/`isTracker` come from `DnsCache` only and are never corrected once an SNI is known |
| V-40 | M | QUIC flows carry no hostname of their own although the Initial packet exposes SNI and ALPN |
| V-41 | H | With MitM on, HTTP/3 traffic bypasses decryption entirely; there is no way to force the TLS fallback |
| V-42 | M | A client-side TCP half-close tears down the upstream connection, so the server's response is lost |
| V-43 | L | A client alert that arrives before the client-facing TLS engine exists is fed to a null engine and logged as an engine failure |
| V-44 | H | Chunked HTTP messages are never recognised as complete — they are not persisted and stall the parser for the rest of the connection |
| V-45 | M | HTTP responses without a body (HEAD, 1xx, 204, 304) and bodies delimited by connection close stall or bloat the parser |
| V-46 | H | On a MitM'd connection, the FIN for a remote close overtakes response data still queued in the TLS layer — the client loses the end of the response |
| V-47 | H | A remote close never reaches the client: the FIN is sent without the ACK flag and the device discards it |
| V-48 | M | Upstream connect failures and resets are not signalled to the client: a refused connection looks like a timeout, a reset like a hang |
| V-49 | H | The device's TCP receive window is ignored and nothing is retransmitted — a client that reads slowly loses data and stalls |
| V-50 | H | Writes to a slow upstream busy-wait on the shared outbound thread, freezing every connection |
| V-51 | H | Blocking per-connection setup on the single outbound thread delays ACKs by hundreds of milliseconds under load |
| V-52 | H | HTTP bodies with `Content-Length` are buffered whole in memory — large transfers exhaust the heap and freeze the VPN |
| V-53 | H | Socket receive buffers are shrunk to 16 KB: UDP bursts are dropped by the kernel and TCP throughput is halved |
| V-54 | M | Fragmented IP packets are not handled, so UDP datagrams above the MTU never arrive |
| V-55 | M | Throughput through the VPN is a fraction of the direct path, most of all for uploads |
| V-56 | M | Stopping the VPN leaks file descriptors: the selector is never closed, so every connection open at that moment keeps its descriptor |

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

## Addendum findings (V-32–V-36)

### V-32 — Netty pulled in for a single class (Low)

`SSLEngineSource.kt:5` imports `io.netty.handler.ssl.util.InsecureTrustManagerFactory`, and `:143`
uses it when `trustAllServers` is set. Nothing else in `core/` or `app/` imports Netty, yet
`core/vpn/build.gradle.kts:36` depends on all of `netty-all` 4.1.58.Final
(`gradle/libs.versions.toml:34,106`). That is an old release that adds APK weight, method count and
dependency-audit surface. The code already flags this itself with the TODO at `SSLEngineSource.kt:138`
("can we get rid of the InsecureTrustManagerFactory (with the goal of eliminating Netty)?").
`CLAUDE.md` and `docs/ARCHITECTURE.md` also describe Netty as doing "TCP/TLS handling in the
VPN's MitM engine", which is not true.

**Recommendation:** replace it with a small in-house `X509ExtendedTrustManager` and drop the
dependency (PKT-20).

### V-33 — Magic device-write message code `6` (Low)

`TransportLayerConnection.getInstance()` resets unknown TCP packets with
`deviceWriter.obtainMessage(6, …)` (`TransportLayerConnection.kt:285`, and the commented-out DoT
branch at `:279`). `DeviceWriteThread` only declares `WRITE_TCP = 0` and `WRITE_UDP = 1`
(`DeviceWriteThread.kt:63-66`). `handleMessageImpl` (`:47-61`) never reads `msg.what`, so there is
no functional bug today. The number is still undocumented, and a future dispatcher keyed on `what`
would silently drop these packets.

**Recommendation:** add a named constant and document that `what` is informational (PKT-21).

### V-34 — `TlsPassthroughCache` is never populated (High)

`TlsConnection.handleOutboundRecord()` checks the cache on every ClientHello:

```kotlin
doMitm = doMitm && !(transportLayer.appId?.let { componentManager.tlsPassthroughCache.get(it, hostname) } ?: false)
```

(`TlsConnection.kt:221`). However, nothing in `core/` or `app/` ever calls
`TlsPassthroughCache.put()`, so the check is always `false`. An app that rejects Heimdall's forged
certificate keeps failing on every connection for the whole VPN session. That includes apps that
don't trust user CAs (the default for `targetSdk ≥ 24`), apps that pin, and apps whose TLS stack
rejects the handshake for some other reason. With MitM enabled, such apps are effectively
offline, and the traffic they would have sent is never captured, even as ciphertext.

Two details make detection non-trivial:
- Under TLS 1.3 the client's fatal alert after our Certificate message is encrypted, so it arrives
  with outer record type `APP_DATA`, not `ALERT`. It only shows up as the client-facing
  `SSLEngine.unwrap()` throwing, inside `handleUnwrap` (`:826-832`).
- A client that simply closes TCP during or right after the handshake (OkHttp's
  `CertificatePinner` completes the handshake and then closes) is invisible to `TlsConnection`.
  `TcpConnection` handles device FIN/RST (`TcpConnection.kt:152-166`) without notifying the layers
  above.

**Recommendation:** add a "client closed" hook from transport to encryption layer (PKT-22), then
learn per-session passthrough entries from client-side handshake failures (PKT-23).

### V-35 — MitM scope preferences have no effect (Medium)

`preferences.proto:47-56` defines `mitm_appLayer_passthrough`, `mitm_monitoringScope_apps`,
`mitm_monitoringScope_hosts` and the four MitM app/host white/blacklists.
`PreferencesDataSource` exposes them, and `TrafficScannerPreferences.kt:98-117` and
`PreferencesScreen.kt:316-327` let the user edit several of them. But
`HeimdallVpnService.launchServiceComponents()` (`:204-229`) only reads `mitmEnable` and
`mitmTrustAllUpstreamCerts`, and `ComponentManager` has no parameter for any of them. Users can
configure "don't intercept app X / host Y" and it is silently ignored. Two further problems:
- `mitm_appLayer_passthrough` (default `true`) has no documented meaning.
- There is no UI editor for the MitM *host* lists.

**Recommendation:** resolve the preferences into a core-owned `MitmScope` and apply it at the
same decision point as V-34's learned passthrough (PKT-24).

### V-36 — Handshake records dropped while delegated tasks are pending (High)

`TlsConnection.continueHandshake()`'s `NEED_TASK` branch drained the engine's delegated tasks
(key schedule, certificate verification) and ran them in a separately launched coroutine on
`connectionScope`. That coroutine only ran after the current task finished. When several handshake
records arrived in one transport payload, `prepareRecords` kept unwrapping the remaining records
in the current task, while the tasks were still pending. JSSE's `SSLEngine.unwrap()` then returns
`NEED_TASK` without consuming anything. The branch found the task queue empty ("prior coroutine is
handling") and returned, so the record was lost and the handshake hung waiting for it.

Whether it triggers depends on how the peer's flight is split across TCP reads, so it showed up as
an intermittent "client-facing TLS handshake never completed" failure in `TlsMitmHttpFlowTest`.
It was confirmed with temporary logging while implementing PKT-23: inbound records of 90 and
~1749 bytes were unwrapped with 0 bytes consumed and dropped. On a device it means MitM'd
connections randomly stall during the handshake.

**Recommendation:** run delegated tasks inline, since the code is already confined to the
connection's single-threaded dispatcher, and retry rather than drop a record the engine refuses
(PKT-25).

---

## QUIC findings (V-37–V-41)

Background, protocol details and the reasoning behind the phases are in `docs/quic_mitm.md`
(§1 to §3.3). The findings here are the parts of it that Q0 to Q2 resolve.

### V-37 — `detectQuic()` is too permissive to act on (Medium)

`EncryptionLayerConnection.detectQuic()` (`EncryptionLayerConnection.kt:157-173`) returns true
for any payload of at least 5 bytes whose first byte has the long-header and fixed bits set
(`:170`). PKT-19 relaxed it on purpose, on the grounds that `QuicConnection` only passes data
through. Once QUIC flows are inspected and possibly blocked, that is too loose:

- Version 0 is Version Negotiation, which only servers send. It is never a client's first packet.
- Handshake, 0-RTT and Retry packets pass, although a client's first packet is always an Initial.
- There is no size check. RFC 9000 §14.1 requires client datagrams carrying an Initial to be at
  least 1200 bytes, which cheaply rejects other UDP protocols whose first byte happens to be
  `0xC0` or above.

**Recommendation:** require a non-zero version, the Initial packet type and 1200 bytes (PKT-26).

### V-38 — Security protocol, SNI and ALPN are not persisted (Medium)

`Connection` stores only the transport protocol (`Protocol.TCP`/`UDP`). `Protocol.kt`'s kdoc
states that the encryption-layer label is "logging-only and never persisted". The SNI that
`TlsConnection` parses is kept in a private field, and ALPN is not parsed at all. The database
therefore cannot tell a QUIC flow from DNS-less UDP noise, or TLS from plaintext TCP, and the UI
and exports cannot show it.

**Recommendation:** add `securityProtocol`, `sni`, `alpn`, `echOffered` and `blocked` to
`Connection` in one schema bump, with update methods on `DatabaseConnector` (PKT-27).

### V-39 — Hostname and tracker label are never corrected by the SNI (Medium)

`TransportLayerConnection.getInstance()` resolves `remoteHost` by reverse lookup of the
destination IP in `DnsCache` (`TransportLayerConnection.kt:282`), and `isTracker` is computed
once from it in the constructor (`:119`). Both are immutable. The lookup fails or is wrong when
the app uses DoH/DoT or Private DNS, when the DNS answer was cached before the VPN started, or
when several hosts share one IP. `TlsConnection` learns the real name from the ClientHello but
only uses it for the MitM decision.

**Recommendation:** let the encryption layer refine the transport connection's hostname and
re-run the tracker label (PKT-28).

### V-40 — QUIC flows have no hostname of their own (Medium)

QUIC Initial packets are protected with keys derived from public values (the Destination
Connection ID and a per-version salt, RFC 9001 §5.2), so any on-path observer can read the
ClientHello inside. `QuicConnection` does not: it forwards every datagram unread
(`QuicConnection.kt:27-35`). A QUIC flow is therefore labelled only by V-39's DNS lookup, and
its ALPN (`h3`, `doq`, …) is unknown.

**Recommendation:** decrypt the client Initial passively and record SNI and ALPN, with MitM on
or off (PKT-29, PKT-46, PKT-47).

### V-41 — HTTP/3 bypasses the MitM entirely (High)

`QuicConnection` sets `doMitm = false` unconditionally (`QuicConnection.kt:22`). With MitM
enabled, every app that speaks HTTP/3 sends that traffic past the decryption pipeline; only its
TCP traffic is intercepted. Almost all such clients fall back to TCP+TLS when UDP/443 fails, and
for Chromium-based clients (Chrome, Cronet) a fallback is the only possible outcome anyway,
because they refuse QUIC certificates that do not chain to a public root
(`docs/quic_mitm.md` §2.6). There is currently no way to trigger that fallback.

**Recommendation:** a user preference to block h3 QUIC while MitM is on, enforced only where
the TLS fallback would actually be intercepted (PKT-48, PKT-49).

---

## Traffic-script findings (V-42–V-45)

Found on 2026-10-01 by running `scripts/emulator-traffic.sh` against a rooted API 33 emulator
with MitM on. V-42 to V-44 were observed on the device and traced to the code below. V-45 came
out of reading the same HTTP parser and has **not** been reproduced yet.

### V-42 — Client-side TCP half-close loses the response (Medium)

`TcpConnection.handleFin()` (`TcpConnection.kt:336-365`, also reached through `handleFinAck()`
at `:323-334`) treats the device's FIN as the end of the connection. Its `else` branch calls
`closeSoft(abortClientSession = false, finalizeState = false)`, which cancels the selection key
and **closes the upstream `SocketChannel`**, and then answers the device with a FIN-ACK:

```kotlin
notifyClientClosed()
closeSoft(abortClientSession = false, finalizeState = false)
increaseTheirSeqNum(1)
val finAckResponse = ipPacketBuilder.buildPacket(buildFinAck())
```

A FIN only says "I have finished sending". A client may send its request, shut down its sending
side and then read the reply. With the upstream socket closed, that reply has nowhere to go.

Observed: `printf 'GET / HTTP/1.1…' | nc host 80` (netcat sends a FIN at end of input) returned
nothing and the connection row had `bytesIn = 0`. The same request with the sending side held
open returned `HTTP/1.1 403 Forbidden`.

Affected are clients that half-close before reading: HTTP/1.0-style clients, code that calls
`Socket.shutdownOutput()`, netcat-like tools and several non-HTTP protocols. Mainstream Android
HTTP stacks do not do this, hence Medium.

**Recommendation:** shut down only the sending side of the upstream socket and keep relaying
inbound data until the remote closes (PKT-30).

### V-43 — Client alert before the client-facing engine exists (Low)

`TlsConnection.handleOutboundRecord()` passes every outbound `ALERT` record to
`handleUnwrap(record, true)` whatever the state (`TlsConnection.kt:271-275`). In `NEW`,
`SERVER_HANDSHAKE` and `SERVER_ESTABLISHED` the client-facing `SSLEngine` has not been created
yet, so `sslEngine?.unwrap(...)` (`:875`) evaluates to `null`. The `null ->` branch then logs
`handleUnwrap (outbound) unexpected res.status: NULL` (`:945`) and calls `closeConnection()`,
which resets the client.

Observed: a ClientHello followed directly by OpenSSL's `close_notify` alert produced that log
line and an immediate close.

The connection ends, which is what the client asked for, so nothing breaks. The defects are:
- an error-level log that reads like an engine failure;
- an RST where a clean close would do;
- the alert's level and description are never read, although the alert is plaintext at that
  point.

**Recommendation:** handle alerts explicitly in the states that have no client-facing engine
(PKT-31).

### V-44 — Chunked HTTP messages are never completed (High)

`HttpConnection.handleData()` has two independent defects.

1. **A message that arrives whole in one payload is never checked.** In the first-payload
   branch a chunked message is added to `chunkCache` and the method returns
   (`HttpConnection.kt:143-153`). The last-chunk test exists only in the branch for later
   payloads (`:169-177`). If no further payload arrives, the message waits forever.
2. **The last-chunk test does not match a correct terminator.**

   ```kotlin
   val lines = assembledPayload.toString(Charsets.UTF_8).split("\r\n")
   if(lines.size >= 2 && (lines[lines.size - 2].trim().toIntOrNull(16) ?: -1) == 0) {
   ```

   (`:171-172`). A chunked body ends with `0\r\n\r\n`. Split on CRLF, the second-to-last
   element of that is the empty string, not `0`. The test only fires for a payload that ends
   with exactly `0\r\n`, which is what `HttpParsingTest.kt:147` feeds it.

Consequences:
- The message is never persisted.
- `state.chunked` stays true, so every later payload in that direction is appended to
  `chunkCache`. The cache grows without bound and no later message on the connection is
  persisted either.
- For a response, the matching entry in `pendingRequestIds` is never consumed.

Observed: `http://example.com/` answers with `Transfer-Encoding: chunked`. Heimdall logged
`http127 Processing http in: 1037 bytes` and `http127 chunked`, never `last chunk`, and the
request row has no response. A response with `Content-Length` from another host was recorded.

Chunked encoding is the normal framing for dynamic HTTP/1.1 responses, and the same parser
handles decrypted HTTPS traffic, so this hits the data the MitM exists to capture.

**Recommendation:** determine completion by walking the declared chunk sizes, after every
payload including the first (PKT-32).

### V-45 — Bodiless and close-delimited responses stall or bloat the parser (Medium)

From reading `HttpConnection.handleData()`; not reproduced on a device or in a test yet.

- **Responses that never carry a body.** A response to `HEAD`, and any 1xx, 204 or 304
  response, may state a `Content-Length` without sending a body. `handleData()` derives
  `remainingContentLength > 0` from the header, sets `overflowing` and waits for body bytes
  that never arrive (`HttpConnection.kt:119-140`). The parser is then stuck in the same way as
  in V-44.
- **Bodies delimited by connection close.** With neither `Content-Length` nor chunked encoding,
  the message is persisted immediately with whatever body bytes shared the first payload. Every
  later payload fails the search for the end of the headers and is prepended to
  `previousPayload` (`:97-102`). That buffer grows for the rest of the connection and is decoded
  to a `String` again on every read.

**Recommendation:** reproduce both as failing tests first, then take the request method and
status code into account and stop parsing once a body runs until close (PKT-33).

### V-46 — A remote close overtakes inbound data still in the TLS layer (High)

Found on 2026-10-01 while verifying PKT-33 on the emulator. Observed once, cause traced in the
code; no test reproduces it yet.

`TcpConnection.unwrapInboundReadable()` hands every chunk it reads to the encryption layer
(`TcpConnection.kt:459`) and, when the read returns end-of-stream, immediately moves to
`CLOSING` and writes a FIN to the device (`:486-491`). For a plaintext connection that is fine,
because the chunk has been processed and written to the device by the time the call returns.
`TlsConnection.unwrapInbound()` only enqueues the chunk on `connectionScope`
(`TlsConnection.kt:163-164`) and returns. So when the server sends its response and closes
right away, the sequence is:

1. The transport reads the last encrypted bytes and enqueues them.
2. The transport sees end-of-stream and sends the FIN, using the current `ourSeqNum`.
3. The device ACKs the FIN. `handleAckEmpty()` closes the connection and removes it from the
   cache.
4. The TLS layer gets round to decrypting the queued bytes and writes them to the device with
   sequence numbers *after* the FIN. The device discards them, and its replies hit an unknown
   flow and are answered with a stray RST.

Observed (connection 269, `POST /play/log` to `play.googleapis.com`, decrypted):

```
16:41:39.270 TcpConnection: tcp269 SocketChannel closed, state transition CONNECTED -> CLOSING
16:41:39.270 HttpConnection: http269 Processing http in: 1002 bytes
16:41:39.272 HttpConnection: http269 chunked
16:41:39.274 HttpConnection: http269 Processing http in: 98 bytes
16:41:39.275 TransportLayerConnection: Resetting unknown TCP packet (ACK) to 172.217.119.4:443
```

The FIN went out before any of the response had been decrypted, and the connection was gone
five milliseconds later. The response's final chunk never reached the HTTP layer either, so the
request row has no response. The app repeated the request on a new connection.

Affected is every MitM'd connection on which the server closes directly after responding, which
is what `Connection: close` responses and many API endpoints do. The app sees a truncated or
missing response.

**Recommendation:** let the encryption layer decide when the remote close reaches the device,
after it has drained what it was given (PKT-36).

---

## Stress-test findings (V-47–V-56, V-17 revisited)

Found on 2026-10-01 with `scripts/stress/run-stress.sh` against a rooted API 33 emulator, MitM
on. The script runs a Java client from the adb shell, so its traffic passes through the VPN like
an app's. Plain HTTP, TCP and UDP tests go to deterministic test servers on the development
machine and verify every body by SHA-256. TLS tests go to public HTTPS servers. Every test was
first run with the VPN stopped: all passed except a paced UDP burst, of which the emulator's own
NAT drops about a tenth.

What held up, for the record:
- Bulk integrity: downloads up to 50 MB with `Content-Length` and 5 MB chunked, uploads up to
  20 MB, all hash-identical.
- 250 simultaneous connections, and 1500 short connections at about 106 per second, the same
  rate as without the VPN.
- 300 requests on one keep-alive connection, a response trickling in over 20 s, a connection
  idle for 75 s, 30 client-side resets mid-download.
- TLS MitM of 17 of 18 public sites, a 25 MB TLS download and a 5 MB TLS upload.
- Stopping and restarting the VPN three times with over 100 connections active: no crash.
- Leak check: see the note at the end of this section.

### V-47 — A remote close never reaches the client (High)

When the remote host closes, `TcpConnection.unwrapInboundReadable()` sends the device a FIN built
by `buildFin()` (`TcpConnection.kt:486-491`, `:629-631`):

```kotlin
return buildTcpPayload(urg = false, ack = false, psh = false, rst = false, syn = false, fin = true, …)
```

The segment has no ACK flag. Every segment of an established TCP connection must carry one, and
Linux discards those that don't. A capture on `tun0` shows it:

```
10.0.2.2.18080 > 10.120.0.1.46234: Flags [P.], seq 1:125, ack 45      response
10.120.0.1.46234 > 10.0.2.2.18080: Flags [.], ack 125
10.0.2.2.18080 > 10.120.0.1.46234: Flags [F], seq 88824064            our FIN, no ACK flag
10.120.0.1.46234 > 10.0.2.2.18080: Flags [F.], seq 45, ack 125        6 s later: still ack 125
10.120.0.1.46234 > 10.0.2.2.18080: Flags [F.], seq 45, ack 125        retransmitted, unanswered
```

The device never acknowledges the FIN (`ack` stays 125), so the client never sees end-of-stream.
Two more flaws in the same handshake:
- In `CLOSING`, `handleAckEmpty()` treats *any* empty ACK as the final one and removes the
  connection (`:302-307`), including ACKs for data that were still in flight.
- After a remote close, the device's own FIN finds `pendingFinAck == null` and is not answered
  (`handleFinAck`/`handleFin`, `CLOSING` branches), so the device retransmits it.

Observed: every response delimited by connection close hangs until the client's read timeout
(`download-close-*`: all bytes received, then a 30 s timeout). Any protocol in which the server
ends the conversation by closing is affected.

**Recommendation:** send FIN-ACK, and complete the handshake on the ACK that covers our FIN
(PKT-35).

### V-48 — Upstream failures are not signalled to the client (Medium)

- **Connection refused.** When the upstream connect fails, `unwrapInboundConnectable()` calls
  `closeHard()` (`:516-520`), which sends an RST built by `buildRst()` with no ACK flag
  (`:622-624`). The client is still in SYN-SENT, where an RST is only accepted if it
  acknowledges the SYN. Observed: connecting to a closed port fails with a timeout after the
  client's full connect timeout instead of `ECONNREFUSED` at once.
- **Upstream reset.** A read that throws is mapped to end-of-stream (`:461-463`) and then takes
  the FIN path of V-47. Observed: after a server reset mid-response the client waits for its
  read timeout (31 s) instead of seeing a reset.
- **RST answered with RST.** `TransportLayerConnection.getInstance()` answers any packet for an
  unknown flow that has FIN, ACK or RST set with a stray RST (`TransportLayerConnection.kt:353`).
  A reset must never be answered. In one run a single closed flow drew 18 RSTs in a row.

**Recommendation:** build resets that are valid for the client's state, map upstream errors to a
reset, and never answer an RST (PKT-42).

### V-49 — The device's receive window is ignored (High)

`TcpConnection` reads the window once, from the SYN (`:50`), and only to echo it in its own
segments. It never looks at the window the device advertises afterwards, and it never
retransmits (`handleAckEmpty`: "there is no packet loss that would make acknowledgements
useful"). Inbound data is written to the TUN as fast as the upstream delivers it. Once the
client's receive buffer is full, the kernel drops what arrives, and those bytes are gone.

Captured during `slowclient` (a 3 MB download read at a throttled rate):

```
zero-window announcements from the device: 244
data segments the VPN sent while the window was 0: 243
highest byte sent: 3000121, highest byte acknowledged: 787681 → 2.2 MB lost
```

The client stalled after 787 kB and timed out. The full-duplex echo test (`duplex`, 10 MB each
way) stalled the same way at 9.47 MB. Any app that reads slower than its server sends is
affected: media players that buffer, downloads to slow storage, busy main threads.

**Recommendation:** track the device's acknowledgements and window, and stop reading from the
upstream channel while the window is exhausted (PKT-40).

### V-50 — A slow upstream freezes the shared outbound thread (High)

`TcpConnection.wrapOutbound()` writes to the non-blocking upstream channel in a loop until
everything is written (`:215-223`, `:231-243`). When the upstream socket's send buffer is full,
`write()` returns 0 and the loop spins. It runs on `OutboundTrafficHandler`, the one thread that
processes every packet from every app.

Observed (`slowupload`: a 4 MB upload to a server reading 400 kB/s, with small requests on other
connections alongside):
- the upload did not complete within 125 s (10.6 s without the VPN);
- an unrelated request took 30 s and another failed.

The device keeps sending because every segment is acknowledged at once and the advertised
window never changes, so nothing tells it to slow down.

**Recommendation:** queue outbound data per connection, write on `OP_WRITE`, and advertise a
receive window that reflects the queue (PKT-41).

### V-17 revisited — Duplicate segments are processed as new data (High)

V-17 was deferred as needing "an actively hostile or badly-behaved TCP peer". The stress test
shows the trigger is routine: whenever an ACK from the VPN is late (V-51), the device
retransmits, and `handleAckData()` (`:275-290`) forwards the retransmitted bytes as new data and
advances `theirSeqNum` again.

Captured during `tlsparallel` (72 HTTPS requests, 24 at a time):
- 30 of 293 data segments from the device were retransmissions;
- Heimdall logged `DECRYPTION_FAILED_OR_BAD_RECORD_MAC` on client records of connections that
  had decrypted earlier records fine, which is what a replayed TLS record produces;
- 10 to 12 of the 72 requests failed with a connection reset.

On a plaintext connection the same duplicate is forwarded to the server silently, as a repeated
part of the request.

**Recommendation:** accept only the segment that starts at the expected sequence number, and
re-ACK anything else (PKT-38).

### V-51 — Blocking connection setup on the outbound thread delays ACKs (High)

Everything a new connection needs is done on `OutboundTrafficHandler` before the next packet of
any connection is looked at:
- `AppFinder.getAppId()` and `getAppPackage()`: two binder calls
  (`ConnectivityManager.getConnectionOwnerUid`, `PackageManager.getPackagesForUid`);
- `createDatabaseEntity()`: a Room insert inside `runBlocking`
  (`TransportLayerConnection.kt:182-196`);
- `protectSocket()`: a binder call to `VpnService.protect`, then the socket setup.

For plaintext connections the application-layer parsing and the upstream write happen on the
same thread too.

Measured from the `tlsparallel` capture (time from a data segment leaving the device to the
ACK that covers it):

```
median 24 ms, p90 558 ms, p99 779 ms, max 802 ms; over 200 ms: 58 of 256; never acknowledged: 7
```

200 ms is roughly the device's minimum retransmission timeout, so a fifth of the segments were
retransmitted needlessly, which then triggers V-17. The lag also shows at close: ACKs from the
device were still queued when their connection had already been removed, and each was answered
with a stray RST (297 RSTs in that capture).

Which of the steps costs most was **not** measured.

**Recommendation:** measure first, then move the blocking steps off the handler thread (PKT-39).

### V-52 — HTTP bodies with Content-Length are buffered whole (High)

A body that does not fit its first payload is collected in `chunkCache`
(`HttpConnection.kt:227`, `:246`) until it is complete, then joined into one array
(`combineChunks`, `:587`), decoded into a `String`, and only then compared with
`maximumMessageSize` to decide that it is "too large" to store. PKT-32 capped this for chunked
bodies; bodies with `Content-Length` have no cap. The parser sees decrypted HTTPS as well.

Observed:
- **300 MB download** (`bigbody`): Heimdall's Java heap grew from 141 MB to 420 MB, then
  `OutOfMemoryError` in `combineChunks`. The connection was reset 2 kB before the end, so the
  download failed. `InboundTrafficHandler` caught the error this time; an allocation on any
  other thread at that moment would have taken the process down.
- **20 MB upload**: completed, but joining and decoding the body ran on the outbound thread
  with the heap at its limit (`235MB/235MB` in the GC log). No packet of any app was processed
  for the next 10 s; a new connection's SYN went unanswered and the client's connect timed out.

**Recommendation:** count the remaining bytes without keeping them once the cap is exceeded, as
the chunked path does, and keep large-body work off the handler threads (PKT-37).

### V-53 — Socket receive buffers are shrunk to 16 KB (High)

Both transports set the upstream socket's receive buffer to `componentManager.maxPacketSize`
(16413 bytes): `TcpConnection.kt:138`, `UdpConnection.kt:115`. The platform default is far
larger.

- **UDP.** A burst overflows the buffer before the selector thread reads it, and the kernel
  drops the rest. In the paced 500-datagram burst, 234 came back through the VPN against 443
  without it, and `/proc/net/udp6` showed 144 drops on that one Heimdall socket. QUIC is
  exactly this kind of traffic, so passed-through QUIC flows lose packets here.
- **TCP.** The buffer bounds the receive window the upstream server sees. Plain downloads ran at
  6.2 MB/s through the VPN against 13.8 MB/s without it.

**Recommendation:** leave TCP at the platform default and give UDP a large buffer (PKT-34).

### V-54 — Fragmented IP packets are not handled (Medium)

A UDP datagram larger than the TUN's MTU reaches Heimdall as IP fragments. `DevicePollThread`
only forwards packets whose payload parses as TCP or UDP (`DevicePollThread.kt:109-111`), and
nothing reassembles fragments. In the other direction a datagram larger than the MTU is written
to the TUN as one oversized packet.

Observed: UDP echoes of 4000 and 8000 bytes time out through the VPN and work without it; up to
1472 bytes they work. Which direction fails first was not traced. QUIC stays within the MTU by
design; affected are DNS with large EDNS answers, some VoIP/media and game protocols.

**Recommendation:** reassemble outbound fragments and fragment oversized inbound datagrams
(PKT-44).

### V-55 — Throughput is a fraction of the direct path (Medium)

| Transfer | Without VPN | Through VPN |
|---|---|---|
| Plain download, 50 MB | 13.8 MB/s | 6.2 MB/s |
| Plain upload, 20 MB | 12.4 MB/s | 1.6 MB/s |
| TLS download, 25 MB (MitM) | 13.3 MB/s | 7.4 MB/s |

Likely contributors, none measured on its own:
- V-53 for downloads.
- For uploads, every segment is acknowledged individually and triggers its own coroutine and
  database `UPDATE` (`recordBytesOut`, `TransportLayerConnection.kt:245-251`; the same for
  inbound).
- For plain HTTP, `HttpConnection` copies and logs every payload.

**Recommendation:** profile an upload, then batch the byte counters (PKT-43).

### V-56 — Stopping the VPN leaks file descriptors (Medium)

`ComponentManager.stopComponents()` closes the interrupter pipe's read end, stops the threads,
closes the TUN streams and calls `ConnectionCache.closeAllAndClear()`
(`ComponentManager.kt:186-218`). It never closes the `Selector`, and the pipe's write end
(`pipes[1]`, `:106-110`) is never closed either.

Closing a channel that is still registered with a selector does not release its descriptor:
NIO redirects it to `/dev/null` and releases it when the selector next processes its cancelled
keys. With the selector thread stopped and the selector never closed, that never happens.

Observed after the stress session (about a dozen VPN stops, three of them with more than 100
connections open): the Heimdall process held 441 descriptors pointing at `/dev/null`, 63 pipes
and 5 epoll instances, against 17 live sockets. Each stop leaks one descriptor per connection
open at that moment plus the selector's own. The process limit on Android is 32768, so it takes
many cycles to hit, but the VPN restarts on every settings change and network switch.

**Recommendation:** close the selector and both pipe ends on stop (PKT-45).

### Leak check within a running session

No significant leak while the VPN keeps running. Measured on the Heimdall process around a
mixed workload (1500 short connections, UDP tests, 72 TLS requests, client and server aborts,
unreachable destinations):

| | Descriptors | Sockets | Threads |
|---|---|---|---|
| Before | 571 | 17 | 48 |
| Right after | 709 | 125 | 38 |
| 2.5 min later | 683 | 119 | 37 |
| 6.5 min later | 580 | 22 | 36 |

The roughly 100 sockets that linger are UDP flows waiting for the five-minute idle sweep
(PKT-13), which then reaps them. Five sockets were still open at the end. That is within what
connections waiting on an unanswered upstream connect or on a close would explain, but it was
not traced to specific connections. The baseline of 571 descriptors is V-56.

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

### PKT-20 — Replace Netty's `InsecureTrustManagerFactory` with our own; drop `netty-all`

- **Priority:** Low · **Depends on:** —
- **Resolves:** V-32
- **Approach:**
  - Add `mitm/InsecureTrustManager.kt` containing
    `object InsecureTrustManager : X509ExtendedTrustManager()`. All six
    `checkClientTrusted`/`checkServerTrusted` overloads are no-ops: `(chain, authType)`,
    `(…, Socket)` and `(…, SSLEngine)`. `getAcceptedIssuers()` returns `emptyArray()`.
  - It **must** extend `X509ExtendedTrustManager` rather than implement plain
    `X509TrustManager`. JSSE wraps a plain `X509TrustManager` in `AbstractTrustManagerWrapper`,
    which re-applies endpoint identification and algorithm constraints.
    `SSLEngineSource.newSSLEngine(host, port)` sets the endpoint identification algorithm to
    `"HTTPS"` (`SSLEngineSource.kt:99-128`), so a plain trust manager would still reject hostname
    mismatches and would not really trust everything.
  - The kdoc says both of these things, and that the class is only reachable when the user
    enables "Trust all upstream TLS certificates" (PKT-07).
  - In `SSLEngineSource.initialiseSSLContext()` (`:139-146`), replace
    `InsecureTrustManagerFactory.INSTANCE.trustManagers` with `arrayOf(InsecureTrustManager)`.
    Delete the Netty import, the TODO at `:138`, and the commented-out `TrustManagerFactory`
    lines.
  - Remove `libs.netty.all` from `core/vpn/build.gradle.kts` and the `netty`/`netty-all` entries
    from `gradle/libs.versions.toml`. Guava stays, because `SSLEngineSource`'s certificate cache
    uses it.
  - Update the docs that describe Netty: `CLAUDE.md` (module tree and dependency table),
    `docs/ARCHITECTURE.md` (dependency table), `core/vpn/README.md` (trust-all description and
    dependency table) and `docs/quic_mitm.md` (§3.4 and open question 2). Leave the historical
    `docs/implementation-plan.md` alone.
- **Files:** new `mitm/InsecureTrustManager.kt`, `mitm/SSLEngineSource.kt`,
  `core/vpn/build.gradle.kts`, `gradle/libs.versions.toml`, and the docs listed above.
- **Tests:** new `core/vpn/src/test/java/de/tomcory/heimdall/core/vpn/mitm/InsecureTrustManagerTest.kt`:
  - Every check overload accepts an arbitrary self-signed chain without throwing.
  - A real handshake through `CertificateSniffingMitmManager(authority, trustAllServers = true)`
    against `integration/support/FakeTlsServer("example.com")` completes, with the server-facing
    engine created for a **different** peer host (for example `"mismatch.test"`). That covers
    both an untrusted issuer and a hostname mismatch.
  - Negative control: the same handshake with `trustAllServers = false` fails, via
    `MergeTrustManager`.
  - `TlsMitmHttpFlowTest` (trust-all via `ComponentManagerFixtures.kt:71`) and
    `CertificateSniffingMitmManagerTest` must stay green.
  - `./gradlew :app:dependencies | grep -i netty` prints nothing.
- **Commit:** `refactor(vpn): replace Netty InsecureTrustManagerFactory with own X509ExtendedTrustManager, drop netty-all`

### PKT-21 — Name the stray-packet device-write code

- **Priority:** Low · **Depends on:** —
- **Resolves:** V-33
- **Approach:**
  - Add `const val WRITE_STRAY = 2` to the `DeviceWriteThread` companion and use it at
    `TransportLayerConnection.kt:285`, and in the commented-out line at `:279`.
  - Add a kdoc on the companion stating that `what` is informational, for logs and tests only:
    `handleMessageImpl` writes any `IpPacket` whatever its code.
  - Include `msg.what` in the "unknown message type" error log at `DeviceWriteThread.kt:49`.
- **Files:** `components/DeviceWriteThread.kt`, `connection/transportLayer/TransportLayerConnection.kt`.
- **Tests:** no existing test asserts `what == 6` (checked). Add an assertion to an existing
  stray-RST path in `integration/ConnectionTeardownTest.kt` or `MalformedInputRobustnessTest.kt`:
  an unknown ACK/FIN produces a message with `what == DeviceWriteThread.WRITE_STRAY`.
  `ComponentManagerFixtures` already records `.what`.
- **Commit:** `refactor(vpn): replace magic device-write message code 6 with DeviceWriteThread.WRITE_STRAY`

### PKT-22 — Notify the encryption layer when the device closes a TCP connection

- **Priority:** Medium · **Depends on:** —
- **Resolves:** — (enabler for PKT-23, which needs to tell "the app gave up" apart from "the
  server closed")
- **Approach:**
  - Add `open fun onClientClosed() {}` to `EncryptionLayerConnection`, a no-op by default.
  - Add `protected fun notifyClientClosed() { encryptionLayer?.onClientClosed() }` to
    `TransportLayerConnection`.
  - In `TcpConnection`, call it only on the **device-initiated** close paths (an RST from the
    device and the device's first FIN, `TcpConnection.kt:152-166`), before teardown. Do not call
    it on remote-EOF or read-error paths.
  - `TlsConnection.onClientClosed()` dispatches onto `connectionScope`, like `unwrapOutbound`.
    If `closeConnection()` has already cancelled the scope, the launch is dropped. That also
    guards against re-entry via `closeConnection() → transportLayer.closeHard()`. PKT-23 adds
    the body.
- **Files:** `connection/encryptionLayer/EncryptionLayerConnection.kt`,
  `connection/encryptionLayer/TlsConnection.kt`,
  `connection/transportLayer/TransportLayerConnection.kt`,
  `connection/transportLayer/TcpConnection.kt`.
- **Tests:** extend `integration/ConnectionTeardownTest.kt` with a recording
  `EncryptionLayerConnection`. A device FIN and a device RST each produce exactly one
  `onClientClosed()`, and a remote EOF produces none.
- **Commit:** `feat(vpn): notify encryption layer when the device closes a TCP connection`

### PKT-23 — Learn per-session TLS passthrough from client-side handshake failures

- **Priority:** High · **Depends on:** PKT-22, PKT-25 (its integration tests hang without the
  PKT-25 fix); builds on PKT-14's bounded cache
- **Resolves:** V-34
- **Approach:**
  - **Cache** (`metadata/TlsPassthroughCache.kt`, already bounded by PKT-14):
    - Add `enum class PassthroughReason { CLIENT_HANDSHAKE_ERROR, CLIENT_CLOSED_DURING_HANDSHAKE, CLOSED_WITHOUT_DATA }`.
    - Add `fun recordFailure(initiator: Int, hostname: String, reason: PassthroughReason): Boolean`,
      which returns `true` when the pair has just become passthrough.
    - The first two reasons call `put()` straight away.
    - `CLOSED_WITHOUT_DATA` increments a per-pair counter kept in a second bounded access-order
      map, under the same lock and with the same `maxSize`. It calls `put()` when the counter
      reaches `closedWithoutDataThreshold`, a constructor parameter with default 2. The
      threshold exists because preconnects and idle keep-alive connections also close without
      data.
    - `get()`/`put()` keep their signatures. Entries stay per VPN session on `ComponentManager`
      (`ComponentManager.kt:85`); they are deliberately not persisted.
  - **Detection** (`TlsConnection`):
    - Use the same key as the read at `:221`, `(transportLayer.appId, hostname)`, and skip
      recording when `appId == null`.
    - Evaluate the signals only while `doMitm` is true.
    - **(a) Client handshake error:** in `handleUnwrap`'s `SSLException` catch (`:826-832`),
      when `isOutbound && state == CLIENT_HANDSHAKE`, record `CLIENT_HANDSHAKE_ERROR` before
      the existing `null` → `closeConnection()` path.
      - Hook the unwrap rather than the `RecordType.ALERT` branch, because a TLS 1.3 client's
        alert is encrypted (see V-34).
      - Treat any `SSLException` in that state as a rejection, since the message text differs
        between JDK ("Received fatal alert: certificate_unknown") and Conscrypt
        (`…ALERT_UNKNOWN_CA`). Log the message.
    - **(b) Client closed during handshake:** in `onClientClosed()` (PKT-22), record
      `CLIENT_CLOSED_DURING_HANDSHAKE` when `state == CLIENT_HANDSHAKE`.
    - **(c) Closed without data:** add `private var outboundAppBytes = 0L`, incremented where
      `CLIENT_ESTABLISHED` passes unwrapped data to the app layer (`:278-285`). Record
      `CLOSED_WITHOUT_DATA` when `state == CLIENT_ESTABLISHED && outboundAppBytes == 0` and
      either `onClientClosed()` fires or `handleUnwrap` returns `Status.CLOSED` for the
      outbound direction (`:874-878`, the client's close_notify). Put both sites behind one
      `recordPinningSuspect()` helper.
    - When `recordFailure` returns `true`, log it once:
      `Timber.i("tls$id learned passthrough for app=$appPackage host=$hostname ($reason)")`.
    - Nothing else needs to change. The next ClientHello for that pair sets `doMitm = false` at
      `:221` and is passed through raw.
- **Files:** `metadata/TlsPassthroughCache.kt`, `connection/encryptionLayer/TlsConnection.kt`,
  `core/vpn/src/test/.../integration/support/FakeClientTlsDriver.kt` (optional rejecting trust
  manager).
- **Tests:**
  - `metadata/TlsPassthroughCacheTest.kt`:
    - The immediate reasons put at once.
    - `CLOSED_WITHOUT_DATA` puts only on the Nth hit.
    - The counter map is bounded.
  - New `integration/TlsPassthroughLearningTest.kt`, reusing the `TlsMitmHttpFlowTest`
    scaffolding. `ComponentManagerFixtures` already stubs `appId = 1000` and a real
    `TlsPassthroughCache`.
    1. The driver rejects the forged certificate. Assert `cache.get(1000, "example.com")`, and
       that a second connection is **not** intercepted: the driver sees
       `FakeTlsServer.leafCert`.
    2. A ClientHello followed by a device FIN during `CLIENT_HANDSHAKE` sets the cache.
    3. Two handshake-then-close-without-data connections leave the cache unset after the first
       and set after the second.
    4. A normal request/response flow leaves the cache empty.
- **Commit:** `feat(vpn): learn per-session TLS passthrough from client handshake failures and pinning-style closes`

### PKT-24 — Honour the MitM app/host scope preferences

- **Priority:** Medium · **Depends on:** PKT-23 (shares the `TlsConnection.kt:221` decision point)
- **Resolves:** V-35
- **Approach:**
  - **Core type.** `core:vpn` must not depend on `core:datastore-proto`, so add
    `mitm/MitmScope.kt`:
    `data class MitmScope(val includedApps: Set<String>?, val excludedApps: Set<String>, val hostMode: HostMode, val hosts: List<String>)`,
    with `enum class HostMode { ALL, WHITELIST, BLACKLIST }`,
    `fun shouldIntercept(appPackage: String?, hostname: String): Boolean`, and a
    `MitmScope.ALL` default.
    - Host matching reuses `core:util`'s `Trie` with the same `split(".").reversed()` splitter
      as `ComponentManager.trackerTrie`, which gives domain-suffix matching. Build the trie once
      at construction.
  - **Wiring.** Add a `ComponentManager(mitmScope: MitmScope = MitmScope.ALL)` parameter.
    `TlsConnection.kt:221` becomes
    `doMitm && componentManager.mitmScope.shouldIntercept(transportLayer.appPackage, hostname) && !learnedPassthrough`.
  - **App side.**
    - `HeimdallVpnService.launchServiceComponents()` reads `mitmMonitoringScopeApps/Hosts` and
      the four MitM lists.
    - It resolves them with a pure `MitmScopeResolver.resolve(…, systemPackages)` in
      `app/.../service/` and passes the result into `ComponentManager`.
    - Extract the existing system-app query (`HeimdallVpnService.kt:343-360`) into a helper
      shared by the VPN scope and the MitM scope.
  - **Decided (2026-09-30):** `mitm_appLayer_passthrough` is the on/off switch for PKT-23's
    learning (`ComponentManager(learnPassthrough = …)`, default on). The UI label is now "Auto-skip
    MitM on cert rejection". The proto field keeps its historical name for storage compatibility
    and has a comment documenting the new meaning.
  - **Out of scope:** a UI editor for the MitM host lists. Only the app lists are editable today
    (`PreferencesScreen.kt:316-327`).
- **Files:** new `mitm/MitmScope.kt`, `components/ComponentManager.kt`,
  `connection/encryptionLayer/TlsConnection.kt`,
  `app/.../service/HeimdallVpnService.kt`, new `app/.../service/MitmScopeResolver.kt`.
- **Tests:**
  - `core/vpn/src/test/.../mitm/MitmScopeTest.kt`:
    - Each host mode.
    - Subdomain matching, and no false match between `badexample.com` and `example.com`.
    - Included and excluded apps.
    - A `null` `appPackage` is excluded only when an include-list is set.
  - `app/src/test/java/de/tomcory/heimdall/service/MitmScopeResolverTest.kt`: every
    `MonitoringScopeApps` value, with a fake system-package set.
  - An integration case: with `hostMode = BLACKLIST, hosts = ["example.com"]`, a
    `TlsMitmHttpFlowTest`-style flow passes through without interception.
- **Commit:** `feat(vpn): honour MitM app/host monitoring-scope preferences when deciding whether to intercept`

### PKT-25 — Run TLS delegated tasks inline instead of dropping records

- **Priority:** High · **Depends on:** —
- **Resolves:** V-36
- **Approach:**
  - In `TlsConnection.continueHandshake()`'s `NEED_TASK` branch, run all pending delegated tasks
    inline through a new `runDelegatedTasks(engine, direction)` helper, then continue with the
    engine's new handshake status.
    - This is safe because the code already runs confined to `connectionScope`'s single-threaded
      dispatcher. The old launched coroutine ran on the same dispatcher anyway, just later, so
      nothing moves to a different thread.
    - A task that throws closes the connection, as before.
    - If the status is still `NEED_TASK` after running the tasks, close the connection instead
      of recursing.
  - Defensive retry in the `NEED_UNWRAP` branch: if `handleUnwrap` reports 0 bytes consumed with
    `NEED_TASK`, run the tasks and unwrap the same record again rather than losing it.
- **Files:** `connection/encryptionLayer/TlsConnection.kt`.
- **Tests:** new `connection/encryptionLayer/TlsHandshakeDelegatedTaskTest.kt`. It drives a
  `TlsConnection` (with its real dispatcher, since `Dispatchers.Unconfined` hides the race) and
  delivers an in-memory upstream server's entire handshake flight as **one** payload. It asserts
  that the server-facing handshake completes, i.e. the client-facing handshake starts. The test
  fails on the old code.
- **Commit:** `fix(vpn): run TLS delegated tasks inline so multi-record handshake flights aren't dropped`

### PKT-26 — Only classify genuine client Initial datagrams as QUIC

- **Priority:** Medium · **Depends on:** —
- **Resolves:** V-37 · **Phase:** Q0.1 of `docs/quic_mitm.md`
- **Approach:** in `detectQuic()`, keep the long-header and fixed-bit test and additionally
  require:
  - a version other than 0;
  - the Initial packet type: bits `0x30` of byte 0 are `0b01` for QUIC v2 (`0x6b3343cf`) and
    `0b00` for v1 and for unknown versions;
  - a payload of at least 1200 bytes.

  Unknown versions that otherwise look like an Initial stay classified as QUIC; PKT-47 simply
  cannot decrypt them. Replace the comment that justifies the lax check with the new rules.
- **Files:** `connection/encryptionLayer/EncryptionLayerConnection.kt`.
- **Tests:** `ProtocolDetectionTest`:
  - Pad the existing positive cases to 1200 bytes.
  - Version 0 → `false` (the current test asserts `true` and flips).
  - A Handshake-type first packet → `false`.
  - A 1199-byte Initial → `false`.
  - v2 with type `0b01` → `true`, v2 with type `0b00` → `false`.
- **Commit:** `fix(vpn): only classify genuine QUIC client Initial datagrams as QUIC`

### PKT-27 — Persist security protocol, SNI, ALPN and a blocked flag

- **Priority:** Medium · **Depends on:** —
- **Resolves:** V-38 · **Phase:** Q0.2
- **Approach:**
  - **Schema.** New `core/database/.../entity/SecurityProtocol.kt` (`PLAIN, TLS, QUIC`) with a
    converter in `HeimdallTypeConverters`. `Connection` gains:
    - `securityProtocol: SecurityProtocol?` (null until the first payload is classified),
    - `sni: String?`,
    - `alpn: String?` (the client's offer, comma-separated),
    - `echOffered: Boolean = false`,
    - `blocked: Boolean = false`.

    Bump `HeimdallDatabase` to **version 8**. This wipes local data (no migrations by design,
    see PKT-00 in `docs/database-schema-audit.md`), so every column Q1 and Q2 need lands here
    and no later packet bumps the version again. Rewrite `Protocol.kt`'s kdoc, which says the
    opposite.
  - **DAO.** `ConnectionDao.updateSecurity(id, securityProtocol, sni, alpn, echOffered)`,
    `updateHost(id, remoteHost, isTracker)` (used by PKT-28) and `markBlocked(id)` (used by
    PKT-49).
  - **Connector.** `DatabaseConnector.updateConnectionSecurity`, `updateConnectionHost` and
    `markConnectionBlocked`, implemented in `RoomDatabaseConnector` in the style of
    `updateConnectionBytesOut`.
  - **Callers.** `EncryptionLayerConnection` gets a `protected fun persistSecurity(...)` that
    runs asynchronously on `Dispatchers.IO` with the same `id > 0` guard as
    `TransportLayerConnection.recordBytesOut` (DNS flows have id 0 and are skipped).
    `PlaintextConnection` calls it in `init`, `TlsConnection` at the ClientHello with the SNI,
    `QuicConnection` in `init` (PKT-47 adds SNI and ALPN).
  - **UI.** `DatabaseScreen` shows the security protocol, SNI, ALPN and "QUIC blocked" as
    further `ConnectionMetadataRow`s.
- **Files:** `core/database/.../entity/Connection.kt`, new `entity/SecurityProtocol.kt`,
  `entity/Protocol.kt`, `HeimdallTypeConverters.kt`, `HeimdallDatabase.kt`,
  `dao/ConnectionDao.kt`; `components/DatabaseConnector.kt`, `components/RoomDatabaseConnector.kt`,
  `connection/encryptionLayer/{EncryptionLayerConnection,PlaintextConnection,TlsConnection,QuicConnection}.kt`;
  `app/.../ui/database/DatabaseScreen.kt`; `CLAUDE.md` (schema version).
- **Tests:**
  - Extend `RecordingDatabaseConnector` and `RecordedConnection` with the new fields and methods.
  - `TlsMitmHttpFlowTest`: the connection row ends up `TLS` with the SNI.
  - A plaintext HTTP flow ends up `PLAIN`.
- **Commit:** `feat(db,vpn): persist security protocol, SNI and ALPN per connection`

### PKT-28 — Let the SNI correct the hostname and tracker label

- **Priority:** Medium · **Depends on:** PKT-27
- **Resolves:** V-39 · **Phase:** Q0.3
- **Approach:**
  - In `TransportLayerConnection`, make `remoteHost` a `@Volatile var` with a private setter and
    `isTracker` mutable, and add `fun refineRemoteHost(sni: String, echOffered: Boolean)`:
    - No-op if the SNI equals the current name.
    - If `echOffered` and a DNS-derived name already exists, keep the DNS name. With real ECH
      the outer SNI is only the provider's public name. Chrome also sends a GREASE ECH
      extension on ordinary connections, where SNI and DNS name agree anyway, so the extension
      alone cannot tell the two cases apart.
    - Otherwise set the name, recompute `componentManager.labelConnection(...)` and persist
      both through `updateConnectionHost`.
  - `TlsConnection.handleOutboundRecord()` calls it where it assigns `hostname` from `findSni`.
    ECH detection for TLS arrives with PKT-29; until then pass `echOffered = false`.
- **Files:** `connection/transportLayer/TransportLayerConnection.kt`,
  `connection/encryptionLayer/TlsConnection.kt`.
- **Tests:** new `connection/transportLayer/RemoteHostRefinementTest.kt`, built on
  `ComponentManagerFixtures`:
  - A DNS-derived name is replaced by a differing SNI and the row is updated.
  - The tracker label flips when the SNI is a tracker host and the DNS name was not.
  - A missing DNS name is filled from the SNI even when ECH is offered.
  - An existing DNS name survives when ECH is offered.
- **Commit:** `feat(vpn): refresh a connection's hostname and tracker label from the SNI`

### PKT-29 — Extract a ClientHello parser shared by TLS and QUIC

- **Priority:** Medium · **Depends on:** —
- **Resolves:** — (enabler for PKT-47; also gives the TLS path ALPN and ECH detection)
- **Approach:**
  - New `connection/encryptionLayer/ClientHelloParser.kt`. It parses a bare TLS handshake
    message (type 1, 24-bit length; no record header) into
    `ClientHelloInfo(sni: String?, alpn: List<String>, echOffered: Boolean, supportedVersions: List<Int>)`.
    Extensions read: `server_name` (0), ALPN (16), `supported_versions` (43),
    `encrypted_client_hello` (`0xfe0d`). Every length is bounds-checked; malformed input returns
    `null` instead of throwing.
  - `TlsConnection.findSni()` hardcodes offset 43 into a *record*. Keep its signature, strip the
    5-byte record header and delegate. `TlsConnection` then passes ALPN and `echOffered` to
    `persistSecurity` and `refineRemoteHost` when PKT-27/PKT-28 are in.
- **Files:** new `connection/encryptionLayer/ClientHelloParser.kt`,
  `connection/encryptionLayer/TlsConnection.kt`.
- **Tests:** new `ClientHelloParserTest`: SNI only; several ALPN entries; ECH extension present;
  no SNI; truncated at every extension boundary. The existing `findSni` cases in
  `TlsRecordHandlingTest` must stay green unchanged.
- **Commit:** `refactor(vpn): extract a ClientHello parser shared by TLS and QUIC`

### PKT-30 — Support client-side TCP half-close

- **Priority:** Medium · **Depends on:** —
- **Resolves:** V-42
- **Approach:**
  - **State.** Add `TransportLayerState.HALF_CLOSED`: the device has finished sending, the
    remote may still send.
  - **Device FIN in `CONNECTED`.** In `handleFin()`: advance `theirSeqNum`, answer with a plain
    ACK, call `selectableChannel.shutdownOutput()` (available on API 24) instead of closing the
    channel, and move to `HALF_CLOSED`. Keep the `notifyClientClosed()` call.
  - **While `HALF_CLOSED`.**
    - Inbound data keeps flowing through `unwrapInboundReadable()` and `wrapInbound()`.
    - Empty ACKs from the device are ignored (`handleAckEmpty`).
    - A retransmitted FIN is ACKed again without advancing sequence numbers.
    - Data from the device is a protocol violation and takes the existing `closeHard()` path
      in `handleAckData`.
  - **Remote EOF while `HALF_CLOSED`.** Send our FIN-ACK, keep it in `pendingFinAck`, move to
    `CLOSING`. The device's final ACK completes the close through the existing `CLOSING` branch
    of `handleAckEmpty`.
  - **Only where the encryption layer can carry it.** Add
    `EncryptionLayerConnection.supportsHalfClose` (default `true`); `TlsConnection` returns
    `!doMitm`. A MitM'd TLS connection keeps today's full close. Mapping a half-close onto two
    separate TLS sessions is out of scope.
  - **Bound it.** Record when a connection entered `HALF_CLOSED` and reap connections that
    have been there for more than two minutes, from `ComponentManager`'s existing 30-second
    sweep job next to `UdpConnection.sweepIdleConnections`.
- **Files:** `connection/transportLayer/TransportLayerConnection.kt`,
  `connection/transportLayer/TcpConnection.kt`,
  `connection/encryptionLayer/EncryptionLayerConnection.kt`,
  `connection/encryptionLayer/TlsConnection.kt`, `components/ComponentManager.kt`,
  `scripts/emulator-traffic.sh`.
- **Tests:**
  - `integration/ConnectionTeardownTest.kt`, against a local `ServerSocket` that reads to EOF
    and only then replies:
    - The reply reaches the device after its FIN, followed by our FIN-ACK; the device's final
      ACK removes the connection from the cache.
    - A retransmitted FIN in `HALF_CLOSED` is ACKed again and nothing else changes.
    - A server that never closes is reaped by the sweep.
    - A MitM'd TLS connection still closes fully on the device's FIN.
  - The existing `graceful FIN close writes only a FIN-ACK, not an RST` and retransmitted-FIN
    tests change to the new sequence (ACK first, FIN-ACK after the remote closes).
  - Script: make the hold time overridable (`HEIMDALL_HOLD_OPEN=0`) and add one request to the
    `http` group that half-closes right after sending. On the emulator it must get its response.
- **Commit:** `fix(vpn): keep a TCP connection open for the response after the client half-closes`

### PKT-31 — Handle a client alert that precedes the client-facing TLS handshake

- **Priority:** Low · **Depends on:** —
- **Resolves:** V-43
- **Approach:** in `handleOutboundRecord()`, when an `ALERT` arrives in a state without a
  client-facing engine (`NEW`, `SERVER_HANDSHAKE`, `SERVER_ESTABLISHED`), do not call
  `handleUnwrap`. The alert is plaintext at that point, so:
  - read its level and description from the record and log them at debug level;
  - close the connection without sending an RST to the client;
  - do not count it toward passthrough learning. No certificate has been presented yet, so the
    alert says nothing about whether the app accepts the forged one.

  Later states keep the existing path.
- **Files:** `connection/encryptionLayer/TlsConnection.kt`.
- **Tests:** `TlsRecordHandlingTest`:
  - A ClientHello followed by `close_notify` in one payload closes the connection, never
    touches the client-facing engine and records no passthrough failure.
  - The same for a fatal alert while the server-facing handshake is running.
  - Script: once this is in, `make_client_hello` no longer has to strip the trailing alert.
    Keep one `tls` case that sends it.
- **Found while implementing (2026-10-01):** `closeSession(isClientFacing = false)` wrapped the
  server-facing close message with the **client-facing** engine, because it always called
  `handleWrap(isOutbound = false, …)` and `handleWrap` picks its engine from that flag. Two
  effects:
  - Before the client-facing engine exists, the wrap returned `null`, which re-entered
    `closeConnection()` and reset the client. This is what kept an early alert during the
    server-facing handshake from closing cleanly, so it is fixed in this packet.
  - In every other close, the upstream server never received a `close_notify` from the
    server-facing session. It now does.
- **Implementation notes:** the transport layer is left open after an early alert, and the
  client's following FIN closes it (a full close, since a MitM'd connection cannot half-close,
  PKT-30). If the client never sends a FIN, the connection ends when the upstream gives up on the
  abandoned handshake.
- **Commit:** `fix(vpn): close cleanly on a client alert that precedes the client-facing TLS handshake`

### PKT-32 — Detect the end of chunked HTTP messages correctly

- **Priority:** High · **Depends on:** —
- **Resolves:** V-44
- **Approach:**
  - Replace the CRLF-split heuristic with a walk over the declared chunk sizes, the logic
    `dechunkHttpMessage()` already uses. Extract it into
    `chunkedBodyEnd(bytes: ByteArray, bodyStart: Int): Int?`. It returns the offset just past
    the terminating zero-size chunk and its trailer section, or `null` while the body is
    incomplete.
  - Call it after every payload while `state.chunked`, **including the first one**.
  - On completion, persist the message. Bytes after the end belong to the next message on a
    keep-alive connection: feed them back into `handleData`.
  - Cap the cached size at `maximumMessageSize`. Beyond the cap, persist with the existing
    "too large" marker and stop caching, but keep tracking chunk boundaries so the end of the
    message is still found.
- **Files:** `connection/appLayer/HttpConnection.kt`.
- **Tests:** `HttpParsingTest`:
  - A chunked response complete in a single payload.
  - The terminator `0\r\n\r\n` arriving in its own payload.
  - The terminator split across payloads as `0\r\n` and `\r\n`.
  - A trailer section after the zero chunk.
  - Two chunked responses back to back on one connection, each paired with its own request.
  - A body larger than the cap.
  - The existing test that feeds only `0\r\n` is corrected to send a real terminator.
  - Device check: in the traffic script's report, `GET http://example.com/` shows status 200.
- **Commit:** `fix(vpn): complete chunked HTTP messages on the real terminator, including single-payload ones`

### PKT-33 — Stop the HTTP parser stalling on bodiless and close-delimited responses

- **Priority:** Medium · **Depends on:** PKT-32 (same function)
- **Resolves:** V-45
- **Approach:**
  - **Reproduce first.** Write both cases of V-45 as failing unit tests. If one does not
    reproduce, drop its bullet and correct V-45.
  - **No body by definition.** Carry the request method alongside each entry in
    `pendingRequestIds`. For an inbound message, treat the body as absent when the pending
    request is `HEAD` or the status code is 1xx, 204 or 304, whatever the headers state.
  - **Body until close.** For a response with neither `Content-Length` nor chunked encoding,
    persist the headers and the bytes at hand as today, mark the inbound direction "body until
    close", and from then on forward payloads without parsing or caching them. The stored body
    stays truncated; the unbounded buffer goes away.
- **Files:** `connection/appLayer/HttpConnection.kt`.
- **Tests:** `HttpParsingTest`:
  - A `HEAD` response with `Content-Length` is persisted, and so is the next response on the
    same connection.
  - The same for a 304 with `Content-Length`.
  - A close-delimited response followed by ten more payloads is persisted once and leaves no
    growing buffer.
- **Commit:** `fix(vpn): handle HTTP responses without a body and bodies delimited by connection close`

- **Implementation notes (2026-10-01):** both cases of V-45 reproduced as failing tests. Beyond
  the approach above, the same change also:
  - skips interim responses (100, 102, 103) without using up the pending request;
  - treats `101 Switching Protocols` and a successful `CONNECT` as the end of HTTP on the
    connection, in both directions;
  - splits a payload at the end of a `Content-Length` body, so a message that follows in the
    same payload is parsed on its own;
  - treats a request with neither `Content-Length` nor chunked encoding as having no body, so
    pipelined requests in one payload are recorded separately;
  - stops collecting bytes once 64 KB have arrived without the end of a header block.

### PKT-34 — Stop shrinking the upstream sockets' receive buffers

- **Priority:** High (trivial) · **Depends on:** —
- **Resolves:** V-53
- **Approach:**
  - `TcpConnection.openChannel()`: remove the `receiveBufferSize` line and leave the kernel's
    default and autotuning in place.
  - `UdpConnection.openChannel()`: request a large receive buffer (start with 1 MB; the kernel
    caps it at `rmem_max`) instead of `maxPacketSize`.
  - `inBuffer` stays at `maxPacketSize`; it only bounds one read.
- **Files:** `connection/transportLayer/TcpConnection.kt`, `connection/transportLayer/UdpConnection.kt`.
- **Tests:** a unit test that the opened channels' `receiveBufferSize` is not below the
  platform default (TCP) and at least 256 KB (UDP). Device: `run-stress.sh udp` — the burst
  comes back at about the rate measured without the VPN, and `/proc/net/udp6` shows no drops on
  Heimdall's sockets; `run-stress.sh download` — note the 50 MB rate before and after.
- **Result on the emulator (2026-10-01):**

  | | Before | After | Without VPN |
  |---|---|---|---|
  | UDP burst, datagrams echoed of 500 | 58 to 234 | 438 to 500 (four runs) | 443 |
  | Plain download, 50 MB | 6.2 MB/s | 7.5 MB/s | 13.8 MB/s |
  | TLS download, 25 MB (MitM) | 7.4 MB/s | 9.8 MB/s | 13.3 MB/s |

  The emulator's kernel caps the UDP request at 524 KB (`rmem_max` is 262144, doubled by the
  kernel). 70 datagrams were still dropped across three bursts, on two sockets: a burst can
  still outrun the selector thread, only far less often. The download gain is smaller than
  V-53 suggested, so the receive buffer was one contributor to V-55, not the main one.
- **Commit:** `fix(vpn): stop shrinking upstream socket receive buffers to 16 KB`

### PKT-35 — Make the remote-initiated close reach the client

- **Priority:** High · **Depends on:** —
- **Resolves:** V-47
- **Approach:**
  - On remote end-of-stream in `CONNECTED`, send a FIN-ACK (`buildFinAck()`), remember the
    sequence number that acknowledges it (`finSeq + 1`), and keep the segment in
    `pendingFinAck` for retransmission. Remove `buildFin()`.
  - In `CLOSING`, `handleAckEmpty()` only completes the close when the ACK number covers our
    FIN. Earlier ACKs are ignored.
  - A FIN from the device in `CLOSING` after a remote close is acknowledged (advance
    `theirSeqNum`, send an ACK); if it also covers our FIN, the connection is done. The existing
    retransmission of `pendingFinAck` stays for the device-initiated close.
  - Bound the wait: a connection that stays `CLOSING` for more than 30 s is removed by the
    sweep that PKT-30 added.
- **Files:** `connection/transportLayer/TcpConnection.kt`, `components/ComponentManager.kt`.
- **Tests:** `ConnectionTeardownTest`:
  - The segment sent on remote close has FIN and ACK set.
  - An ACK below our FIN's sequence number does not close the connection; the one that covers
    it does.
  - The device's FIN after a remote close is acknowledged and nothing is retransmitted.
  - Device: `run-stress.sh download` — the `download-close-*` checks pass.
- **Implementation notes (2026-10-01):**
  - The handshake is complete once the device has acknowledged our FIN **and** sent its own;
    the two are tracked separately because either can come first.
  - Deviation: a connection stuck in `CLOSING` is dropped after two minutes, not 30 s, and
    without a reset. Its upstream channel is already closed, so the entry costs nothing, and an
    app may legitimately keep its side open for a while (connection pools do).
  - `sweepHalfClosedConnections` became `sweepStaleConnections` and covers both states.
  - On the emulator all `download-close-*` checks pass, and a capture shows
    `[F.] seq 125` from the VPN, `[F.] ack 126` from the device and the final `ack 46`.
    `serverabort-rst` passes as well, because the client now sees the end of the stream; it is
    still a FIN where a reset would be right (PKT-42).
- **Commit:** `fix(vpn): send FIN-ACK on remote close and complete the closing handshake correctly`

### PKT-36 — Deliver queued inbound data before passing a remote close on to the device

- **Priority:** High · **Depends on:** PKT-35 (same end-of-stream branch; its FIN-ACK is what gets deferred)
- **Resolves:** V-46
- **Approach:**
  - **Reproduce first.** An integration test in the style of `TlsMitmHttpFlowTest` whose fake
    upstream writes its response and closes the socket at once. Assert that the device receives
    the complete decrypted response *before* the FIN, that the FIN's sequence number follows
    the last data byte, and that the response is persisted. It should fail on the current code;
    slow the connection's dispatcher down in the test if the race needs help.
  - **Hook.** Add `EncryptionLayerConnection.onRemoteClosed(deliverClose: () -> Unit)`. The
    default calls `deliverClose` straight away, which keeps today's behaviour for plaintext and
    QUIC. `TlsConnection` launches it on `connectionScope`, so it runs after every inbound
    payload that was enqueued before the end-of-stream.
  - **Transport.** In `TcpConnection.unwrapInboundReadable()`, on end-of-stream, close the
    channel as today but hand the rest (state change, FIN or FIN-ACK, cache removal) to the
    encryption layer as `deliverClose`. That block keeps running under `closeLock`. If there is
    no encryption layer yet, run it directly.
  - **If the TLS connection has already closed itself**, `connectionScope` is cancelled and the
    launch is dropped. That path has already called `transportLayer.closeHard()`, so nothing is
    left to deliver.
  - A passed-through TLS connection (`doMitm == false`) forwards synchronously but still goes
    through `connectionScope`, so it needs the same ordering.
- **Files:** `connection/encryptionLayer/EncryptionLayerConnection.kt`,
  `connection/encryptionLayer/TlsConnection.kt`, `connection/transportLayer/TcpConnection.kt`.
- **Tests:** the reproduction above; the same for a half-closed connection (PKT-30), where the
  close is a FIN-ACK; `ConnectionTeardownTest` and `TcpHalfCloseTest` stay green. Device check:
  in the traffic script's report, no decrypted request of the `apps` group is left without a
  status because its connection closed, and logcat shows no
  `Resetting unknown TCP packet (ACK)` directly after a `CONNECTED -> CLOSING` transition.
- **Implementation notes (2026-10-01):**
  - The new `TlsRemoteCloseOrderingTest` reproduced the bug for MitM'd and for passed-through
    TLS before the fix, without slowing the dispatcher down.
  - The hook alone fixed passed-through TLS. MitM'd connections needed a second change: on the
    server's `close_notify`, `TlsConnection` called `closeConnection()`, which first tried to
    answer the server on a channel that was already closed (the write failed and reset the
    client) and only then sent the client-facing `close_notify`. It now ends the client-facing
    session with `close_notify`, does not answer the server, and leaves the TCP close to the
    transport layer, so the client sees data, `close_notify`, FIN-ACK in that order.
  - If the TLS connection has cancelled its scope, the queued close is delivered from the
    job's completion handler; `deliverRemoteClose()` is idempotent and does nothing once the
    transport has been torn down.
  - On the emulator `run-stress.sh tlsclose` went from 3 of 40 to 40 of 40, and the
    `stackoverflow.com` check (a 403 followed by a close) passes.
- **Commit:** `fix(vpn): deliver decrypted inbound data to the device before the remote close`

- **Stress-test evidence (2026-10-01):** with `Connection: close`, 37 of 40 HTTPS responses
  through the MitM were lost (`run-stress.sh tlsclose`); all 40 arrive without the VPN. That
  test is the device check for this packet.

### PKT-37 — Stop buffering whole HTTP bodies that have a Content-Length

- **Priority:** High · **Depends on:** —
- **Resolves:** V-52
- **Approach:**
  - Give the `Content-Length` path the cap PKT-32 gave the chunked path: once the cached bytes
    of a message exceed `maximumMessageSize`, drop the cache, keep only the header bytes, and
    just count down `remainingContentLength`. At the end persist with the `<too large: N bytes>`
    marker and the real length.
  - A body whose `Content-Length` already exceeds the cap is never cached at all.
  - `persistMessage` must not be handed megabytes: with the cap in place the largest string it
    sees is `maximumMessageSize`.
- **Files:** `connection/appLayer/HttpConnection.kt`.
- **Tests:** `HttpParsingTest`: a 5 MB response and a 5 MB request with `Content-Length`,
  delivered in 16 KB payloads, are persisted with the marker and the correct length while the
  bytes held by the parser never exceed the cap (reflection helper from PKT-33); the message
  after them on the same connection is parsed. Device: `run-stress.sh bigbody` passes and
  Heimdall's Java heap stays flat; `run-stress.sh upload,keepalive` shows no connect timeout
  after the 20 MB upload.
- **Commit:** `fix(vpn): cap the memory used for HTTP bodies that have a Content-Length`

### PKT-38 — Accept only in-order segments from the device

- **Priority:** High · **Depends on:** —
- **Resolves:** V-17
- **Approach:** in `TcpConnection.unwrapOutbound()`, before a data segment is handled:
  - If its sequence number equals `theirSeqNum`, process it as today.
  - If it lies entirely below `theirSeqNum` (a retransmission), do not forward it; answer with
    an ACK for `theirSeqNum`.
  - If it overlaps, forward only the part from `theirSeqNum` on.
  - If it lies above (a gap), drop it and answer with an ACK for `theirSeqNum`, which makes the
    device retransmit from there. No reordering buffer.
  - Compare with 32-bit wrap-around in mind. The same check applies to a FIN.
- **Files:** `connection/transportLayer/TcpConnection.kt`.
- **Tests:** new `TcpSegmentValidationTest` against a local `ServerSocket`: a duplicated
  segment, an overlapping one, an out-of-order pair and a wrap-around case each deliver the
  byte stream to the server exactly once and in order. Device: `run-stress.sh tlsparallel` — no
  `BAD_RECORD_MAC` lines in logcat.
- **Commit:** `fix(vpn): drop retransmitted and out-of-order segments from the device instead of forwarding them`

### PKT-39 — Take blocking connection setup off the outbound handler thread

- **Priority:** High · **Depends on:** PKT-38 (until then late ACKs corrupt streams)
- **Resolves:** V-51
- **Approach:**
  - **Measure first.** Wrap the steps of connection creation (`getAppId`, `getAppPackage`,
    `createDatabaseEntity`, `protectSocket`, `connect`) in timing logs, run
    `run-stress.sh tlsparallel` and record the numbers here. Fix what the numbers point at;
    the items below are the expected outcome.
  - Allocate connection IDs in memory (an `AtomicLong` seeded from the highest stored ID at
    start-up) and insert the row asynchronously, so no `runBlocking` remains on the handler.
    `DatabaseConnector.persistTransportLayerConnection` then takes the ID as a parameter.
  - Cache the UID-to-package lookup.
  - Resolve the app asynchronously and patch it into the row when known, if
    `getConnectionOwnerUid` turns out to be the slow step. `TlsConnection` needs the package
    for the MitM scope decision, which it takes at the ClientHello, so it must wait for the
    lookup there.
- **Files:** `connection/transportLayer/TransportLayerConnection.kt`, `TcpConnection.kt`,
  `UdpConnection.kt`, `components/DatabaseConnector.kt`, `components/RoomDatabaseConnector.kt`,
  `core/util/.../AppFinder.kt`.
- **Tests:** existing suites stay green with the ID change. Device: rerun the capture analysis
  from V-51 with `scripts/stress/tcp-capture-stats.py` — p90 time-to-ACK under `tlsparallel`
  below 50 ms and no retransmissions from the device.
- **Commit:** `perf(vpn): keep database inserts and binder calls off the outbound packet thread`

### PKT-40 — Respect the device's receive window

- **Priority:** High · **Depends on:** PKT-35 (the close must wait for unsent data too)
- **Resolves:** V-49
- **Approach:**
  - Parse the window-scale option from the device's SYN and offer none ourselves unless we
    honour it (today's SYN-ACK carries no options, so the device's scale is in effect only for
    what it advertises; verify in a capture).
  - Track, per connection, the highest ACK from the device and its current window. The bytes
    we may still send are `lastAck + window - nextSeq`.
  - `unwrapInboundReadable()` reads at most that many bytes. When the budget is zero, clear
    `OP_READ` on the upstream key; an ACK or window update from the device restores it. Selector
    interest changes go through `selectorMonitor` as the registrations do.
  - Answer zero-window probes from the device with an ACK.
  - Because the TUN does not lose packets, staying inside the window makes retransmission
    unnecessary. State that assumption in the code.
  - The encryption layer sits between read and write: for TLS the plaintext is re-encrypted, so
    the budget has to be applied to what `wrapInbound()` emits. Bytes already read but not yet
    sendable are queued per connection (bounded by the read budget).
- **Files:** `connection/transportLayer/TcpConnection.kt`, `TransportLayerConnection.kt`.
- **Tests:** an integration test with a device side that advertises a small window and opens it
  step by step: nothing is sent beyond the window, everything arrives in order, the upstream is
  not read while the window is closed. Device: `run-stress.sh slowclient,duplex` pass.
- **Commit:** `fix(vpn): honour the device's TCP receive window instead of sending regardless`

### PKT-41 — Queue outbound data per connection and apply backpressure

- **Priority:** High · **Depends on:** PKT-38, PKT-40 (shares the selector-interest handling)
- **Resolves:** V-50
- **Approach:**
  - `wrapOutbound()` writes what the channel takes. What is left goes into a per-connection
    queue, and `OP_WRITE` is set; `InboundTrafficHandler` drains the queue when the channel is
    writable. No loop that waits for the channel.
  - The window we advertise to the device is the free space of that queue (bounded, e.g.
    256 KB), so a slow upstream slows the app down instead of the handler thread. Segments that
    arrive beyond it are dropped and re-ACKed, as in PKT-38.
  - A half-close (PKT-30) and a close wait until the queue is drained.
  - The same for `UdpConnection.wrapOutbound()`: a datagram the channel does not take is
    dropped, not retried in a loop.
- **Files:** `connection/transportLayer/TcpConnection.kt`, `UdpConnection.kt`,
  `components/InboundTrafficHandler.kt`.
- **Tests:** an integration test with an upstream that does not read: the handler thread
  returns from `unwrapOutbound()` promptly, the advertised window shrinks to zero, and the data
  arrives intact once the upstream reads. Device: `run-stress.sh slowupload` passes both checks.
- **Commit:** `fix(vpn): queue outbound data per connection instead of busy-waiting on a slow upstream`

### PKT-42 — Signal upstream connect failures and resets to the client

- **Priority:** Medium · **Depends on:** PKT-35
- **Resolves:** V-48
- **Approach:**
  - A reset for a client still in its handshake (our state `CONNECTING`) is an RST-ACK with
    sequence number 0 and `ack = theirInitSeqNum + 1`. In every other state keep sequence
    number `ourSeqNum`, and set the ACK flag as well.
  - An `IOException` while reading from the upstream (other than a clean end-of-stream) closes
    with a reset instead of a FIN.
  - `TransportLayerConnection.getInstance()` does not answer packets that have RST set.
- **Files:** `connection/transportLayer/TcpConnection.kt`, `TransportLayerConnection.kt`.
- **Tests:** `ConnectionTeardownTest`: a refused upstream connect produces an RST-ACK that
  acknowledges the SYN; an upstream reset produces an RST, not a FIN; an RST for an unknown
  flow draws no reply. Device: `run-stress.sh unreachable,serverabort` pass.
- **Commit:** `fix(vpn): reset the client correctly when the upstream refuses or resets the connection`

### PKT-43 — Find and remove the upload bottleneck

- **Priority:** Medium · **Depends on:** PKT-34, PKT-39, PKT-41
- **Resolves:** V-55
- **Approach:**
  - Profile a 20 MB plain upload on the emulator (method tracing or simpleperf on the outbound
    handler thread) after the packets above are in, and record where the time goes.
  - Expected: batch the byte counters. Accumulate `bytesOut`/`bytesIn` per connection in
    memory and flush at most once a second and at close, instead of one coroutine and one
    `UPDATE` per segment.
  - Demote the per-payload `Timber.d` lines in `HttpConnection` to a debug flag.
- **Files:** `connection/transportLayer/TransportLayerConnection.kt`,
  `connection/appLayer/HttpConnection.kt`.
- **Tests:** byte counters in `RecordingDatabaseConnector` still match the bytes transferred
  after close. Device: record `run-stress.sh download,upload,tlsbulk` rates in the V-55 table.
- **Commit:** `perf(vpn): batch per-connection byte counter updates`

### PKT-44 — Handle UDP datagrams larger than the MTU

- **Priority:** Low · **Depends on:** —
- **Resolves:** V-54
- **Approach:**
  - Trace first which direction fails and what the server receives today.
  - Outbound: collect IPv4 fragments by (source, destination, identification, protocol) in
    `DevicePollThread`, with a short timeout and a size cap, and reassemble them with pcap4j's
    `IpV4Helper.defragment` before the packet goes to the handler.
  - Inbound: split datagrams larger than the TUN's MTU with `IpV4Helper.fragment`.
- **Files:** `components/DevicePollThread.kt`, `connection/transportLayer/UdpConnection.kt`,
  `connection/inetLayer/IpV4PacketBuilder.kt`.
- **Tests:** unit tests for reassembly (in order, out of order, incomplete set times out) and
  for inbound fragmentation. Device: `run-stress.sh udp` — the 4000- and 8000-byte echoes pass.
- **Commit:** `feat(vpn): reassemble and fragment UDP datagrams larger than the MTU`

### PKT-45 — Release the selector and pipe descriptors when the VPN stops

- **Priority:** Medium · **Depends on:** —
- **Resolves:** V-56
- **Approach:** in `ComponentManager.stopComponents()`, after the handler threads have stopped
  and `ConnectionCache.closeAllAndClear()` has run, call `selector.close()`, which deregisters
  every key and releases the channels' descriptors. Keep both ends of the interrupter pipe and
  close both. Join `InboundTrafficHandler` before closing the selector, so it is not inside
  `select()` at that moment (this also resolves V-28).
- **Files:** `components/ComponentManager.kt`, `components/InboundTrafficHandler.kt`.
- **Tests:** an instrumentation-free check is hard here (`ComponentManager` needs `Os.pipe`).
  Device: note `ls /proc/<pid>/fd | wc -l`, start and stop the VPN ten times with
  `run-stress.sh parallel` running, and compare; `run-stress.sh` prints the count before and
  after each run.
- **Commit:** `fix(vpn): close the selector and the interrupter pipe when the VPN stops`

**Order for PKT-30 to PKT-45:** PKT-30 to PKT-33 are done. The rest are numbered in the order
they should be done. PKT-34 is a two-line change with a large effect. PKT-35 to PKT-38 each fix
a failure that real traffic hits today. PKT-39 to PKT-41 rework how the transport paces itself
and are the larger pieces. PKT-42 to PKT-45 can follow in any order. All of them come before the
QUIC packets (PKT-46 to PKT-49): passed-through and blocked QUIC both rely on the UDP path and
on a TLS fallback that works.

### PKT-46 — Decrypt QUIC v1/v2 client Initial packets

- **Priority:** Medium · **Depends on:** —
- **Resolves:** — (enabler for PKT-47) · **Phase:** Q1, part 1
- **Approach:** new package `quic/`. Plain JCA only (`Mac "HmacSHA256"`, `AES/ECB/NoPadding`,
  `AES/GCM/NoPadding`), all available on API 24. No new dependency.
  - `QuicVarInt.kt`: variable-length integer decoding (RFC 9000 §16).
  - `QuicInitialKeys.kt`: HKDF-Extract and HKDF-Expand-Label, and the client Initial `key`,
    `iv` and `hp` for a given version and Destination Connection ID.
    - v1: salt `38762cf7f55934b34d179ae6a4c80cadccbb7f0a`, labels `quic key`, `quic iv`,
      `quic hp`.
    - v2 (RFC 9369 §3.3): its own salt, labels `quicv2 key`, `quicv2 iv`, `quicv2 hp`.
  - `QuicInitialPacket.kt`: parse one long-header packet at an offset in a datagram (version,
    DCID, SCID, token, length, packet-number offset), remove header protection, AEAD-decrypt
    and return the plaintext payload plus the number of bytes consumed, so a caller can iterate
    coalesced packets. Failures are a typed result (unknown version, not an Initial,
    authentication failed, malformed); nothing throws.
- **Files:** new `quic/QuicVarInt.kt`, `quic/QuicInitialKeys.kt`, `quic/QuicInitialPacket.kt`.
- **Tests:** pure JVM, raw byte arrays as in the existing packet tests.
  - `QuicInitialKeysTest`: RFC 9001 Appendix A.1 and RFC 9369 Appendix A key vectors.
  - `QuicInitialPacketTest`: the protected client Initial of RFC 9001 Appendix A.2 decrypts to
    the listed payload; the same for RFC 9369; a flipped ciphertext byte yields "authentication
    failed"; a truncated header yields "malformed".
  - New test helper `integration/support/QuicInitialFixtures.kt` that *protects* a given
    ClientHello into Initial datagrams, optionally split over two packets and with shuffled
    CRYPTO frames. Validate it by reproducing the RFC 9001 A.2 packet. PKT-47 and PKT-49 use it.
- **Commit:** `feat(vpn): decrypt QUIC v1/v2 client Initial packets`

### PKT-47 — Record SNI and ALPN of QUIC flows from the Initial packet

- **Priority:** Medium · **Depends on:** PKT-26, PKT-27, PKT-28, PKT-29, PKT-46
- **Resolves:** V-40 · **Phase:** Q1, part 2
- **Approach:**
  - New `quic/QuicInitialInspector.kt`, one instance per flow. `offer(datagram)` returns
    `Pending`, `Complete(ClientHelloInfo, quicVersion)` or `GaveUp(reason)`.
    - Derive keys from the DCID of the first Initial and keep them. Later client Initials carry
      a different DCID field once the server has answered, but the keys do not change.
    - If authentication fails and the packet's DCID differs from the first one, try once with
      that DCID and adopt it on success. This covers a server Retry.
    - Iterate coalesced packets; skip everything that is not an Initial.
    - Skip PADDING, PING and ACK frames. Collect CRYPTO frames by offset. Complete when
      `[0, handshakeLength)` is contiguous, then call `ClientHelloParser`. Do not assume one
      packet or ordered frames: hybrid key shares push the ClientHello over one datagram, and
      Chrome shuffles CRYPTO frames deliberately.
    - Limits: 4 datagrams and a 16 KB reassembly buffer, then `GaveUp`.
  - `QuicConnection`: feed each outbound datagram to the inspector until it is terminal.
    **Forward the datagram unchanged first, then inspect**, so inspection can never delay or
    alter traffic (PKT-49 changes this order only under the Block policy). On `Complete`, call
    `persistSecurity(QUIC, sni, alpn, echOffered)` and `transportLayer.refineRemoteHost(...)`.
    The inspector is touched only from the outbound handler thread. Remove the `//TODO`
    placeholders this replaces; keep the unconditional `doMitm = false`.
- **Files:** new `quic/QuicInitialInspector.kt`, `connection/encryptionLayer/QuicConnection.kt`.
- **Tests:**
  - `QuicInitialInspectorTest`: single-packet ClientHello; ClientHello over two datagrams;
    shuffled CRYPTO frames with PING and PADDING between them; an unknown version and random
    bytes both give up without throwing; the datagram limit is honoured.
  - `integration/QuicPassthroughInspectionTest`, in the style of `TlsMitmHttpFlowTest`: push
    fixture datagrams through a `UdpConnection` towards a local `DatagramSocket`. Assert the
    socket receives them byte-identical and in order, and that `RecordingDatabaseConnector`
    holds `QUIC`, the SNI, the ALPN and the refined hostname.
- **Commit:** `feat(vpn): record SNI and ALPN of QUIC flows from the Initial packet`

### PKT-48 — Add the QUIC policy preference

- **Priority:** High · **Depends on:** —
- **Resolves:** — (enabler for PKT-49) · **Phase:** Q2, part 1
- **Decided (2026-10-01):** the policy is a user preference with two values, Block and
  Passthrough. The default is Block. It only takes effect while MitM is enabled.
- **Approach:**
  - **Proto.** `enum MitmQuicPolicy { QUIC_BLOCK = 0; QUIC_PASSTHROUGH = 1; }` and field
    `MitmQuicPolicy mitm_quic_policy = 50` in `preferences.proto`. Block is the zero value, so
    existing installs, which have no stored value, get the default as well. Flipping the
    default later means swapping the two enum numbers before release, or setting it explicitly
    in the serializer.
  - **Datastore.** `PreferencesInitialValues.mitmQuicPolicyInitial`, the serializer default,
    and `PreferencesDataSource.mitmQuicPolicy` with a setter, following
    `mitmTrustAllUpstreamCerts`.
  - **Core.** New `quic/QuicPolicy.kt` (`PASSTHROUGH, BLOCK`). `core:vpn` must not depend on the
    preference schema, as with `MitmScope`. Add `ComponentManager(quicPolicy: QuicPolicy = QuicPolicy.PASSTHROUGH)`.
  - **App.** `HeimdallVpnService.launchServiceComponents()` maps the preference and forces
    `PASSTHROUGH` when MitM is off. `MitMPreferences` in `TrafficScannerPreferences.kt` gets a
    `BooleanPreference` "Block QUIC (force TLS fallback)".
- **Files:** `core/datastore-proto/.../preferences.proto`,
  `core/datastore/.../{PreferencesInitialValues,PreferencesSerializer,PreferencesDataSource}.kt`,
  new `quic/QuicPolicy.kt`, `components/ComponentManager.kt`,
  `app/.../service/HeimdallVpnService.kt`,
  `app/.../ui/scanner/traffic/TrafficScannerPreferences.kt`.
- **Tests:** stub `componentManager.quicPolicy` explicitly in `ComponentManagerFixtures` (a
  relaxed mock would return a mock enum) with a `quicPolicy` parameter defaulting to
  `PASSTHROUGH`. Behaviour is covered by PKT-49.
- **Commit:** `feat(prefs): add a QUIC policy preference (block or passthrough)`

### PKT-49 — Block HTTP/3 over QUIC while MitM is on

- **Priority:** High · **Depends on:** PKT-47, PKT-48
- **Resolves:** V-41 · **Phase:** Q2, part 2
- **Approach:**
  - **Decision.** Taken in `QuicConnection` once the inspector is terminal. Block only if all
    of these hold, which together mean "the TLS fallback would actually be intercepted":
    - `componentManager.quicPolicy == BLOCK` and `componentManager.doMitm`;
    - the remote port is 443;
    - the inspector completed and the ALPN offer contains `h3` or an `h3-*` draft token;
    - `componentManager.mitmScope.shouldIntercept(appPackage, host)`;
    - no learned passthrough: `tlsPassthroughCache.get(appId, host)` is false.

    `host` is the transport connection's refined hostname. If the inspector gave up, forward.
  - **Holding.** Under the Block policy, hold outbound datagrams until the verdict instead of
    forwarding them first. The inspector's limit bounds this at 4 datagrams, and clients send
    the datagrams of one flight back to back, so the hold lasts microseconds. On "forward",
    flush them in order.
  - **Blocking.** Drop the held and all later datagrams of the flow and call
    `markConnectionBlocked(id)`. Answer the first three dropped datagrams with an ICMP
    Destination Unreachable (port unreachable), so the client fails over at once instead of
    waiting for its handshake timeout.
    - New `connection/inetLayer/IcmpUnreachableBuilder.kt`, using pcap4j's
      `IcmpV4CommonPacket`, `IcmpV4DestinationUnreachablePacket` and
      `IcmpV4Code.PORT_UNREACHABLE`. The quoted "invoking packet" is the IPv4 header plus UDP
      header, reconstructed from `ipPacketBuilder` and the two ports; that is what the kernel
      matches against the app's socket. Source is the remote address, destination the local one.
    - IPv4 only. An IPv6 flow is dropped silently; the VPN routes IPv4 only today.
    - Post it with a new `DeviceWriteThread.WRITE_ICMP` code.
  - **Lifecycle.** The flow stays in `ConnectionCache`, so the client's retransmissions hit the
    blocked flag instead of creating new connections and rows. The existing UDP idle sweep
    (PKT-13) reaps it after five minutes.
  - **Out of scope:** stripping `h3` from `Alt-Svc` headers and from DNS HTTPS/SVCB records.
    Both need rewriting that the application layer cannot do yet.
- **Files:** `connection/encryptionLayer/QuicConnection.kt`, new
  `connection/inetLayer/IcmpUnreachableBuilder.kt`, `components/DeviceWriteThread.kt`.
- **Tests:**
  - `IcmpUnreachableBuilderTest`: type and code, the quoted header, checksum, swapped addresses.
  - `integration/QuicBlockPolicyTest`, with `RecordingDeviceWriter` and a local `DatagramSocket`:
    - An in-scope h3 flow on port 443 is blocked: nothing reaches the socket, an ICMP packet is
      written to the device, the row is marked blocked.
    - Each of these forwards byte-identical instead: a non-h3 ALPN; a port other than 443; a
      host outside the `MitmScope`; a host with learned passthrough; MitM off; the Passthrough
      policy; an undecryptable Initial.
    - A ClientHello spanning two datagrams is flushed in order when the verdict is "forward".
    - Retransmitted datagrams of a blocked flow create no further connection rows.
- **Manual check:** on a device, with MitM on and the policy set to Block, an HTTP/3-capable
  app's requests appear as decrypted HTTP over TCP and its UDP/443 rows are marked blocked. This
  is also the first real check that an ICMP error written to the TUN reaches the app's socket.
  If it does not, fallback still happens, only after the client's own timeout.
- **Commit:** `feat(vpn): block HTTP/3 over QUIC while MitM is on so clients fall back to TLS`

**Order for the QUIC packets (PKT-26 to PKT-29, PKT-46 to PKT-49):** 26, 27, 29, 46 and 48 are
independent of each other. Then 28, then 47, then 49. Only PKT-27 changes the database version.

**Deferred / lower priority (V-07, V-08, V-09, V-17, V-26, V-27, V-28):** each is real but either
narrow-trigger (V-07 needs a CN shared across differing-SAN certs within a 5-minute window; V-17
needs an actively hostile or badly-behaved TCP peer; V-27/V-28 are minor selector/teardown
hygiene with no correctness impact observed) or a genuinely open architectural question (V-26,
confining all of a `TlsConnection`'s mutation to a single-threaded per-connection dispatcher, is
a bigger refactor than a packet — worth a dedicated design pass rather than a quick fix). Revisit
after PKT-01 through PKT-25 land.

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
