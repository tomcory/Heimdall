# VPN / MitM audit — `core:vpn`

**Date:** 2026-09-28 · **Scope:** `core/vpn` (packet pipeline, transport/encryption/app-layer
connection handling, and the certificate-sniffing MitM engine), plus `app/.../HeimdallVpnService.kt`
and `app/src/main/AndroidManifest.xml` where relevant.

This document is a findings register plus a set of **independently-committable packets**, in the
same format as `docs/records/database-schema-audit.md`. Each packet stands on its own: it lists what it
resolves, which files it touches, how to verify it, and a suggested commit message. Nothing here
has been implemented — no file under `core/vpn` was changed while producing this audit.

All file:line references were verified against the source at the time of writing (2026-09-28).
Line numbers drift — use the surrounding quoted code to re-locate if they no longer match.

**Addendum 2026-09-30:** V-32–V-35 / PKT-20–PKT-24, found during the QUIC analysis
(`docs/records/quic-mitm.md`), plus V-36 / PKT-25, found while implementing PKT-23. References were checked against branch `bugfix/mitm-vpn` at `cb7cc22`.

**Addendum 2026-10-01:** V-37–V-41 / PKT-26–PKT-29 and PKT-49–PKT-52, the implementation
packets for phases Q0 to Q2 of `docs/records/quic-mitm.md` (detection hardening, passive Initial
inspection, QUIC block policy). References were checked against `bugfix/mitm-vpn` at `3454f48`.
PKT-26 to PKT-29 are implemented; PKT-49 to PKT-52 are not.

**Addendum 2026-10-01 (traffic script):** V-42–V-46 / PKT-30–PKT-33 and PKT-36, found by running
`scripts/emulator-traffic.sh` against a rooted emulator. They are numbered ahead of the remaining
QUIC packets, which moved from PKT-30–PKT-33 to PKT-49–PKT-52, because they should be done first.
References for V-42–V-45 were checked against `bugfix/mitm-vpn` at `4eb2013`, for V-46 at
`84667ca`. PKT-30 to PKT-33 and PKT-36 are implemented.

**Addendum 2026-10-01 (stress test):** V-47–V-56 / PKT-34, PKT-35 and PKT-37–PKT-47, found by
stress-testing the VPN on a rooted emulator with `scripts/stress/run-stress.sh` (see "Stress-test
findings"). V-17 is raised from Medium to High on the same evidence. The packets are numbered in
the order they should be done, so the packet for V-46 moved from PKT-34 to PKT-36 and the QUIC
packets to PKT-49–PKT-52. References were checked against `bugfix/mitm-vpn` at `ebba1f8`.
PKT-34 to PKT-38 are implemented. PKT-38 (batching the byte counters) was split out of the
throughput packet and moved forward on 2026-10-01, when verifying PKT-37 showed that the
per-segment counter updates, not body buffering, freeze the VPN after a large upload.

**Addendum 2026-10-02:** PKT-39 is implemented. Verifying it on the emulator produced V-57 /
PKT-48 (no reordering buffer, so real packet loss on the tunnel stalls uploads) and V-58 /
PKT-40 (the VPN service crashes when the interface cannot be established, and again on the
restart that follows). PKT-40 was numbered first among the pending packets because it had to
be done first, so the pending stress-test packets moved from PKT-40–PKT-46 to PKT-41–PKT-47
and the QUIC packets to PKT-49–PKT-52. References were checked against `bugfix/mitm-vpn` at
`ac57197`. PKT-40 to PKT-48 are implemented.

**Addendum 2026-10-02 (QUIC packets reviewed):** PKT-49 to PKT-52 were checked against
`bugfix/mitm-vpn` at `d48a514`, after all fix packets. The design holds; PKT-49 is unchanged.
Revised: the default policy is Passthrough (PKT-51); the block rule uses the same hostname and
decision as the TLS path and no longer depends on port 443 (PKT-52); a blocked flow releases
its socket at once (PKT-52); the device checks are scripted, with a `quic` group in
`emulator-traffic.sh` (PKT-50) and a per-session policy override on the VPN service (PKT-51).
Each revised packet lists what changed.

**Addendum 2026-10-03 (second audit):** all packets up to PKT-52 are implemented. The stack was
re-reviewed and live-tested at `39bd517` on the rooted emulator. This covered the full stress
suite with MitM on and in plain mode, the suite under injected loss, duplication and
reordering, both QUIC policies with real apps, a TLS edge-case probe and a TCP half-close
probe. Findings V-59–V-67 are in "Second-audit findings" (V-68 was added while implementing PKT-58), with a summary of the runs and of
the items still open from earlier work. Packets PKT-53–PKT-61 address them; PKT-53 to PKT-60 are implemented; PKT-61 was measured and closed without a code change. The re-checked low-severity appendix (A-1 to A-19) is addressed by PKT-62 to PKT-64, all implemented.

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
| V-57 | M | Segments that arrive ahead of a gap are dropped, not buffered, so one lost packet makes the device resend everything after it and repeated loss stalls an upload |
| V-58 | H | The VPN service crashes when `establish()` returns null (Heimdall is not the prepared VPN app, e.g. after a reboot), and crashes again when Android restarts it with a null intent |
| V-59 | H | Data the client sends after the remote host has closed its side is answered with a reset and never reaches the remote host, so a server half-close silently loses the client's data |
| V-60 | H | Passthrough learning counts an idle connection that the app closes as certificate pinning, so hosts that accept the forged certificate stop being decrypted |
| V-61 | M | The MitM negotiates no ALPN on either side: every client is downgraded to HTTP/1.1, and clients or servers that require HTTP/2 fail |
| V-62 | M | An upstream TLS failure (untrusted, expired or self-signed certificate, unsupported handshake) is answered with a TCP reset and never learned, so the app can never connect while MitM is on |
| V-63 | M | When the system resolver uses Private DNS (DNS over TLS), the DNS cache stays empty: every connection starts without a hostname, and plain HTTP traffic is never named |
| V-64 | M | HTTP bodies are stored as UTF-8-decoded text: binary and compressed bodies are irreversibly corrupted and take twice their size, which fills the database |
| V-65 | M | Under load, request rows are written more than 30 s late, and responses that wait longer than that for their request are discarded |
| V-66 | M | The VPN network is reported as metered, so apps and the system treat an unmetered Wi-Fi as metered while Heimdall runs |
| V-67 | L | A new UDP flow, including every plain DNS query, is still set up with blocking binder calls on the thread that handles every packet from the device (lowered from M on 2026-10-04: measured at a few milliseconds per flow, see PKT-61) |
| V-68 | H | About one DNS query in 256 is taken for TLS and swallowed, so the lookup fails until the resolver retries (found while implementing PKT-58, fixed by it) |

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
`CLAUDE.md` and `docs/architecture.md` also describe Netty as doing "TCP/TLS handling in the
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

Background, protocol details and the reasoning behind the phases are in `docs/records/quic-mitm.md`
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
(`QuicConnection.kt:29-37`). A QUIC flow is therefore labelled only by V-39's DNS lookup, and
its ALPN (`h3`, `doq`, …) is unknown.

**Recommendation:** decrypt the client Initial passively and record SNI and ALPN, with MitM on
or off (PKT-29, PKT-49, PKT-50).

### V-41 — HTTP/3 bypasses the MitM entirely (High)

`QuicConnection` sets `doMitm = false` unconditionally (`QuicConnection.kt:23`). With MitM
enabled, every app that speaks HTTP/3 sends that traffic past the decryption pipeline; only its
TCP traffic is intercepted. Almost all such clients fall back to TCP+TLS when UDP/443 fails, and
for Chromium-based clients (Chrome, Cronet) a fallback is the only possible outcome anyway,
because they refuse QUIC certificates that do not chain to a public root
(`docs/records/quic-mitm.md` §2.6). There is currently no way to trigger that fallback.

**Recommendation:** a user preference to block h3 QUIC while MitM is on, off by default,
enforced only where the TLS fallback would actually be intercepted (PKT-51, PKT-52).

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

## Stress-test findings (V-47–V-58, V-17 revisited)

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
reset, and never answer an RST (PKT-44).

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
upstream channel while the window is exhausted (PKT-42).

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
receive window that reflects the queue (PKT-43).

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
re-ACK anything else (PKT-39).

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

Which of the steps costs most was not measured at the time. PKT-41 measured it on 2026-10-02
(435 TCP connections during `tlsparallel`, `parallel` and `churn`, times per connection in ms):

| Step | Median | p90 | p99 | Max | Share of total |
|---|---|---|---|---|---|
| `getAppId` (binder) | 1.6 | 4.7 | 21 | 57 | 9 % |
| `getAppPackage` | 0.03 | 0.06 | 0.4 | 1.8 | 0 % |
| `createDatabaseEntity` (`runBlocking` insert) | 5.2 | 17.5 | 215 | 2434 | 65 % |
| Open, protect, connect the socket | 3.8 | 9.0 | 25 | 55 | 16 % |
| Register with the selector | 0.65 | 3.6 | 66 | 358 | 10 % |
| **Total** | **12.9** | **38** | **384** | **2466** | |

Within the socket step, `connect()` costs most (median 2.6 ms; on Android every `connect()`
talks to netd), `protect()` 0.3 ms. The registration waited because the selector thread held
`selectorMonitor` for as long as it processed selected keys.

**Recommendation:** measure first, then move the blocking steps off the handler thread (PKT-41).

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
- **20 MB upload**: completed, with the heap at its limit (`235MB/235MB` in the GC log), and
  no packet of any app was processed for the next 10 s; a new connection's SYN went unanswered
  and the client's connect timed out.

  **Correction (2026-10-01):** that freeze is not caused by body buffering. It was still there
  after PKT-37, with a flat heap. See "V-55 revisited" below for the cause.

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
(PKT-46).

### V-55 — Throughput is a fraction of the direct path (Medium)

| Transfer | Without VPN | Through VPN | After PKT-38 |
|---|---|---|---|
| Plain download, 50 MB | 13.8 MB/s | 6.2 MB/s | 8.1 MB/s |
| Plain upload, 20 MB | 12.4 MB/s | 1.6 MB/s | 5.3 MB/s |
| TLS download, 25 MB (MitM) | 13.3 MB/s | 7.4 MB/s | 10.1 MB/s |

Likely contributors, none measured on its own:
- V-53 for downloads.
- For uploads, every segment is acknowledged individually and triggers its own coroutine and
  database `UPDATE` (`recordBytesOut`, `TransportLayerConnection.kt:245-251`; the same for
  inbound).
- For plain HTTP, `HttpConnection` copies and logs every payload.

**Recommendation:** batch the byte counters (PKT-38, done), then profile an upload for what is
left (PKT-45).

**After PKT-45 (2026-10-02).** The emulator was slower that day than when the table above was
measured, so the rates are given with their own baseline, all from one session, before and
after in alternating runs (two each):

| Transfer | Without VPN | Before PKT-45 | After PKT-45 |
|---|---|---|---|
| Plain download, 50 MB | 5.0 MB/s | 3.4 – 3.5 MB/s | 5.0 – 5.2 MB/s |
| Plain upload, 20 MB | 10.1 MB/s | 0.6 – 0.8 MB/s | 5.2 – 7.3 MB/s |
| TLS download, 25 MB (MitM) | 5.2 MB/s | 2.5 – 2.6 MB/s | 4.4 – 4.6 MB/s |
| TLS upload, 5 MB (MitM) | 3.7 MB/s | 1.4 MB/s | 3.1 – 3.2 MB/s |

Downloads are now at the rate of the direct path, uploads at one half to three quarters of it.

### V-55 revisited — Per-segment counter updates freeze the VPN after a large upload (High)

Found while verifying PKT-37. `recordBytesOut()` launches one coroutine and one
`UPDATE Connection SET bytesOut = …` for every data segment the device sends
(`TransportLayerConnection.kt:245-251`, called from `TcpConnection.wrapOutbound`). A 20 MB
upload is about 14,000 segments, so about 14,000 updates queue up behind SQLite's single
writer. The next new connection then blocks the outbound handler thread in
`createDatabaseEntity()`'s `runBlocking` insert (V-51) until that queue has drained.

Observed after PKT-37, heap flat at about 80 MB:

```
20:33:46.064 http3101 resolved overflow with 0 of 20000000 bytes remaining      upload done
20:34:01.199 http3101 persisting request with ID 7380                           15 s later
20:34:01.201 tcp3120 Creating TCP Connection to 10.0.2.2:18080                  next SYN handled
```

For those 15 s no packet of any app was processed. The client's next connect timed out after
10 s, and a request it retransmitted during the stall was forwarded four times (V-17).

`recordBytesIn()` is called once per readable event rather than once per segment, so downloads
queue far fewer updates.

**Recommendation:** accumulate the counters in memory and write them at most once a second
(PKT-38).

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

**Recommendation:** close the selector and both pipe ends on stop (PKT-47).

### V-57 — Out-of-order segments are dropped, so packet loss stalls uploads (Medium)

Found while verifying PKT-39 with packet loss injected on the tunnel
(`tc qdisc add dev tun0 root netem duplicate 5% delay 2ms reorder 5% loss 1%`, which acts on
packets from the device to the VPN).

PKT-39 accepts only the segment that starts at the expected sequence number and has no
reordering buffer. Heimdall's SYN-ACK offers no SACK either. After a lost or overtaken segment
the device therefore has to resend everything from the gap on. If one of those resent segments
is lost or overtaken again, the device only notices through its retransmission timer, which
doubles each time.

Captured during a 1 MB upload: the acknowledgement number stopped at 85,033 while the device
kept sending up to 150,425 (the full 65,535-byte window), and the pauses between its attempts
grew to 1, 3, 7, 14 and 28 s. The upload did not finish within 40 s. In the stress run
`upload-1000000`, `upload-20000000` and both TLS uploads failed with timeouts. Nothing was
corrupted, and connection-heavy tests with small requests passed under the same conditions.

A TUN interface does not reorder packets, and the stress runs without injected loss showed no
gap (`Dropping out-of-order segment` was logged 0 times). Loss can still occur when Heimdall
reads the tunnel too slowly and its queue (500 packets) overflows, which is what V-50 and V-51
make possible.

**Recommendation:** keep segments that arrive ahead of a gap, up to the advertised window, and
deliver them once the gap is filled (PKT-48).

### V-58 — The VPN service crashes when the interface cannot be established (High)

Two defects in `HeimdallVpnService`, found when the stress script started the service on a
freshly booted emulator:

- `establishInterface()` treats a null result of `Builder.establish()` as success
  (`HeimdallVpnService.kt:437-439`). `establish()` returns null when the app is not the
  prepared VPN app. That is the case after every reboot until `VpnService.prepare()` has been
  called again, even though the user's consent is still recorded. The UI calls `prepare()`;
  a start from anywhere else (the stress script, a boot receiver, a restart by the system)
  does not. `launchServiceComponents()` then passes the null descriptor to `FileInputStream`
  (`:226`) and the process dies with `NullPointerException: fdObj == null`.
- `onStartCommand()` declares its intent as non-null (`:80`) and returns `START_STICKY`
  (`:101`). Android restarts a sticky service with a **null** intent after its process died, so
  the restarted service crashes at once: `Parameter specified as non-null is null: method
  HeimdallVpnService.onStartCommand, parameter intent`.

Observed on the emulator: both crashes one after the other, four seconds apart, each time the
service was started without the UI after a cold boot. No tunnel came up.

**Recommendation:** call `VpnService.prepare()` in the service before establishing, treat a
null interface as a failure, and accept a null intent (PKT-40).

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

## Second-audit findings (V-59–V-67)

Found on 2026-10-03 at `39bd517`, after PKT-26 to PKT-52 had all been implemented. Line
references are to that commit.

### Test runs

All runs used the rooted emulator (`Pixel_6a_API_33_magisk`, started with
`-dns-server 1.1.1.1`) and a freshly deleted Heimdall database.

| Run | Result |
|---|---|
| `run-stress.sh --baseline` (VPN off) | 71/72; `udp-burst-500` fails, as it always does on the emulator's NAT |
| `run-stress.sh` with all tests and `bigbody`, MitM on | 72/73; `slowupload-others-responsive` failed once (slowest small request 2003 ms, baseline 26 ms) and passed in three reruns (268–583 ms) |
| `run-stress.sh`, plain mode (MitM off) | 71/72, only `udp-burst-500`; but 143 HTTP responses were discarded (V-65) |
| Download, upload, keep-alive, parallel, duplex and TLS tests under `netem delay 15ms 5ms loss 1% duplicate 1% reorder 5% 50%` | 50/50 |
| `emulator-traffic.sh run`, QUIC policy Passthrough | all groups ran, no crash; QUIC SNI/ALPN recorded for 15/15 flows |
| `emulator-traffic.sh run --quic-policy block` | the h3, split and v2 Initials are refused with ICMP, doq is forwarded; YouTube falls back to TLS and 16 of its requests are decrypted; 16 QUIC flows blocked |
| TLS probe (18 targets, trust-all client offering h2 and http/1.1), with and without the VPN | V-61, V-62 |
| TCP half-close probe (server replies, shuts down its sending side, then reads 200,000 bytes) | V-59 |

No crashes in any run. No descriptor leak within a session: 137 descriptors before a
connection-heavy run, 143 three minutes after it. The 363 that `run-stress.sh` reports straight
after a run are connections still waiting out the two-minute closing timeout. Plain TCP
throughput through the VPN now matches or exceeds the direct path (5.4 against 2.4 MB/s for a
50 MB download, 6.8 against 2.1 MB/s for a 20 MB upload; the emulator's NAT is the slower
path). This resolves V-55 for plain TCP. Decrypted TLS bulk transfers run 20–35% below the
direct path. `tlsparallel-72` took 12.1 s with MitM, 16.0 s in plain mode and 6.4 s without the
VPN; it varies too much between runs to tell what MitM itself costs.

### V-59 — A remote close resets the client's later data (High)

When the remote host closes its side, `unwrapInboundReadable()` reads end of stream and closes
the whole `SocketChannel` (`TcpConnection.kt:1150-1156`), then sends our FIN to the device.
From then on the connection is CLOSING, and any segment with data from the device is answered
by `handleAckData()` with a reset (`TcpConnection.kt:822-828`, "Got ACK (data, invalid state
CLOSING)"). A FIN from the remote host only says that it has finished sending. It may still
read, and with a half-close that is the point.

- **Half-close loses data silently.** Server replies, shuts down its sending side, then reads
  200,000 bytes: through the VPN it received **0 of 200,000** bytes (twice, with and without a
  500 ms pause). Without the VPN it received all of them. The client saw no error: its writes
  had been buffered by the time the reset arrived.
- **Every server-initiated TLS close ends in a reset.** A TLS client answers the server's
  close_notify with its own, which is data. That accounts for most of the 44 resets in the MitM
  stress run (17 to `www.cloudflare.com`, 13 to `www.wikipedia.org`, from `tls` and `tlsclose`)
  and the 41 in plain mode. Each is followed by the client's FIN, which arrives for a connection
  no longer in the cache and draws a second, stray reset ("Resetting unknown TCP packet (FIN)":
  71 in the MitM run). The response itself is complete by then, so the harm is a reset where a
  clean close was due.
- `closeChannel()` on end of stream also throws away anything still in the upstream write queue
  (`outQueue`), e.g. the rest of an upload the server answered early.

This is the remote-side counterpart of V-42, which PKT-30 fixed for client half-closes.

**Recommendation:** on end of stream, shut down only the input. Keep the channel open for
writing until the device's FIN has been forwarded and the write queue drained, and keep
accepting and forwarding data from the device in CLOSING. If the remote host has really closed
its socket, the write fails with a reset, and that is the point to reset the device (PKT-53).

### V-60 — Idle connections closed by the app are learned as pinning (High)

`recordPinningSuspect()` (`TlsConnection.kt:1325-1329`) learns `CLOSED_WITHOUT_DATA` when the
client closes a connection whose handshake completed but which never carried application data.
Two such closes for the same app and host make the host passthrough for the rest of the
session (PKT-23's threshold). Apps routinely open connections they never use. Cronet races TCP
against QUIC and keeps the loser. OkHttp and Cronet pre-connect. Pools evict idle connections.
An app that is force-stopped, swiped away or killed closes all of them at once.

Observed: the traffic script's `apps` group force-stops each app after 25 s. In the Passthrough
run, YouTube's TLS connections were idle because QUIC carried its traffic. When the app was
stopped, `www.youtube.com`, `i.ytimg.com`, `redirector.googlevideo.com` and
`youtubei.googleapis.com` were all learned as passthrough within 50 ms
(`CLOSED_WITHOUT_DATA`). The Block run shows these hosts accept the forged certificate: 16 of
YouTube's requests to them were decrypted. In that run `www.youtube.com` was learned again
at the force-stop, though requests to it had already been decrypted on other connections.

Every false positive silently ends decryption for that app and host for the session, which is
the opposite of what an analysis tool needs. The same rule can also fail to learn a real
rejection. The Play Store keeps its rejected TLS fallback open and idle, so the close that
would count may never come, and that case was left as is on 2026-10-02.

**Recommendation:** only count a close as pinning when it follows the handshake within a short
time (pinning rejects within milliseconds of seeing the certificate, idle eviction takes
seconds to minutes). Never count it once any connection of the same app and host has carried
application data. Ignoring bursts of closes across many hosts of one app (an app being
stopped) would also help, but with the first two rules it is rarely needed (PKT-54).

### V-61 — No ALPN is negotiated through the MitM (Medium)

Neither engine is given application protocols. `SSLEngineSource.newSSLEngine()`
(`SSLEngineSource.kt:83-106`) and `setupServerSSLEngine()` / `setupClientSSLEngine()`
(`TlsConnection.kt:745-786`) never call `SSLParameters.setApplicationProtocols()`. The upstream
handshake offers no ALPN, and the client-facing engine selects none.

Observed with the TLS probe, which offers `h2,http/1.1`. Without the VPN, `www.google.com`,
`www.cloudflare.com`, `http2.golang.org` and `grpcb.in:9001` negotiate `h2`. Through the
MitM, all four negotiate nothing and serve HTTP/1.1. Most clients fall back without complaint,
which is also why decrypted traffic is parseable today: decrypted HTTP/2 would go to
`RawConnection`, which records nothing. Clients that require HTTP/2 do fail: gRPC requires it
and refuses a connection without `h2`, and so do some servers. Clients also see an
HTTP/1.1-only server where the real one supports HTTP/2, which changes their behaviour
(connection count, multiplexing) under observation.

**Recommendation:** negotiate upstream with the client's offered list, and select on the
client-facing side what the server selected. That needs an HTTP/2 frame parser (HPACK)
before `h2` can be let through and still be recorded. Until then, at least pass through
connections whose client offers only `h2` (gRPC), learned like the other passthrough cases (PKT-57).

### V-62 — Upstream TLS failures reset the client and are never learned (Medium)

Upstream certificate validation (fixed by V-02) and the upstream handshake can fail. Then
`handleUnwrap()` logs the `SSLException` (`TlsConnection.kt:963`) and the connection is closed
with a TCP reset to the client. Only failures on the client-facing side are learned
(`TlsConnection.kt:969-971`), so the same thing happens on every retry.

Observed through the MitM: `expired.badssl.com`, `self-signed.badssl.com` and
`untrusted-root.badssl.com` all end in `SocketException: Connection reset` (logcat:
`CertPathValidatorException: Trust anchor for certification path not found`, `Chain validation
failed`). That is the right outcome for an app that uses the platform's trust store. It is the
wrong outcome for an app that legitimately trusts its own CA through a network security config
or a custom trust manager, which covers enterprise and IoT apps and self-hosted services. Such
an app can never connect while MitM is on, and Heimdall records nothing but a reset. The app
also gets a reset instead of a certificate error, which makes the failure hard to diagnose.
Heimdall decides trust here on the app's behalf, and the app may decide differently.

**Recommendation:** treat an upstream verification failure like a client rejection: learn
passthrough for the app and host, so the retry reaches the server directly and the app applies
its own trust decision. Mark the connection in the database (like `blocked`), so the analysis
shows why it was not decrypted (PKT-56).

### V-63 — Private DNS leaves the DNS cache empty (Medium)

`DnsCache` is filled only by `DnsConnection`, which is used for UDP port 53
(`AppLayerConnection.kt:42-43`). On Android 9+ the default Private DNS mode is "automatic":
the system resolver uses DNS over TLS to the VPN's DNS server when that server supports it.
1.1.1.1, the configured server, does. Then no plain DNS passes through the VPN at all.

Observed. In the MitM stress session, 5 DoT connections to `1.1.1.1:853`, 2 UDP/53 flows and
**127 of 127** port-443 connections created without a hostname. In the plain-mode session the
resolver used UDP/53 (43 flows, no DoT) and 0 of 120 lacked one. Which mode the resolver
picks varies between VPN sessions. `dumpsys connectivity` shows `UsePrivateDns: true
ValidatedPrivateDnsAddresses: [1.1.1.1]` on the VPN network. TLS and QUIC flows recover their
name from the SNI (PKT-27, PKT-50). Plain HTTP does not: in the Block traffic run, four
plaintext requests to `connectivitycheck.gstatic.com` were recorded with host `-`. The
`isTracker` label for those connections is evaluated on nothing. With MitM on, the DoT
connections themselves (uid 1051) are decrypted and their DNS messages pass through a
`RawConnection` unused.

**Recommendation:** when a DoT connection is decrypted, parse its stream (DNS over TCP, two-byte
length prefix) with the same code as `DnsConnection`, and fill the cache from it. Without
MitM, either reset connections to the VPN's DNS address on port 853 (opportunistic mode then
falls back to plain DNS; strict mode would fail, so only do this when the setting is
"automatic"), or document the gap. For plain HTTP, also fall back to the `Host` header for the
request's host (PKT-58).

### V-64 — HTTP bodies are stored as lossy text (Medium)

`HttpConnection` turns every message into a `String` with UTF-8 decoding
(`HttpConnection.kt:235` and the chunked path), and `Request.content` / `Response.content` are
`String` columns. Every byte sequence that is not valid UTF-8 becomes U+FFFD, which takes three
bytes. Images, protobuf, gzip/brotli-compressed bodies and other binary payloads are therefore
stored irreversibly corrupted, at up to three times their size. Bodies up to 1 MB are kept
(`maximumMessageSize`, `:84`).

Observed in the pulled database: a 1,000,000-byte random body is stored as 2,000,004 bytes, of
which 500,002 are replacement characters. After roughly an hour of testing, the database was
439 MB, 406 MB of it in the `Response` table. This is the "database grows to gigabytes during
stress runs" seen throughout the stress work.

**Recommendation:** store bodies as `BLOB` (or as a file per body, with the path in the row),
decoded to text only for display and only when the content type says it is text. Make the size
limit a preference, with a lower default. Optionally store compressed bodies decompressed (PKT-59).

### V-65 — Late request rows make responses get discarded (Medium)

A response waits for its request's database ID for at most
`REQUEST_CORRELATION_TIMEOUT_MS` (30 s, `HttpConnection.kt:639`) and is discarded after that
(`:453`). Request rows are written on unbounded `Dispatchers.IO` coroutines behind everything
else that is being written.

Observed in the plain-mode stress run: **143** responses discarded ("No matching request ID
became available in time"), on 16 connections, all to the stress server (`10.0.2.2:18080`).
On one connection, requests sent around 04:40:02 were persisted between
04:40:34 and 04:40:46. The database ended with 7,566 requests and 7,322 responses. The MitM run
the hour before showed none, with a smaller database and the same tests. V-64's oversized rows
are the likely cause of the write backlog, but that was not measured separately.

**Recommendation:** do not drop the response. Persist it with a null request ID and link it
when the request row arrives, or write the request and response in one transaction once the
response is complete. Fix V-64 first and re-measure (PKT-60).

### V-66 — The VPN network is metered (Medium)

Since API 29 a VPN network counts as metered unless the builder calls `setMetered(false)`.
`establishInterface()` (`HeimdallVpnService.kt:407-411`) does not. On the emulator, the
underlying Wi-Fi network has `NOT_METERED`, but the VPN network's capabilities lack it. Apps
that check `isActiveNetworkMetered()` or schedule work with `NetworkType.UNMETERED` (Play Store
auto-updates, backups, photo sync, prefetching, video quality) behave as on mobile data while
Heimdall runs. So the traffic Heimdall records is not what the app sends on Wi-Fi without it.

**Recommendation:** call `setMetered(false)` on API 29+. Meteredness then follows the underlying
networks, and calling `setUnderlyingNetworks()` makes that explicit (PKT-55).

### V-67 — UDP flows are still set up on the packet thread (Medium)

PKT-41 moved TCP setup off the thread that handles every packet from the device. UDP setup was
left there: `UdpConnection`'s constructor calls `appFinder.getAppId()` (a binder call on API
29+), `getAppPackage()` (another), `protectDatagramSocket()` (another) and `connect()`
(`UdpConnection.kt:67-68, 113, 121`). The same happens for each plain DNS query, since each
query uses a new source port and so becomes a new flow. Every packet of every other connection
waits behind those calls. This was not measured in this audit. PKT-41 measured the same calls
for TCP at hundreds of milliseconds of ACK delay under load, and a burst of DNS queries (an
app starting) is the UDP equivalent.

**Recommendation:** set UDP flows up asynchronously like TCP: queue the datagrams that arrive
until the channel is connected. Short-cut DNS flows, which need no app lookup before the query
can be forwarded (PKT-61).

**Measured 2026-10-04 (PKT-61):** the setup costs 1.5–3.9 ms per flow at the median and at
most 12 ms. PKT-41 had already moved the database insert, the expensive part, off the thread.
Lowered to Low; PKT-61 was closed without a code change.

### V-68 — One DNS query in 256 is taken for TLS (High)

Found on 2026-10-03 while verifying PKT-58, which makes the system resolver send its queries
over plain UDP through the VPN. In one `tlsparallel` run, one of 72 requests failed with
`UnknownHostException` after 10 s. The log showed a DNS query for `www.mozilla.org` reaching a
`TlsConnection` (`prepareRecords (outbound) Invalid TLS record type: 01`).

`EncryptionLayerConnection.detectTls()` takes a first segment for TLS when byte 0 is `0x16` and
byte 5 is `1`. In a DNS query, bytes 0 and 1 are the random query ID, and byte 5 is the low byte
of the question count, which is 1. So every query whose ID begins with `0x16`, one in 256, was
handed to a TLS connection, which drops it as an invalid record. The resolver gets no answer,
times out, and retries with a new ID. The detection also ran on any transport, so TLS-looking
bytes over UDP and QUIC-looking bytes over TCP could be misclassified as well. The bug is old,
but it bit rarely while the resolver used DNS over TLS; with plain DNS through the VPN, a busy
device would hit it several times an hour.

**Recommendation:** never apply TLS or QUIC detection to DNS ports, and apply TLS detection to
TCP flows only and QUIC detection to UDP flows only (done in PKT-58).

### Still open from earlier work

Not new, listed so the register shows everything that is unresolved:

- **ACK latency under load.** PKT-41's p90 target of 50 ms was not met (CPU contention on the
  emulator). The single 2003 ms `slowupload-others-responsive` result in this audit belongs here.
- **The 534 s `tlsclose` hang** seen once during PKT-47 did not recur. `tlsclose` took 46 s in
  this audit.
- **The null-intent sticky restart** fixed by PKT-40 has never been observed on a device.
- **Inbound UDP datagrams above 16,413 bytes** are truncated (logged since PKT-46), and IPv6
  fragments are not reassembled. The VPN carries no IPv6 today.
- **Passthrough learning for the Play Store** under the Block policy depends on an idle
  fallback being closed (see V-60). Left as is on 2026-10-02.
- **pcap4j's per-packet cost** (PKT-45 analysis). Kept by decision on 2026-10-02.
- **V-07, V-08, V-09, V-26, V-27** remain deferred.
- **Logging:** `handleUnwrap()` logs the full record as hex at error level on every
  `SSLException` (`TlsConnection.kt:972`). For an upstream failure that is the server's
  certificate chain, and logcat is readable by anything with `READ_LOGS`.

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
    `docs/architecture.md` (dependency table), `core/vpn/README.md` (trust-all description and
    dependency table) and `docs/records/quic-mitm.md` (§3.4 and open question 2). Leave the historical
    `docs/records/implementation-plan.md` alone.
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
- **Resolves:** V-37 · **Phase:** Q0.1 of `docs/records/quic-mitm.md`
- **Approach:** in `detectQuic()`, keep the long-header and fixed-bit test and additionally
  require:
  - a version other than 0;
  - the Initial packet type: bits `0x30` of byte 0 are `0b01` for QUIC v2 (`0x6b3343cf`) and
    `0b00` for v1 and for unknown versions;
  - a payload of at least 1200 bytes.

  Unknown versions that otherwise look like an Initial stay classified as QUIC; PKT-50 simply
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
    see PKT-00 in `docs/records/database-schema-audit.md`), so every column Q1 and Q2 need lands here
    and no later packet bumps the version again. Rewrite `Protocol.kt`'s kdoc, which says the
    opposite.
  - **DAO.** `ConnectionDao.updateSecurity(id, securityProtocol, sni, alpn, echOffered)`,
    `updateHost(id, remoteHost, isTracker)` (used by PKT-28) and `markBlocked(id)` (used by
    PKT-52).
  - **Connector.** `DatabaseConnector.updateConnectionSecurity`, `updateConnectionHost` and
    `markConnectionBlocked`, implemented in `RoomDatabaseConnector` in the style of
    `updateConnectionBytesOut`.
  - **Callers.** `EncryptionLayerConnection` gets a `protected fun persistSecurity(...)` that
    runs asynchronously on `Dispatchers.IO` with the same `id > 0` guard as
    `TransportLayerConnection.recordBytesOut` (DNS flows have id 0 and are skipped).
    `PlaintextConnection` calls it in `init`, `TlsConnection` at the ClientHello with the SNI,
    `QuicConnection` in `init` (PKT-50 adds SNI and ALPN).
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
- **Resolves:** — (enabler for PKT-50; also gives the TLS path ALPN and ECH detection)
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
    still a FIN where a reset would be right (PKT-44).
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
- **Implementation notes (2026-10-01):**
  - The length is known up front, so a body above the limit is never cached at all, and a body
    within the limit is cached as before. Nothing has to be dropped half-way as in the chunked
    path.
  - On the emulator the 300 MB download passes with a matching hash and Heimdall's Java heap
    stays between 64 and 88 MB (420 MB and `OutOfMemoryError` before). Large bodies are stored
    as `<too large: N bytes>` with the real length, for decrypted HTTPS as well.
  - The device check "no connect timeout after the 20 MB upload" still **fails**. The freeze
    has a different cause, written up as "V-55 revisited" and fixed by PKT-38.
- **Commit:** `fix(vpn): cap the memory used for HTTP bodies that have a Content-Length`

### PKT-38 — Batch the per-connection byte counters

- **Priority:** High · **Depends on:** —
- **Resolves:** "V-55 revisited" (the freeze after a large upload); part of V-55
- **Approach:**
  - Keep `bytesOut` and `bytesIn` deltas per connection in memory (`AtomicLong`s on
    `TransportLayerConnection`). `recordBytesOut()`/`recordBytesIn()` only add to them.
  - Write the accumulated deltas with one `UPDATE` per connection at most once a second, from
    the sweep job in `ComponentManager`, and once more when the connection closes
    (`closeSoft`). A connection with nothing new is skipped.
  - Flush everything in `stopComponents()` before the session's end time is written.
  - `DatabaseConnector.updateConnectionBytesOut/In` keep their signatures; only their callers
    change. Use `Long` deltas.
- **Files:** `connection/transportLayer/TransportLayerConnection.kt`, `TcpConnection.kt`,
  `UdpConnection.kt`, `components/ComponentManager.kt`, `components/DatabaseConnector.kt`,
  `components/RoomDatabaseConnector.kt`.
- **Tests:** a unit test that many `recordBytesOut()` calls produce one connector call per
  flush and that the total matches; that close flushes the remainder; existing tests that
  assert `bytesIn`/`bytesOut` (e.g. `TcpHalfCloseTest`) stay green, waiting for the flush.
  Device: `run-stress.sh upload,keepalive,download` — no connect timeout after the 20 MB upload,
  and the byte counters in the report match the transferred sizes. Note the upload rate before
  and after in the V-55 table.
- **Implementation notes (2026-10-01):**
  - The counters live in `TransportLayerConnection` only; `TcpConnection` and `UdpConnection`
    did not need to change. The flush runs in its own one-second job in `ComponentManager`
    rather than in the 30-second sweep job.
  - The flush on close is in `ConnectionCache.removeConnection()`, not in `closeSoft`: every
    close path (soft, hard, sweep, UDP idle) ends there. It runs on `Dispatchers.IO`, so a
    closing connection never waits for the database.
  - `stopComponents()` flushes all connections synchronously before clearing the cache.
  - The delta parameter is `Long` down to `ConnectionDao.updateBytesOut/In`. The query text is
    unchanged, so there is no schema change and no version bump.
  - Tests: `ByteCounterBatchingTest` (three cases); `RecordingDatabaseConnector` counts counter
    updates. 270 `core:vpn` tests pass.
  - Emulator, `run-stress.sh upload,keepalive,download,parallel,churn,tlsbulk`: 30 checks
    passed, none failed. The gap between the end of the 20 MB upload and the next connection
    is 16 ms (15 s before), and the connect timeout is gone. Rates are in the V-55 table; the
    TLS upload ran at 8.9 MB/s. Counters match the transfers, e.g. `bytesOut` 21,003,192 for a
    connection that uploaded 1 MB and 20 MB, and `bytesIn` 300,001,356 for the 300 MB download.
  - `emulator-traffic.sh run` shows the same results as before the change. One run had a
    connect timeout to `connectivitycheck.gstatic.com:80` in the half-close case; three
    further runs of the `http` group did not repeat it.
- **Commit:** `perf(vpn): batch per-connection byte counter updates instead of one UPDATE per segment`

### PKT-39 — Accept only in-order segments from the device

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
- **Implementation notes (2026-10-02):**
  - The check is `acceptInOrder()` in `TcpConnection`, called from `unwrapOutbound()` for every
    segment that carries data or a FIN. The distance to the expected sequence number is a
    32-bit subtraction, so it is right on both sides of the wrap-around.
  - A retransmitted FIN still reaches `handleFin()`, which already answered it correctly
    (PKT-30, PKT-35). A FIN that follows a gap is dropped like data.
  - Two additions that the same check made cheap:
    - An empty segment one below the expected sequence number is a keep-alive probe and is
      now acknowledged. It used to be ignored, so a device with keep-alive enabled would
      eventually have given up on an idle connection.
    - A data segment that arrives while the connection is still `CONNECTING`, after our
      SYN-ACK went out, completes the handshake. The device's handshake ACK was lost or
      overtaken; the connection used to be reset.
  - Tests: `TcpSegmentValidationTest` (nine cases). 279 `core:vpn` tests pass.
  - Emulator, no injected faults: `run-stress.sh` with eleven tests incl. `tlsparallel`,
    54 checks passed, none failed, no `BAD_RECORD_MAC`. The device did not retransmit at all
    in these runs (0 of 870 data segments in a capture, slowest ACK 145 ms), because PKT-38
    removed what delayed the ACKs. The failure therefore had to be provoked.
  - Emulator, 10 % of the device's packets duplicated (`netem duplicate 10%` on `tun0`), same
    seven tests on both builds:

    | | Before | After |
    |---|---|---|
    | Checks passed / failed | 21 / 10 | 30 / 1 |
    | `BAD_RECORD_MAC` | 16 | 0 |
    | `tlsparallel` | 48 of 72 | 72 of 72 |
    | `keepalive` | 2 of 300 | 300 of 300 |
    | Uploads of 1 MB and 20 MB | timeout | hash matches |

    About 5,900 duplicates were ignored in the "after" run. Its one failure was a connect that
    took over 10 s. It came back in one of four reruns. A capture shows the SYN-ACK arriving
    7 s after the first SYN while about half of the connections needed a SYN retry, so the
    delay is in connection setup (V-51, PKT-41), not in segment handling. It was not traced
    further.
  - Emulator, loss and reordering as well (`duplicate 5% delay 2ms reorder 5% loss 1%`):
    `tlsparallel`, `parallel`, `keepalive` and `churn` pass with every stream intact. Large
    uploads stall: V-57.
  - Throughput without injected faults is unchanged (20 MB upload 5.2 MB/s, 50 MB download
    8.8 MB/s, TLS 25 MB 9.9 MB/s).
- **Commit:** `fix(vpn): drop retransmitted and out-of-order segments from the device instead of forwarding them`

### PKT-40 — Stop the VPN service crashing when it cannot establish the interface

- **Priority:** High · **Depends on:** —
- **Resolves:** V-58
- **Approach:**
  - `onStartCommand(intent: Intent?, …)`. A null intent is Android restarting the service
    after its process died: treat it as `START_SERVICE` without an existing session.
  - Before `establish()`, call `VpnService.prepare(this)`. If it returns an intent, the user
    has to consent in the UI: log it, set the VPN preference to inactive, stop the service and
    return `START_NOT_STICKY`.
  - Treat a null result of `establish()` as a failure (`establishInterface()` returns false),
    with the same clean stop.
- **Files:** `app/.../service/HeimdallVpnService.kt`; `scripts/emulator-traffic.sh` (its
  `vpn-start` no longer needs the UI after a cold boot).
- **Tests:** a Robolectric or instrumentation test is not in place for the service, so verify
  on the emulator: cold boot, `emulator-traffic.sh vpn-start` brings `tun0` up without the UI;
  with consent revoked (`appops set de.tomcory.heimdall ACTIVATE_VPN ignore`) the service
  stops without a crash; `am crash de.tomcory.heimdall` while the VPN runs is followed by a
  restart that brings the tunnel back.
- **Implementation notes (2026-10-02):**
  - `prepare()` is called in `onStartCommand()`, after `startForeground()` (a service started
    with `startForegroundService` has to call it whatever happens next). Without consent the
    service logs why, stops itself and returns `START_NOT_STICKY`.
  - `launchServiceComponents()` now returns whether the VPN came up. On failure the new
    `abortStart()` removes the notification, stops the service and records the VPN as
    inactive. Before, the preference was set to active even when nothing had started, also
    when the `ComponentManager` failed to launch.
  - `scripts/emulator-traffic.sh` needed no change. `run-stress.sh` no longer tells the reader
    to start the VPN from the UI.
  - No automated test (as planned). Emulator:
    - Reboot, then `emulator-traffic.sh vpn-start`: `tun0` comes up without the UI.
    - Consent revoked: `The user has not consented to the VPN…`, the service is destroyed,
      no crash, the process keeps running.
    - `emulator-traffic.sh run` is clean, and starting and stopping from the UI still works.
    - **Not verified:** the restart with a null intent. In five attempts (`am crash` and
      `kill -9`, app in the foreground and in the background) Android either scheduled no
      restart of the service, or stopped the restarted service as "app idle" before
      `onStartCommand()` ran. In none of them did the service crash. Whether the tunnel comes
      back after a process death therefore depends on Android delivering the restart, which
      it did on the morning of 2026-10-02 (V-58) and did not in these attempts.
- **Commit:** `fix(app): start the VPN service safely after a reboot or a process restart`

### PKT-41 — Take blocking connection setup off the outbound handler thread

- **Priority:** High · **Depends on:** PKT-39 (until then late ACKs corrupt streams)
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
- **Implementation notes (2026-10-02):**
  - Measured first; the table is in V-51. The database insert was two thirds of the time, so
    the order of work followed the numbers.
  - **Connection IDs and the insert.** `DatabaseConnector.persistTransportLayerConnection()` is
    no longer a `suspend` function. `RoomDatabaseConnector` assigns the ID itself (an
    `AtomicLong` seeded from `ConnectionDao.maxId()`) and writes the row in the background.
    The interface does not take the ID as a parameter, as the packet proposed: the connector
    owns it, which also keeps the test double simple. Every other call that names a
    connection ID first waits for that connection's pending insert, so a request or an update
    cannot reach the database before the row it refers to. No schema change.
  - `deleteDatabaseEntity()` no longer uses `runBlocking` either.
  - **Selector registration.** `InboundTrafficHandler` now only passes through
    `selectorMonitor` before each `select()` and processes the selected keys outside it.
  - **The rest of TCP setup** (app lookup, `protect()`, `connect()`, registration) runs in
    `TcpConnection.setUp()` on a background dispatcher, at most eight at a time. The device has
    only sent its SYN at that point and waits for the SYN-ACK, which is sent when the channel
    connects, as before. A connection the device resets during setup is not stored and its
    socket is never connected.
  - **Not done:** caching the UID-to-package lookup (0.03 ms, not worth it), `AppFinder` is
    unchanged. UDP setup still runs on the handler thread; its first datagram would have to
    be queued until setup is done, and only the insert was moved off the thread for it.
  - Tests: `RoomDatabaseConnectorTest` (three cases: IDs without waiting, later writes wait
    for the row, other connections do not wait) and `TcpConnectionSetupTest` (two cases). 284
    `core:vpn` tests pass.
  - Emulator, same three tests before and after (capture analysed with
    `tcp-capture-stats.py`; the "after" columns are two runs):

    | | Before | After |
    |---|---|---|
    | Setup time on the handler thread per connection, median / p99 / max | 12.9 / 384 / 2466 ms | not on the thread any more |
    | Port 443 (`tlsparallel`): time to ACK, median | 102 ms | 20 / 73 ms |
    | Port 443: p90 | 366 ms | 90 / 304 ms |
    | Port 443: segments retransmitted by the device | 4 of 280 | 1 of 324 / 1 of 294 |
    | Port 18080 (`parallel`, `churn`): p90 | 2678 ms | 826 / 420 ms |
    | Port 18080: segments retransmitted by the device | 264 of 2133 | 0 of 1870 / 1 of 1871 |
    | `parallel-250x20000` | one connect timeout | pass |

  - **The target "p90 below 50 ms" is not met**, and the numbers vary a lot between runs. A
    profile of the handler thread during `parallel` (simpleperf with off-CPU time) shows it
    idle 74 % of the time and no blocking call left in what remains. The largest part of it is
    being descheduled right after waking another thread (`CoroutineScheduler.tryUnpark` when a
    coroutine is launched for a connection's setup or for a TLS record). The emulator has four
    cores, and the selector thread, the coroutine workers and the garbage collector compete
    for them. That is the subject of V-55 (PKT-45), not of this packet.
  - Regression: the full `run-stress.sh` suite gives 66 passed, 6 failed. Five of the six are
    the known ones for later packets (`slowclient`, `duplex`, `unreachable-refused`, UDP 4000
    and 8000). The sixth, `udp-burst-500`, fails on the build before this packet too in the
    same session (243 to 369 of 500 on the old build, 235 to 354 on the new one).
    `emulator-traffic.sh run` is clean, and no database error was logged.
  - Throughput is unchanged between the two builds when run alternately (20 MB upload
    0.6 / 0.6 / 0.7 MB/s new against 0.6 old, 50 MB download 3.3 / 3.0 against 3.0, TLS 25 MB
    2.3 / 1.8 against 2.0). **These absolute numbers are far below the V-55 table** because the
    emulator itself was slower that afternoon: without the VPN the 50 MB download ran at
    5.1 MB/s, against 13.8 MB/s when the table was measured. They are only valid as a
    comparison of the two builds.
  - Test environment: Heimdall's database on the emulator had grown to 2.8 GB from the day's
    stress runs and filled the data partition. It was deleted (captured traffic only) before
    the final runs.
- **Commit:** `perf(vpn): keep database inserts and binder calls off the outbound packet thread`

### PKT-42 — Respect the device's receive window

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
- **Implementation notes (2026-10-02):**
  - **Window scaling.** Nothing to parse: the SYN-ACK carries no options, so scaling is in
    effect in neither direction and the header field is the window. Checked in a capture: the
    device's SYN offers `wscale`, its later segments advertise at most 65535.
  - **Send queue.** `wrapInbound()` appends to a per-connection queue. `flushSendQueue()`
    sends from it as long as `deviceWindow - (nextSeq - acknowledgedByDevice)` is positive.
    It runs when data is queued and when a segment from the device acknowledges data or
    changes the window (`handleAckField()`, called for every segment with the ACK flag).
    Everything that sets a sequence number (data, SYN-ACK, FIN, empty ACKs) runs under one
    lock, so segments are built in the order they are written.
  - **Read pausing.** The upstream channel is not read while more than 131 kB read from it
    has not reached the device (`SEND_BACKLOG_HIGH`); reading resumes at 32 kB. The upstream
    socket buffer then fills and TCP slows the remote host down. The backlog counts the queue
    plus what a TLS connection is still decrypting on its own dispatcher: `TlsConnection`
    reports that through `inboundProcessingDeferred()`/`inboundProcessingFinished()`, a
    three-line change in a file the packet did not list. Without it the selector thread could
    read arbitrarily far ahead of a MitM'd connection.
  - Interest changes do **not** go through `selectorMonitor`. Unlike `register()`,
    `interestOps()` does not wait for a `select()` in progress; a `wakeup()` is enough.
  - **The FIN waits for the queue.** `requestFin()` replaces the direct send. The connection
    is `CLOSING` from the moment the remote host closed, the FIN goes out when the queue is
    empty, and the sweep for stuck closes counts from the last progress, not from the request.
    A half-closed connection that is still sending counts as active for its sweep too.
  - **Probe.** If data has waited for the window for 10 s, the 30-second sweep sends an empty
    segment one below the next sequence number, which the device answers with its window.
    A safeguard only: the device announces an opening window itself and the TUN does not lose
    that.
  - **Zero-window probes from the device** need nothing new: the window Heimdall advertises
    is never zero (that is PKT-43), and the keep-alive form is answered since PKT-39.
  - Tests: `TcpReceiveWindowTest` (four cases) with a device side that acknowledges and
    advertises windows with real numbers. 288 `core:vpn` tests pass.
  - Emulator: `slowclient` and `duplex` pass (both failed before). A capture of `slowclient`
    shows 57 zero-window announcements from the device, 0 data segments sent while the window
    was zero (243 before), 0 segments beyond the window, and every byte acknowledged.
  - Regression: the full suite gives 68 passed, 4 failed: UDP 4000 and 8000 (PKT-46),
    `unreachable-refused` (PKT-44) and `udp-burst-500`, which already failed before PKT-41.
    `emulator-traffic.sh run` is clean.
  - Throughput is unchanged against the previous build in alternating runs (50 MB download
    3.5 MB/s on both, TLS 25 MB 2.2 to 2.3 against 2.4, 20 MB upload 0.7 against 0.6). The
    emulator is still slow overall: 5.2 MB/s for the download without the VPN.
  - Not changed: data from the device that arrives after the remote host has closed still
    resets the connection (`Got ACK (data, invalid state CLOSING)`). With the FIN now waiting
    for the queue, that state can last longer than before.
  - `slowupload` passes in this run (4 MB in 10.9 s, other requests at most 594 ms). The loop
    that V-50 describes is still in `wrapOutbound()`, so PKT-43 remains, but its device check
    no longer distinguishes before from after.
- **Commit:** `fix(vpn): honour the device's TCP receive window instead of sending regardless`

### PKT-43 — Queue outbound data per connection and apply backpressure

- **Priority:** High · **Depends on:** PKT-39, PKT-42 (shares the selector-interest handling)
- **Resolves:** V-50
- **Approach:**
  - `wrapOutbound()` writes what the channel takes. What is left goes into a per-connection
    queue, and `OP_WRITE` is set; `InboundTrafficHandler` drains the queue when the channel is
    writable. No loop that waits for the channel.
  - The window we advertise to the device is the free space of that queue (bounded, e.g.
    256 KB), so a slow upstream slows the app down instead of the handler thread. Segments that
    arrive beyond it are dropped and re-ACKed, as in PKT-39.
  - A half-close (PKT-30) and a close wait until the queue is drained.
  - The same for `UdpConnection.wrapOutbound()`: a datagram the channel does not take is
    dropped, not retried in a loop.
- **Files:** `connection/transportLayer/TcpConnection.kt`, `UdpConnection.kt`,
  `components/InboundTrafficHandler.kt`.
- **Tests:** an integration test with an upstream that does not read: the handler thread
  returns from `unwrapOutbound()` promptly, the advertised window shrinks to zero, and the data
  arrives intact once the upstream reads. Device: `run-stress.sh slowupload` passes both checks.
- **Implementation notes (2026-10-02):**
  - **Write queue.** `TcpConnection.wrapOutbound()` writes once. What the channel does not take
    goes into a per-connection queue and `OP_WRITE` is set; the selector thread writes the
    queue out when the channel is writable (`drainOutQueue()`, reached through
    `unwrapInbound()`, so `InboundTrafficHandler` itself did not change). No loop is left.
    The key's interest set now depends on both directions and is set in one place
    (`updateInterest()`).
  - **Advertised window.** Every segment to the device carries
    `min(65535, 256 kB - backlog)` as its window; it used to echo the window from the device's
    SYN. The backlog is the queue plus what a TLS connection is still processing on its own
    dispatcher (`outboundProcessingDeferred()`/`Finished()` in `TlsConnection`, the mirror of
    PKT-42's inbound pair). When room opens by 16 kB or more, the device is told with an ACK
    of its own.
  - Data is now acknowledged **after** it has been passed on, so the window in the ACK
    already accounts for it. A window once advertised is not taken back: a segment is dropped
    and re-ACKed only if it reaches beyond the furthest edge the device was ever told.
  - **Half-close and close wait for the queue.** `shutdownOutput()` after the device's FIN, and
    the close of the channel when the encryption layer cannot carry a half-close, happen once
    the backlog is written. For the close the connection stays `CLOSING` and in the cache
    until then, even if the closing handshake with the device is already complete; the
    existing two-minute sweep bounds it. Because the backlog includes data still inside the
    TLS layer, this also closes a gap that was there before: a FIN from the device could shut
    the channel while the last records were still being processed.
  - `UdpConnection.wrapOutbound()` makes one attempt and logs a datagram the channel did not
    take.
  - Tests: `TcpUpstreamBackpressureTest` (two cases) against a server that does not read,
    with a device side that sends only inside the advertised window. 290 `core:vpn` tests
    pass.
  - Emulator: `slowupload` passes both checks, but it did before (see the PKT-42 notes): a
    4 MB upload fits into the socket buffers. With 20 MB to a server reading 300 kB/s the
    difference shows in the packet thread's CPU time over the 67 s of the upload: 55.4 s
    before, 21.2 s after. Small requests alongside were answered in both builds (slowest
    1.5 s before, 1.2 s after). In a capture of `slowupload` Heimdall now advertises a
    shrinking window (745 segments below 65535, 8 with 0); before, none.
  - Regression: the full suite gives 68 passed, 4 failed, the same four as after PKT-42 (UDP
    4000 and 8000, `unreachable-refused`, `udp-burst-500`). `emulator-traffic.sh run` is
    clean. Throughput is unchanged against the previous build in alternating runs (50 MB
    download 3.1 to 3.3 MB/s against 2.9, 20 MB upload 0.7 on both, TLS 25 MB 2.2 to 2.3
    against 2.4 to 2.5).
  - **Found on the way, for PKT-45:** the device uploads in 536-byte segments (7500 segments
    for 4 MB). The SYN-ACK carries no MSS option, so the device falls back to the default
    MSS. The remaining 21 s of packet-thread CPU for a 20 MB upload is the per-segment cost
    of those 37,000 segments, each with two `Timber.d` lines in `HttpConnection`.
- **Commit:** `fix(vpn): queue outbound data per connection instead of busy-waiting on a slow upstream`

### PKT-44 — Signal upstream connect failures and resets to the client

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
- **Implementation notes (2026-10-02):**
  - `buildRst()` always sets the ACK flag. Before our SYN-ACK was sent it uses sequence
    number 0 and acknowledges the device's SYN; afterwards it uses our next sequence number.
  - A setup that fails before the connect is even under way (for example `protect()` or
    `connect()` throwing) used to leave the connection `ABORTED` in the cache without telling
    the device. It now takes the same `closeHard()` path as a refused connect.
    `getInstance()` removes a connection that was already closed by the time it was put into
    the cache, which that makes possible because setup runs on another thread (PKT-41).
  - An `IOException` from the read no longer counts as end-of-stream:
    `unwrapInboundReadable()` resets the connection. Data still queued for the device is
    dropped with it, as a reset implies.
  - `getInstance()` ignores a packet for an unknown flow that has RST set. Stray FINs and
    ACKs are still answered with a reset as before.
  - Tests: four new cases in `ConnectionTeardownTest` (refused connect, failed setup, upstream
    reset, stray reset). 294 `core:vpn` tests pass.
  - Emulator: `unreachable-refused` fails with `ECONNREFUSED` after 0.7 s (it ran into the
    client's 6 s connect timeout before; 44 ms without the VPN). `serverabort-rst` ends with
    `Connection reset` after 1.1 s, as it does without the VPN. `clientabort` passes.
  - Regression: the full suite gives 67 passed, 5 failed. Three are the known UDP ones (4000,
    8000, burst). Two were DNS lookups that failed in the `tls` tests
    (`Unable to resolve host`); `tls,tlsparallel` passed 20 of 20 in three reruns, and a
    lookup failed the same way once before this packet (PKT-41 "before" run), so this is
    intermittent and not from this change. It was not investigated. `emulator-traffic.sh run`
    is clean.
  - The log no longer shows `Resetting unknown TCP packet (RST)`, which was the most frequent
    warning in the previous run (about 130 lines).
- **Commit:** `fix(vpn): reset the client correctly when the upstream refuses or resets the connection`

### PKT-45 — Find and remove the upload bottleneck

- **Priority:** Medium · **Depends on:** PKT-34, PKT-41, PKT-43
- **Resolves:** V-55
- **Approach:**
  - **Send an MSS option in the SYN-ACK** (found while verifying PKT-43): without one the
    device assumes 536 bytes and uploads in segments a third of the size it could use. Offer
    the tunnel MTU minus 40. Consider offering window scaling in the same step, now that
    both windows are honoured (PKT-42, PKT-43); without it neither direction can have more
    than 65535 bytes in flight.
  - Profile a 20 MB plain upload on the emulator (method tracing or simpleperf on the outbound
    handler thread) after the packets above are in, and record where the time goes.
  - The byte counters are batched by PKT-38 already. Look at what is left: per-segment ACKs,
    the blocking write, and the application-layer parsing on the handler thread.
  - Demote the per-payload `Timber.d` lines in `HttpConnection` to a debug flag.
- **Files:** `connection/transportLayer/TransportLayerConnection.kt`,
  `connection/appLayer/HttpConnection.kt`.
- **Tests:** byte counters in `RecordingDatabaseConnector` still match the bytes transferred
  after close. Device: record `run-stress.sh download,upload,tlsbulk` rates in the V-55 table.
- **Implementation notes (2026-10-02):**
  - **MSS.** The SYN-ACK now carries a maximum-segment-size option with the value the device
    announced in its own SYN (1460 on the emulator; `TcpConnection.buildSynAck()`). A device
    that announced none is told none. The device's upload segments went from 533 to 1438
    bytes on average, 39,400 to 14,600 segments for the test run, and the 20 MB upload from
    0.9 to 2.5 MB/s.
  - **Profile** (simpleperf, packet thread during a 20 MB plain upload, after the MSS change):
    51 % of the thread's time was `Timber.d`. The debug tree takes a stack trace for every
    line to find its tag (36 %), and `HttpConnection` wrote two lines per segment. The
    upstream write was 17 %, building and sending the ACK 19 %.
  - **Logging.** The two per-payload lines in `HttpConnection` and the two in `RawConnection`
    are behind a `log` flag that is off, as `TlsConnection` already does it. This took the
    upload from 2.5 to 6.0 MB/s, and it helps downloads as much, because the same line was
    written for every inbound payload on the selector thread.
  - Packet thread CPU for the test run: 24 to 26 s before, 3.2 s after. The rates are in the
    V-55 table.
  - **Window scaling was not added.** Nothing in the measurements points at the 65535-byte
    windows: downloads run at the rate of the direct path with them.
  - **What is left** (profile after both changes): the packet thread spends 35 % in the
    upstream `write()` and 37 % on the ACK it sends for every segment, two thirds of that in
    pcap4j building the IP and TCP packet objects. The poll thread spends 37 % parsing each
    packet with pcap4j, and the device write thread carries one ACK per segment. Options, none
    taken here: acknowledge every second segment, build ACKs without pcap4j, or raise the
    tunnel MTU (1500 today, `Builder.setMtu()` is never called) so that the device sends
    fewer, larger segments.
  - Tests: `TcpConnectionSetupTest` checks the option in the SYN-ACK as the device parses it.
    The byte counter tests are unchanged and pass. 295 `core:vpn` tests pass.
  - Regression: the full suite gives 69 passed, 3 failed (UDP 4000, 8000 and burst, as
    before). `emulator-traffic.sh run` is clean.
  - `TransportLayerConnection.kt`, listed under Files, did not need to change.
- **Commit:** `perf(vpn): announce an MSS to the device and stop logging every payload`

### PKT-46 — Handle UDP datagrams larger than the MTU

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
- **Implementation notes (2026-10-02):**
  - **Traced first.** A capture on `tun0` shows the device sending a 4000-byte datagram as
    three IP fragments and an 8000-byte one as six. pcap4j parses a fragment's payload as a
    `FragmentedPacket`, `DevicePollThread` forwards only TCP and UDP payloads, so every
    fragment was dropped there. Nothing came back because nothing went out: the outbound
    direction failed first.
  - **Outbound.** New `IpV4Reassembler` (in `components/`), used by `DevicePollThread` before
    a packet goes to the handler. Fragments are collected by source, destination,
    identification and protocol; when they cover the datagram without gaps it is rebuilt with
    `IpV4Helper.defragment`. Incomplete datagrams are dropped after 5 s, at most 64 are held.
    `UdpConnection.wrapOutbound()` no longer copies the payload into its 16 kB buffer, which a
    reassembled datagram can exceed.
  - **Inbound fragmentation was not implemented**, because it turned out not to be needed.
    With reassembly in place the echoes pass, and the capture shows the replies reaching the
    device as single IP packets of 4028 and 8028 bytes. The device accepts packets larger than
    the MTU from the tunnel, as it does the 16 kB TCP segments Heimdall has always written.
    `IpV4PacketBuilder.kt`, listed under Files, is unchanged.
  - Remaining limit: an inbound datagram larger than the 16,413-byte read buffer is cut off.
    `UdpConnection` now logs a warning when a datagram fills the buffer. IPv6 fragments (an
    extension header, not a header flag) are not reassembled.
  - Tests: `IpV4ReassemblerTest` (six cases: in order, out of order and repeated,
    interleaved datagrams, timeout, bound on pending datagrams, an unfragmented packet).
    301 `core:vpn` tests pass.
  - Emulator, `run-stress.sh udp`, four runs per build in alternation: `udp-echo-4000` and
    `udp-echo-8000` pass 4 of 4 with this packet and 0 of 4 without.
  - **`udp-burst-500` is not a Heimdall failure.** It failed in 2 of 8 of these runs across
    both builds (228 to 285 of 500) and in the run **without the VPN** as well (228 of 500).
    The emulator's own NAT drops part of a burst, as the test's source already notes. This is
    the check listed as failing since PKT-41.
  - Regression: the full suite gives 71 passed, 1 failed (`udp-burst-500`, 382 of 500).
    `emulator-traffic.sh run` is clean.
- **Commit:** `feat(vpn): reassemble fragmented UDP datagrams from the device`

### PKT-47 — Release the selector and pipe descriptors when the VPN stops

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
- **Implementation notes (2026-10-02):**
  - `stopComponents()` now closes the selector after the connection cache has been cleared,
    and both ends of the interrupter pipe.
  - **The pipe is closed the other way round.** The code used to close the read end, the one
    `DevicePollThread` polls, and never the write end. Closing a descriptor another thread is
    polling does not reliably wake it. Now the write end is closed, the poll reports a
    hang-up, and the read end is closed once the thread has finished.
  - All four traffic threads are joined (2 s each at most, with a warning if one does not
    stop) before the pipe, the tunnel streams and the selector are released. That covers
    V-28. `InboundTrafficHandler` ends its loop on `ClosedSelectorException`, for the case
    that it was not waited for.
  - `stopComponents()` is guarded against running twice: a second run would close descriptor
    numbers that may already belong to something else.
  - No unit test, as the packet anticipated. 301 `core:vpn` tests pass unchanged.
  - Emulator, ten start/stop cycles with `parallel` traffic running at each stop, descriptors
    of the Heimdall process:

    | | Before | After |
    |---|---|---|
    | After the first start | 112 | 111 |
    | After ten cycles, VPN stopped | 345 | 111 |
    | The same after a forced GC | 344 | 105 |
    | of which `/dev/null` (closed channels the selector still held) | 208 | 10 |
    | of which pipes | 51 | 10 |

    Between cycles the new build shows up to about 20 extra pipes; they are garbage that the
    next collection releases, not a leak. Stopping takes 1.5 to 1.9 s per cycle, as before,
    no thread missed its join, and nothing was logged about a failed close.
  - Regression: the full suite gives 71 passed, 1 failed; `emulator-traffic.sh run` is clean.
  - **The one failure is unexplained.** One of the 40 `tlsclose` requests ended with
    `Connection reset` after 534 s, far beyond the client's timeouts, with no certificate
    seen. The log of that run was not kept. It did not repeat in four further runs of
    `tlsclose` (160 requests), and this packet only changes the stop path, but neither is
    proof that it is unrelated. If it shows again, the run's full log is the thing to keep
    (`run-stress.sh` prints where it saved it).
  - In one of those four reruns the 25 MB TLS download ended with `Connection reset` after
    7.7 MB. The log shows the cause outside Heimdall: `tcp6983 Error reading from
    SocketChannel (IOException: Connection reset by peer)`, i.e. the remote side or the
    emulator's NAT reset the upstream connection, and Heimdall passed that on as PKT-44
    intends. Before PKT-44 the same event would have looked like a truncated download.
- **Commit:** `fix(vpn): close the selector and the interrupter pipe when the VPN stops`

### PKT-48 — Buffer segments that arrive ahead of a gap

- **Priority:** Medium · **Depends on:** PKT-39; best after PKT-42 (both touch the window)
- **Resolves:** V-57
- **Approach:**
  - In `TcpConnection.acceptInOrder()`, keep a segment that starts above the expected sequence
    number instead of dropping it, in a per-connection map ordered by sequence number. Still
    answer with an ACK for the expected sequence number.
  - When a segment fills the gap, forward it and then every buffered segment that follows
    without a gap, and acknowledge the last one.
  - Bound the buffer by the window Heimdall advertises (65,535 bytes today). Anything beyond
    it is dropped as now. Free the buffer when the connection closes.
  - Do not add SACK. With the buffer a single retransmission fills a gap, which is what the
    device's fast retransmit sends.
- **Files:** `connection/transportLayer/TcpConnection.kt`.
- **Tests:** `TcpSegmentValidationTest`: change the out-of-order case so that the overtaking
  segment is **not** sent again and the stream still arrives complete; a segment beyond the
  window is dropped; duplicates of buffered segments are ignored. Device: with
  `tc qdisc add dev tun0 root netem duplicate 5% delay 2ms reorder 5% loss 1%`,
  `run-stress.sh upload,tlsbulk` passes.
- **Implementation notes (2026-10-02):**
  - `acceptInOrder()` now hands a segment that starts above the expected sequence number to
    `bufferSegment()` instead of dropping it, and still answers with an ACK for the expected
    number. After every segment that was taken in, `deliverBufferedSegments()` takes in what
    has become next, through the same `acceptInOrder()` as a segment from the device, so
    overlaps, duplicates and a buffered FIN are handled by the existing rules.
  - Bounds: only a segment that lies inside the furthest window edge the device was told
    (PKT-43) is kept, and at most 65535 bytes in total. A sequence number that is already
    waiting is not stored twice. The buffer is dropped when the connection stops accepting
    data (half-closed, closing, closed).
  - No SACK, as planned.
  - Tests: `TcpSegmentValidationTest` has the out-of-order case rewritten (the overtaking
    segment is not sent again) and two new cases (several segments behind a gap in the wrong
    order with a duplicate; a segment beyond the window is not kept). 303 `core:vpn` tests
    pass.
  - Emulator, with `netem duplicate 5% delay 2ms reorder 5% loss 1%` on `tun0`,
    `run-stress.sh upload,tlsbulk,keepalive`:

    | | Before | After |
    |---|---|---|
    | Checks passed / failed | 8 / 2 | 10 / 0 |
    | 1 MB upload | timeout after 160 s | 1.1 s |
    | 20 MB upload | 455 s | 20.6 s |
    | TLS 5 MB upload | reset after 83 s | 5.4 s |

    No `BAD_RECORD_MAC` in either run.
  - Regression without injected faults: the full suite gives 72 passed, 0 failed, the first
    run of the whole suite without a failure. Throughput is as after PKT-45 (20 MB upload
    8.5 MB/s, 50 MB download 5.7 MB/s). `emulator-traffic.sh run` is clean.
- **Commit:** `fix(vpn): buffer out-of-order segments from the device until the gap before them is filled`

**Order for PKT-30 to PKT-48:** all done. The QUIC packets (PKT-49 to PKT-52) are next:
passed-through and blocked QUIC both rely on the UDP path and on a TLS fallback that works.

### PKT-49 — Decrypt QUIC v1/v2 client Initial packets

- **Priority:** Medium · **Depends on:** —
- **Resolves:** — (enabler for PKT-50) · **Phase:** Q1, part 1
- **Approach:** new package `quic/` inside `connection/encryptionLayer/`. 
  - Plain JCA only (`Mac "HmacSHA256"`, `AES/ECB/NoPadding`, `AES/GCM/NoPadding`), 
    all available on API 24. No new dependency.
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
    CRYPTO frames. Validate it by reproducing the RFC 9001 A.2 packet. PKT-50 and PKT-52 use it.
- **Implementation notes (2026-10-03):**
  - As planned: `quic/QuicVarInt.kt` (decode, plus encode for the fixture and later use),
    `quic/QuicInitialKeys.kt` (`forClient`, and `forServer` for the RFC vectors),
    `quic/QuicInitialPacket.kt` (`decrypt(datagram, offset, keys)`). Plain JCA, no dependency.
  - `decrypt()` takes optional keys: PKT-50 needs to keep the keys of the first Initial when
    later ones name another connection ID. `AuthenticationFailed` carries the packet's
    connection ID so the caller can retry with keys derived from it.
  - Packet types: other long header types are skipped by their length field; Retry, Version
    Negotiation and short header packets take the rest of the datagram; an unknown version
    stops the walk, since its layout is unknown. Only the long-header bit is required, not
    the fixed bit, which a peer may grease (RFC 9287).
  - The truncated packet number is used as the full one; client Initials start at the lowest
    numbers, so that is what RFC 9000 Appendix A.3 gives with no packet received yet.
  - Test vectors: the RFC 9001 and RFC 9369 Appendix A values were copied from the RFC texts
    by a script into `integration/support/QuicRfcVectors.kt`, not typed in.
  - Tests: `QuicVarIntTest` (RFC 9000 examples), `QuicInitialKeysTest` (secrets and keys of
    both RFCs, client and server), `QuicInitialPacketTest` (client and server Initials of both
    RFCs; the fixture reproducing all four sample packets byte for byte; a changed byte and
    wrong keys fail authentication; truncation; skipping coalesced Handshake, Retry, Version
    Negotiation and short header packets; 2000 random or damaged inputs without an exception;
    fixture flights over one to three datagrams, shuffled, rebuild the ClientHello). 320
    `core:vpn` tests pass.
  - `integration/support/QuicInitialFixtures.kt` also builds ClientHellos with an SNI, an ALPN
    list and padding to any size, for PKT-50's multi-datagram cases.
  - **Real traffic.** Nothing is wired in yet, so the device check was a capture: UDP/443 on
    `tun0` while `emulator-traffic.sh run apps` ran, the client's Initial datagrams decrypted
    with this code through a throwaway test (not committed). Four Initials from the Play Store
    (packet numbers 1, 2, 4, 5) all decrypted. The ClientHello is 1741 bytes over two
    datagrams in 11 out-of-order CRYPTO frames, and parses to SNI `play-fe.googleapis.com`,
    ALPN `h3`, ECH offered. The fourth Initial already names another connection ID and
    decrypts only with the first one's keys. This confirms PKT-50's assumptions: keep the
    first keys, reassemble across datagrams, expect shuffled frames and ACK frames.
- **Commit:** `feat(vpn): decrypt QUIC v1/v2 client Initial packets`

### PKT-50 — Record SNI and ALPN of QUIC flows from the Initial packet

- **Priority:** Medium · **Depends on:** PKT-26, PKT-27, PKT-28, PKT-29, PKT-49
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
    alter traffic (PKT-52 changes this order only under the Block policy). On `Complete`, call
    `persistSecurity(QUIC, sni, alpn, echOffered)` and `transportLayer.refineRemoteHost(...)`.
    The inspector is touched only from the outbound handler thread. Remove the `//TODO`
    placeholders this replaces; keep the unconditional `doMitm = false`.
  - **An inspector failure must not cost the flow.** `OutboundTrafficHandler` closes a
    connection on any uncaught exception. Wrap the call to `offer()`: an exception is logged
    once and counts as `GaveUp`.
  - **No log line per datagram.** `Timber.d` on a per-packet path cost half of the packet
    thread's time (PKT-45). Log only when the inspector reaches a terminal result.
- **Revised 2026-10-02:** the two points above and the scripted device check are new.
- **Files:** new `quic/QuicInitialInspector.kt`, `connection/encryptionLayer/QuicConnection.kt`,
  `scripts/emulator-traffic.sh`.
- **Tests:**
  - `QuicInitialInspectorTest`: single-packet ClientHello; ClientHello over two datagrams;
    shuffled CRYPTO frames with PING and PADDING between them; an unknown version and random
    bytes both give up without throwing; the datagram limit is honoured.
  - `integration/QuicPassthroughInspectionTest`, in the style of `TlsMitmHttpFlowTest`: push
    fixture datagrams through a `UdpConnection` towards a local `DatagramSocket`. Assert the
    socket receives them byte-identical and in order, and that `RecordingDatabaseConnector`
    holds `QUIC`, the SNI, the ALPN and the refined hostname. One case with an inspector that
    throws: the datagrams are still forwarded and the connection stays open.
  - **Device.** New group `quic` in `scripts/emulator-traffic.sh`, built like the `tls` group:
    it sends canned client Initial datagrams with `nc -u`. Initial keys depend only on the
    version and the Destination Connection ID, so a datagram produced once by PKT-49's
    `QuicInitialFixtures` stays valid; embed it as hex (add a small `main`-style test or
    Gradle task note on how the hex was produced). Cases: `h3` with an SNI; a non-h3 ALPN;
    a ClientHello over two datagrams; QUIC v2. Expected in the report: one `UDP / QUIC` row
    per case with the SNI and ALPN filled in. Also run the `apps` group once and note how
    many of its QUIC rows carry an SNI.
- **Implementation notes (2026-10-03):**
  - `quic/QuicInitialInspector.kt` as planned. CRYPTO data is collected into a buffer of
    `maxCryptoBytes` with a bit set of the bytes received, so overlapping and repeated frames
    are harmless; the ClientHello is complete when the bytes from 0 to its declared length are
    all there. ACK frames (both types) are skipped, a CONNECTION_CLOSE or any other frame type
    ends the inspection. A first datagram with no decryptable Initial gives up at once.
  - `QuicConnection` forwards each datagram, then offers it to the inspector, and drops the
    inspector when it has a result, so later datagrams of the flow cost nothing extra. An
    exception from the inspector counts as giving up; one log line per flow.
  - **Bug found on the device and fixed:** in one run a canned flow got its hostname from the
    SNI but no SNI or ALPN in its row. `QuicConnection` writes the security fields twice in
    quick succession (the `QUIC` label when the flow is created, then what the ClientHello
    revealed), each from its own coroutine, and the earlier write landed last. Each write
    replaces all the fields, so `EncryptionLayerConnection.persistSecurity()` now chains a
    connection's writes so that they land in the order they were made. TLS writes only once,
    but gets the same guarantee. A test that delays the first write fails without the change.
  - Tests: `QuicInitialInspectorTest` (ten cases: the RFC sample; one datagram in v1 and v2;
    two datagrams in order and shuffled; the second half first; a later Initial naming another
    connection ID; a Retry; ACK frames; an unknown version, random input and a damaged
    Initial; the datagram limit; the buffer limit). `QuicPassthroughInspectionTest` (four
    cases through a real `UdpConnection` and socket: datagrams arrive unchanged and the row
    gets QUIC, SNI, ALPN and the hostname; the write order; an unreadable ClientHello; an
    inspector that throws). `QuicCannedInitialsTest` keeps `scripts/quic-initials.txt` in sync
    with the fixture and checks every canned flight. 335 `core:vpn` tests pass.
  - `scripts/emulator-traffic.sh` has the `quic` group (cases `h3`, `doq`, `split`, `v2`, sent
    to `10.0.2.2:443`). The datagrams are in `scripts/quic-initials.txt`, written by
    `QuicCannedInitialsTest` when `HEIMDALL_WRITE_QUIC_INITIALS=1` is set. The script needs
    `xxd` now.
  - Emulator: all four canned cases appear as QUIC rows with SNI, ALPN and the SNI as
    hostname, version 2 included, in three runs after the fix. The `apps` group produced three
    QUIC flows (Play Store, Google services framework), all three with SNI, ALPN `h3` and ECH
    offered. The full traffic script is clean, and `run-stress.sh udp,tls` passes 28 of 28.
- **Commit:** `feat(vpn): record SNI and ALPN of QUIC flows from the Initial packet`

### PKT-51 — Add the QUIC policy preference

- **Priority:** High · **Depends on:** —
- **Resolves:** — (enabler for PKT-52) · **Phase:** Q2, part 1
- **Decided:** the policy is a user preference with two values, Block and Passthrough
  (2026-10-01). The default is **Passthrough** (2026-10-02; the earlier text assumed Block).
  Block only takes effect while MitM is enabled.
- **Revised 2026-10-02:** the default and with it the enum numbering; the per-session override.
- **Approach:**
  - **Proto.** `enum MitmQuicPolicy { QUIC_PASSTHROUGH = 0; QUIC_BLOCK = 1; }` and field
    `MitmQuicPolicy mitm_quic_policy = 50` in `preferences.proto` (50 is free; 49 is the
    highest in use). Passthrough is the zero value, so existing installs, which have no
    stored value, get the default without a special case in the serializer.
  - **Datastore.** `PreferencesInitialValues.mitmQuicPolicyInitial`, the serializer default,
    and `PreferencesDataSource.mitmQuicPolicy` with a setter, following
    `mitmTrustAllUpstreamCerts`.
  - **Core.** New `quic/QuicPolicy.kt` (`PASSTHROUGH, BLOCK`). `core:vpn` must not depend on the
    preference schema, as with `MitmScope`. Add `ComponentManager(quicPolicy: QuicPolicy = QuicPolicy.PASSTHROUGH)`.
  - **App.** `HeimdallVpnService.launchServiceComponents()` maps the preference and forces
    `PASSTHROUGH` when MitM is off. `MitMPreferences` in `TrafficScannerPreferences.kt` gets a
    `BooleanPreference` "Block QUIC (force TLS fallback)", off by default.
  - **Per-session override, for scripted tests.** `onStartCommand()` reads an optional string
    extra `QUIC_POLICY_EXTRA` (`block` or `passthrough`) next to `SESSION_ID_EXTRA` and hands
    it to `launchServiceComponents()`, where it replaces the preference for that session. The
    stored preference is not changed. The service is not exported, so only the app itself or
    a root shell can pass it. `scripts/emulator-traffic.sh vpn-start` (and `run`) get an
    option `--quic-policy block|passthrough` that passes the extra.
- **Files:** `core/datastore-proto/.../preferences.proto`,
  `core/datastore/.../{PreferencesInitialValues,PreferencesSerializer,PreferencesDataSource}.kt`,
  new `quic/QuicPolicy.kt`, `components/ComponentManager.kt`,
  `app/.../service/HeimdallVpnService.kt`,
  `app/.../ui/scanner/traffic/TrafficScannerPreferences.kt`, `scripts/emulator-traffic.sh`.
- **Tests:** stub `componentManager.quicPolicy` explicitly in `ComponentManagerFixtures` (a
  relaxed mock would return a mock enum) with a `quicPolicy` parameter defaulting to
  `PASSTHROUGH`. Behaviour is covered by PKT-52. Device: `vpn-start --quic-policy block`
  logs the policy the session runs with, and a start without the option logs `PASSTHROUGH`
  on a fresh install.
- **Implementation notes (2026-10-03):**
  - As planned for the proto (`MitmQuicPolicy`, field 50), the datastore, `quic/QuicPolicy.kt`
    and `ComponentManager(quicPolicy)`. No database change.
  - The mapping lives in a new `app/.../service/QuicPolicyResolver.kt`, next to
    `MitmScopeResolver`: MitM off gives `PASSTHROUGH` whatever is stored or requested; else the
    session override (`block`/`passthrough`, case-insensitive) wins; else the preference. An
    unknown override value or an `UNRECOGNIZED` stored value falls back to the next rule.
  - `HeimdallVpnService.QUIC_POLICY_EXTRA` is read in `onStartCommand()` and handed to
    `launchServiceComponents()`, which logs `QUIC policy: …` (with the override, if any).
  - `scripts/emulator-traffic.sh`: `--quic-policy block|passthrough` before the command's
    groups, for `vpn-start` and `run`; the "tun0 is up" line now shows the policy. `--install`
    is parsed the same way. `vpn-start`/`vpn-stop` now reject arguments they do not know,
    after a test call whose option was passed as one word was silently ignored.
  - Tests: `QuicPolicyResolverTest` (app, four cases, including that an install without the
    field reads Passthrough). `ComponentManagerFixtures` stubs `quicPolicy`. 335 `core:vpn`
    and 15 `app` tests pass.
  - Emulator, MitM on: a start without the option logs `PASSTHROUGH`; `--quic-policy block`
    logs `BLOCK (session override 'block')`, and the next plain start is `PASSTHROUGH` again,
    so the stored value is untouched. The new switch "Block QUIC (force TLS fallback)" is
    shown off; switched on, a plain start logs `BLOCK` and `--quic-policy passthrough` still
    wins; the switch keeps its state when the screen is reopened; switched off again (as it
    was left), a plain start logs `PASSTHROUGH`. A session with `--quic-policy block` runs
    normally; nothing is blocked yet, that is PKT-52.
- **Commit:** `feat(prefs): add a QUIC policy preference (block or passthrough)`

### PKT-52 — Block HTTP/3 over QUIC while MitM is on

- **Priority:** High · **Depends on:** PKT-50, PKT-51
- **Resolves:** V-41 · **Phase:** Q2, part 2
- **Approach:**
  - **Decision.** Taken in `QuicConnection` once the inspector is terminal. Block only if all
    of these hold, which together mean "the TLS fallback would actually be intercepted":
    - `componentManager.quicPolicy == BLOCK` and `componentManager.doMitm`;
    - the inspector completed and the ALPN offer contains `h3` or an `h3-*` draft token;
    - the TLS path would intercept this app and host.

    If the inspector gave up (unknown version, undecryptable, limits hit), forward, whatever
    the policy.
  - **One decision shared with the TLS path.** `TlsConnection` decides with the SNI if there
    is one, else the DNS-derived name, else the IP address (`TlsConnection.kt:77, 281`), and
    checks `mitmScope.shouldIntercept(appPackage, hostname)` and the passthrough cache with
    that value (`:294-295`). That is not always the transport connection's refined hostname:
    with ECH offered, `refineRemoteHost()` keeps an existing DNS name while the TLS path uses
    the SNI. The QUIC rule predicts what the TLS fallback will do, so it has to use the same
    value. Move the host choice and the two checks into one function on
    `EncryptionLayerConnection` (for example `wouldIntercept(sni: String?): Boolean`) and
    call it from both classes, so that they cannot drift apart.
  - **No port condition.** An earlier version of this packet also required port 443. The
    ALPN offer already identifies HTTP/3; QUIC protocols without a TCP fallback (DoQ, media,
    games) offer other ALPNs and pass. The TLS MitM is not tied to a port either.
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
      header; that is what the kernel matches against the app's socket. The UDP header is
      the dropped datagram's own (`QuicConnection.unwrapOutbound(packet)` receives the
      `UdpPacket`), the IPv4 header is reconstructed from `ipPacketBuilder`. Source of the
      ICMP packet is the remote address, destination the local one.
    - IPv4 only. An IPv6 flow is dropped silently; the VPN routes IPv4 only today.
    - Post it with a new `DeviceWriteThread.WRITE_ICMP` code.
  - **Lifecycle.** The flow stays in `ConnectionCache`, so the client's retransmissions hit the
    blocked flag instead of creating new connections and rows. The existing UDP idle sweep
    (PKT-13) reaps it after five minutes. Its socket is released at once: call
    `transportLayer.closeSoft()` when the flow is blocked. That closes the `DatagramChannel`
    and leaves the cache entry; `UdpConnection.unwrapOutbound()` still reaches
    `QuicConnection`, which drops. Without it every blocked attempt holds a socket and two
    16 kB buffers' worth of connection for five minutes.
  - **Out of scope:** stripping `h3` from `Alt-Svc` headers and from DNS HTTPS/SVCB records.
    Both need rewriting that the application layer cannot do yet.
- **Revised 2026-10-02:** the shared decision, no port condition, the socket release, the
  quoted UDP header, and the scripted device check.
- **Files:** `connection/encryptionLayer/QuicConnection.kt`,
  `connection/encryptionLayer/EncryptionLayerConnection.kt`, `TlsConnection.kt` (the shared
  decision), new `connection/inetLayer/IcmpUnreachableBuilder.kt`,
  `components/DeviceWriteThread.kt`.
- **Tests:**
  - `IcmpUnreachableBuilderTest`: type and code, the quoted header, checksum, swapped addresses.
  - `integration/QuicBlockPolicyTest`, with `RecordingDeviceWriter` and a local `DatagramSocket`:
    - An in-scope h3 flow is blocked: nothing reaches the socket, an ICMP packet is written to
      the device, the row is marked blocked, and the flow's `DatagramChannel` is closed.
    - Each of these forwards byte-identical instead: a non-h3 ALPN; a host outside the
      `MitmScope`; a host with learned passthrough; MitM off; the Passthrough policy; an
      undecryptable Initial.
    - With ECH offered and a DNS name that differs from the SNI, the scope and the
      passthrough cache are consulted with the SNI, as the TLS path does.
    - A ClientHello spanning two datagrams is flushed in order when the verdict is "forward".
    - Retransmitted datagrams of a blocked flow create no further connection rows.
  - The existing TLS tests cover the shared decision from the TLS side and must stay green.
- **Device:** `emulator-traffic.sh run --quic-policy block quic` with MitM on. Expected:
  - the h3 Initial is answered with "connection refused" on the sending UDP socket. That is
    the ICMP error reaching the app, and the first real check that one written to the TUN
    does. If it does not arrive, fallback still happens, only after the client's own timeout;
    record which it is;
  - that flow's row is `blocked`; the non-h3 case is forwarded and not blocked;
  - the same run with `--quic-policy passthrough` blocks nothing.

  Then one run of the `apps` group under Block as a sanity check with real clients. What to
  expect there: Chrome is excluded from the VPN while MitM is on, and Cronet-based apps
  (Play Store, YouTube, Play services) reject the forged certificate on the TLS fallback, so
  after the first blocked attempt their host is learned as passthrough and their QUIC is
  forwarded again. Blocked rows followed by forwarded ones for the same host are therefore
  correct, not a failure.
- **Implementation notes (2026-10-03):**
  - **Shared decision.** `EncryptionLayerConnection.interceptionHost(sni)` (SNI, else DNS
    name, else address) and `wouldIntercept(host)` (MitM scope and passthrough cache).
    `TlsConnection` now uses both instead of its own copy; `QuicConnection` calls the same.
  - **Holding and blocking** in `QuicConnection` as planned. Datagrams are only held when the
    session runs with MitM and the Block policy, so the Passthrough path is unchanged.
    Blocking marks the row, calls `transportLayer.closeSoft()` (socket released, cache entry
    kept) and answers the held and later datagrams with at most three ICMP errors.
  - **Deviations.** The ICMP error is built byte by byte (`IcmpUnreachableBuilder`) rather
    than with pcap4j's ICMP classes: it quotes a truncated IP packet, which pcap4j's builders
    do not represent. The quoted UDP header is rebuilt from the ports and the datagram (with
    a correct checksum), because the encryption layer receives the UDP payload, not the UDP
    packet; the revision assumed otherwise. `DeviceWriteThread` now also writes raw byte
    arrays, posted with the new `WRITE_ICMP`.
  - Tests: `IcmpUnreachableBuilderTest` (four cases, checked against pcap4j-built datagrams)
    and `QuicBlockPolicyTest` (eleven cases: blocked with ICMP, released socket and cached
    flow; retransmissions without new rows and at most three ICMP errors; a two-datagram
    ClientHello blocked once complete and flushed in order when forwarded; non-h3; `h3-29`;
    out of scope; learned passthrough; MitM off and the Passthrough policy; an unreadable
    ClientHello; ECH with a differing DNS name decided on the SNI). The fixture can add an
    ECH extension. 350 `core:vpn` and 15 `app` tests pass.
  - **Device check scripted.** `nc` does not use a connected UDP socket, so it never sees an
    ICMP error. The `quic` group now sends through `scripts/quic-probe/QuicProbe.java`, which
    the script compiles, pushes and runs with `app_process`, and reports per case what the
    socket saw. With MitM on and `--quic-policy block`: `h3`, `split` and `v2` are refused
    after 52 to 103 ms and their rows are `blocked`; `doq` gets no answer (forwarded) and is
    not blocked. With `--quic-policy passthrough` all four get no answer and nothing is
    blocked. A capture confirms the ICMP error on `tun0` 31 ms after the datagram, and the
    kernel counts it in `InDestUnreachs` without errors. So an ICMP error written to the TUN
    does reach the app's socket.
  - **Real apps under Block** (`apps` group): the Play Store's QUIC to `play-fe.googleapis.com`
    was blocked four times within 1.2 s, and the app fell back to TLS over TCP to the same host
    (three rows, ALPN `h2,http/1.1`). It rejected the forged certificate there, and passthrough
    was learned ten seconds later, as the packet predicted for Cronet-based apps.
  - Regression with the default policy: the full stress suite passes 72 of 72, and the full
    traffic script is clean.
  - V-41 is resolved for users who turn the policy on; Alt-Svc and HTTPS-record stripping stay
    out of scope.
- **Commit:** `feat(vpn): block HTTP/3 over QUIC while MitM is on so clients fall back to TLS`

**Order for the QUIC packets (PKT-26 to PKT-29, PKT-49 to PKT-52):** all done (phases Q0 to
Q2 of `docs/records/quic-mitm.md`). None of the
remaining four changes the database version.

### PKT-53 — Keep forwarding the client's data after the remote host closes its side

- **Priority:** High · **Depends on:** none
- **Resolves:** V-59
- **Approach:**
  - In `TcpConnection.unwrapInboundReadable()`, on end of stream (`:1150-1156`), shut down only
    the input (`socket().shutdownInput()`, ignoring errors), stop reading (`readsStopped`,
    `updateInterest()`), and remember that the remote host closed first. Do not close the
    channel: the write queue (`outQueue`) and later data from the device still go out through
    it. `deliverRemoteClose()` stays as it is: CLOSING, our FIN after everything queued for the
    device.
  - Let `handleAckData()` (`:822-828`) forward data in CLOSING when the remote host closed
    first and the device has not sent its FIN yet. Data after the device's own FIN, and data in
    a CLOSING entered through `closeFully()`, still draw a reset as today. Apply the same
    condition where the reorder buffer (`bufferSegment()`, `deliverBufferedSegments()`) and
    `announceWindowIfOpened()` check for CONNECTED, so that a connection in this state keeps
    proper flow control.
  - When the device's FIN arrives in this state (`handleFinLocked()`, CLOSING branch without
    `deviceFinReceived`), close the channel only once the write queue has drained: set
    `closeWhenDrained` when `outboundBacklog() > 0`, as `closeFully()` does, so that
    `finishCloseIfComplete()` waits for `completeDeferredUpstreamActions()`.
  - If the remote host has really closed its socket, the next write fails with a reset. The
    existing failure path (`wrapOutbound()` / `drainOutQueue()` → `closeHard()`) then resets
    the device, which is the right signal at that point.
  - Count forwarded device data as progress for the CLOSING sweep (`closingSince`), so that a
    long upload after a server half-close is not dropped after two minutes.
  - `TlsConnection.unwrapOutbound()` / `unwrapInbound()`: once the TLS layer has closed itself
    (`connectionScope` cancelled, e.g. after the server's close_notify), a payload handed to it
    is never processed, and the bytes counted by `outboundProcessingDeferred()` are never
    released. That blocks `completeDeferredUpstreamActions()` and with it the deferred close
    above. Release the count when the launched job is cancelled before it ran
    (`invokeOnCompletion`, as `onRemoteClosed()` does). The client's close_notify arriving then
    is dropped by the TLS layer and acknowledged by the transport layer, with no reset.
- **Files:** `connection/transportLayer/TcpConnection.kt`,
  `connection/encryptionLayer/TlsConnection.kt`; `scripts/stress/StressClient.java`,
  `scripts/stress/stress_server.py`.
- **Tests:**
  - New `TcpRemoteHalfCloseTest`, with a real local server socket in the style of
    `TcpUpstreamBackpressureTest`. Server replies, shuts down its output, then reads: data
    the device sends afterwards arrives complete, the device gets no reset, and the close
    completes once both FINs are acknowledged. Server closes its socket completely: the
    device's next data draws a reset. Upstream write queue non-empty at end of stream: the
    queued data still arrives. Device FIN while data is still queued: the channel closes only
    after the queue has drained.
  - `TlsConnection`: a payload handed over after the connection closed itself releases its
    in-process count.
  - Device: add a `halfclose` test to the stress suite (server replies, shuts down its output,
    reads N bytes and reports the count; the test passes when the count is N), on a new
    `stress_server.py` port. With MitM on and in plain mode it passes, and the full suite logs
    no `Got ACK (data, invalid state CLOSING)` for the `tls`/`tlsclose` tests. The number of
    `Resetting unknown TCP packet (FIN)` lines drops accordingly.
- **Implementation notes (2026-10-03):**
  - `TcpConnection`: on end of stream, the receiving side is shut down and reading stops
    (`readsStopped`). The channel stays open. `deliverRemoteClose()` sets the new
    `remoteClosedFirst` unless the connection was HALF_CLOSED, where the device has already
    sent its FIN. The new `acceptsDeviceData()` (CONNECTED, or CLOSING with `remoteClosedFirst`
    and no FIN from the device yet) replaces the CONNECTED checks in `handleAckData()`,
    `bufferSegment()`, `deliverBufferedSegments()` and `announceWindowIfOpened()`. Data in
    CLOSING refreshes `closingSince`. The device's FIN in that state sets `closeWhenDrained`
    when data for the remote host is still queued. `deviceFinReceived` became `@Volatile`,
    because `acceptsDeviceData()` reads it from the threads that announce the window.
  - The channel is now closed by `finishCloseIfComplete()` once both FINs are acknowledged,
    when a write fails, or by the CLOSING sweep, and no longer at the remote host's FIN. A
    connection whose app never closes its side therefore holds its descriptor for up to the
    two-minute closing timeout, as the socket of a real TCP stack stays in CLOSE_WAIT.
  - `TlsConnection`: `unwrapOutbound()` and `unwrapInbound()` go through the new
    `launchCounted()`, which releases the in-process count from `invokeOnCompletion` when the
    cancelled scope never ran the block.
  - Tests: new `TcpRemoteHalfCloseTest` (4 cases) and `TlsProcessingAccountingTest` (2 cases).
    `ConnectionTeardownTest`'s V-21 test now checks that the channel stays open after the
    remote close and is released once the device has closed too. Against the old
    `TcpConnection`, the two main half-close cases fail (the server receives 0 bytes; the
    channel is closed with data queued). 356 `core:vpn` tests pass.
  - Stress suite: new `halfclose` test (in the default set) and `stress_server.py`
    half-close handler on base port + 3, which reports what it received on a second
    connection.
  - Emulator:

    | | Before (`39bd517`) | After |
    |---|---|---|
    | `halfclose` (200,000 bytes, after 0 and 500 ms) | server received 0 bytes, both FAIL | all bytes, hash ok, both PASS |
    | `Got ACK (data, invalid state CLOSING)` in `halfclose,tls,tlsclose` | 35 | 0 |
    | `Resetting unknown TCP packet (FIN)` in the same run | 32 | 0 |

    Full suite with MitM: 74 passed, 0 failed (this time including `udp-burst-500`), no crash.
    Throughput as before (50 MB download 5.8 MB/s, 20 MB upload 4.9 MB/s). Descriptors went
    from 130 before the run to 129 after the UDP idle sweep, with no TCP socket in CLOSE_WAIT.
    Plain mode: `halfclose,tls,tlsclose,tlsparallel` 23/23, no CLOSING resets.
    `emulator-traffic.sh run` is clean.
- **Commit:** `fix(vpn): keep forwarding the client's data after the remote host closes its side`

### PKT-54 — Stop learning passthrough from idle connections

- **Priority:** High · **Depends on:** none
- **Resolves:** V-60
- **Approach:**
  - `TlsConnection`: record when the client-facing handshake completed (the switch to
    CLIENT_ESTABLISHED). `recordPinningSuspect()` (`:1325-1329`) counts a close without
    application data only if it comes within `PINNING_CLOSE_WINDOW_MS` (3 s) of that moment. A
    client that rejects a pin closes right after its handshake (OkHttp's `CertificatePinner`
    runs immediately after the handshake). Connection pools, pre-connects and the losers of a
    TCP/QUIC race sit idle for seconds to minutes before they are closed. Take the clock from
    a parameter that tests can replace.
  - `TlsPassthroughCache`: add `recordDecrypted(initiator, hostname)`, called the first time a
    connection of the pair carries application data from the client (where `outboundAppBytes`
    first becomes non-zero). For such a pair, `CLOSED_WITHOUT_DATA` is ignored from then on and
    its pending suspect count is cleared. A pair that has been decrypted has proven that the app
    accepts the certificate. `CLIENT_HANDSHAKE_ERROR` and `CLIENT_CLOSED_DURING_HANDSHAKE` are
    unaffected: they are direct evidence. Bound the new set like the others (`boundedMap`).
  - Considered and left out: suppressing bursts of closes across many hosts of one app (an app
    being stopped). With the time window, a burst only matters for an app stopped within 3 s of
    opening its connections, and the threshold of two still applies.
  - Not in scope: the case where a real rejection is never learned because the app keeps the
    rejected connection idle (the Play Store under the Block policy, left as is on 2026-10-02).
- **Files:** `connection/encryptionLayer/TlsConnection.kt`, `metadata/TlsPassthroughCache.kt`;
  `scripts/stress/StressClient.java`.
- **Tests:**
  - `TlsPassthroughCacheTest`: `CLOSED_WITHOUT_DATA` for a pair marked decrypted never
    learns; marking clears a pending count; the other reasons still learn at once.
  - `TlsConnection` with an injected clock: a close without data 1 s after the handshake
    counts, one 10 s after does not.
  - Device: add a `tlspinning` stress test that, for one host, completes the handshake and
    closes at once twice, then expects the third connection to show the real issuer
    (passthrough). `emulator-traffic.sh run`: the force-stops in the `apps` group no longer
    produce `learned passthrough ... (CLOSED_WITHOUT_DATA)` for YouTube's hosts, and
    `--quic-policy block` still decrypts YouTube's fallback requests.
- **Implementation notes (2026-10-03):**
  - `TlsConnection` records when the client-facing handshake completed (in `switchState()`).
    `recordPinningSuspect()` ignores a close without data that comes more than
    `pinningCloseWindowMs` after it, by default `TlsConnection.DEFAULT_PINNING_CLOSE_WINDOW_MS`
    (3 s). The first application data of a connection calls the new
    `TlsPassthroughCache.recordDecrypted()`. From then on `recordFailure()` ignores
    `CLOSED_WITHOUT_DATA` for the pair, and pending hits are dropped. The new set is bounded like
    the others.
  - Deviation from the plan: the window is a `ComponentManager` constructor parameter
    (`pinningCloseWindowMs`), not an injected clock. The `TlsConnection` is created deep inside
    the pipeline, so a test cannot reach it to replace a clock. With the parameter, a test
    shrinks the window and waits past it. The test fixture stubs the parameter, because its
    relaxed mock would otherwise return 0 and nothing would ever be counted.
  - Addition to the plan: the forced-fallback exception. Measured on the emulator, the Play
    Store under the Block policy opens its TLS fallback and closes it unused about 10.8 s after
    the handshake. The old rule learned that after two such closes; the window alone would have
    stopped it, leaving the app with neither HTTP/3 nor TLS for the session. So
    `QuicConnection.block()` now records the pair through the new
    `TlsPassthroughCache.recordQuicBlocked()`, under the same hostname the TLS path uses
    (`interceptionHost()`). For such a pair, a close without data counts whatever its delay.
    YouTube under Block is unaffected: its fallback carries data and is recorded as decrypted.
  - Burst suppression stays out, as planned.
  - Tests: `TlsPassthroughCacheTest` +6 (decrypted pairs, dropped hits, rejections still
    learned, per-pair, bounds, blocked QUIC pairs). `TlsPassthroughLearningTest` +3: late
    closes are not counted; idle closes after a decrypted connection are not counted; late
    closes on a forced fallback are. `QuicBlockPolicyTest` checks that a block is recorded and a
    forwarded flow is not. 365 `core:vpn` and 15 `app` tests pass.
  - Stress suite: new `tlspinning` test (in the default set). Two handshakes on
    `www.example.net`, each closed after 5 s idle: the third connection must still be
    intercepted. Two handshakes on `www.example.org`, closed at once: the third must be passed
    through. Without MitM both pass with a note.
  - Emulator:

    | | Before (PKT-53 build) | After |
    |---|---|---|
    | `tlspinning-idle-closes-keep-mitm` | FAIL (`www.example.net` learned) | PASS |
    | `tlspinning-quick-closes-learn-passthrough` | PASS | PASS |
    | `apps` group, Passthrough policy: YouTube hosts learned at force-stop | 4 (audit run) | 0 |
    | `apps` group, Block policy: YouTube hosts learned / requests decrypted | 1 / 16 (audit run) | 0 / 17 and 0 / 19 |

    `tls,tlsbulk,tlsclose,tlsparallel,tlspinning`: 28/28, and the only host learned is
    `www.example.org`. In one Block run the Play Store opened two fallback connections, which
    under PKT-54 alone were not learned (that is why the exception exists). In the run after the
    exception it opened only one, which is one hit below the threshold of two, so `play-fe` was
    not learned in that run either. Whether a single rejected forced fallback should be enough
    is open; the threshold is unchanged.
- **Commit:** `fix(vpn): stop learning passthrough from idle connections that the app closes`

### PKT-55 — Report the VPN network as unmetered

- **Priority:** Medium · **Depends on:** none
- **Resolves:** V-66
- **Approach:**
  - In `HeimdallVpnService.establishInterface()` (`HeimdallVpnService.kt:407-411`), call
    `builder.setMetered(false)` on API 29+. Android then treats the VPN as metered exactly when
    an underlying network is metered. Below API 29, VPNs did not mark themselves metered, so
    nothing is needed there.
  - Leave `setUnderlyingNetworks()` alone (null means "the default network", which is what
    Heimdall's protected sockets use), and record that choice in a comment.
  - Done early on purpose, although it is small: it changes what apps send while Heimdall
    records them, so measurements after it are closer to what the apps do without Heimdall.
- **Files:** `app/src/main/java/de/tomcory/heimdall/service/HeimdallVpnService.kt`,
  `scripts/emulator-traffic.sh`.
- **Tests:** device. `dumpsys connectivity` shows `NOT_METERED` in the VPN network's
  capabilities while the emulator is on Wi-Fi. Add that check to the "Checks" block of the
  `emulator-traffic.sh` report.
- **Implementation notes (2026-10-03):**
  - `HeimdallVpnService.establishInterface()` calls `builder.setMetered(false)` on API 29+,
    with a comment that the underlying networks are left unset on purpose.
  - `emulator-traffic.sh report` reads the VPN network's capabilities from `dumpsys
    connectivity`, takes the underlying transport from the VPN's own transport list (e.g.
    `WIFI|VPN`), and compares `NOT_METERED` on both. The emulator also has a validated cellular
    network, so "the first validated non-VPN network" is not the VPN's underlying network.
  - No unit test: the change is one builder call that only Android can evaluate.
  - Emulator: with the PKT-54 build the report printed `VPN network unmetered: no (expected
    yes, as its underlying network: Transports: WIFI)`. With this build it prints `yes (expected
    yes ...)`. `emulator-traffic.sh run` is clean, and `run-stress.sh download,upload,udp,tls`
    passes 48/48.
- **Commit:** `fix(vpn): report the VPN network as unmetered when its underlying network is`

### PKT-56 — Learn passthrough when the upstream TLS handshake fails, and record why a connection was not decrypted

- **Priority:** Medium · **Depends on:** none; before PKT-57, which relies on it
- **Resolves:** V-62 (and the logging item under "Still open from earlier work")
- **Approach:**
  - Add `PassthroughReason.UPSTREAM_HANDSHAKE_FAILED`, learned at once like the other direct
    reasons. Record it when the server-facing handshake fails with an `SSLException`: in
    `handleUnwrap()` for inbound data (`TlsConnection.kt:963`), in `handleWrap()` for outbound,
    and in `runDelegatedTasks()` for the server-facing engine, each only in state
    SERVER_HANDSHAKE. A connect failure or a reset from the server is not an `SSLException`
    and is not learned: those are not a matter of trust. With
    `trustAllUpstreamCertificates` on, verification never fails, and only protocol failures
    are learned.
  - The failing connection itself is still reset. Its ClientHello has been used up on the
    upstream handshake, so it cannot be passed through. The app's retry is passed through, and
    the app then applies its own trust decision. Replaying the stored ClientHello
    (`originalClientHello`) on a new upstream socket would save the retry, but it means
    replacing the transport's channel mid-connection, so it is left out.
  - Make `TlsPassthroughCache` store the reason a pair was learned instead of `true`, and add
    a nullable `passthroughReason` column to `Connection`. Fill it for a connection passed
    through because of the cache (the learned reason), because it is outside the MitM scope
    (`OUT_OF_SCOPE`), or because its own upstream handshake failed (`UPSTREAM_HANDSHAKE_FAILED`,
    on the failing connection). That makes "not decrypted, and why" visible in the database
    for every case, including V-60's and PKT-57's. Write it through `DatabaseConnector` like
    `markConnectionBlocked()`. Bump `HeimdallDatabase` to version 9 (destructive, as for every
    schema change so far).
  - Gate the full-record hex dump after an `SSLException` (`TlsConnection.kt:972`) behind the
    `log` flag. For an upstream failure it is the server's certificate chain.
- **Files:** `connection/encryptionLayer/TlsConnection.kt`, `metadata/TlsPassthroughCache.kt`,
  `connection/encryptionLayer/EncryptionLayerConnection.kt` (where the scope decision is made),
  `components/DatabaseConnector.kt`, `components/RoomDatabaseConnector.kt`;
  `core/database/.../entity/Connection.kt`, `dao/ConnectionDao.kt`, `HeimdallDatabase.kt`; the
  database screen's connection details; `scripts/emulator-traffic.sh` (report column);
  `scripts/stress/StressClient.java`.
- **Tests:**
  - `TlsPassthroughCacheTest`: the new reason learns at once, and `get` returns the stored
    reason.
  - A TLS integration test with a local upstream server whose certificate the upstream engine
    rejects: the client is reset, the pair is learned, and the next connection is passed
    through with `passthroughReason = UPSTREAM_HANDSHAKE_FAILED`.
  - Device: add a `tlsupstream` stress test (trust-all client) against `expired.badssl.com`,
    `self-signed.badssl.com` and `untrusted-root.badssl.com`. The first connection to each is
    reset, and the second succeeds and shows the real issuer. The test depends on badssl.com
    being up, so on a network error it reports SKIP, not FAIL. `emulator-traffic.sh` shows the
    reasons in its TLS table.
- **Implementation notes (2026-10-03):**
  - `TlsConnection.upstreamHandshakeFailed()` learns `UPSTREAM_HANDSHAKE_FAILED` and marks the
    failing connection, once per connection. It is called from `handleWrap()` (outbound),
    `handleUnwrap()` (inbound) and `runDelegatedTasks()` (server-facing engine), each only in
    SERVER_HANDSHAKE. A delegated task's exception counts only if it or one of its causes is an
    `SSLException` or a `GeneralSecurityException`. On the emulator the badssl failures
    surfaced in `handleUnwrap()`. The record hex dump after an `SSLException` is now behind
    `log`.
  - `TlsPassthroughCache` stores the reason for each pair. The new `getReason()` returns it,
    and `get()` stays a Boolean on top of it, so callers are unchanged. `put()` (only used by
    tests) takes an optional reason. A later failure does not replace the stored reason.
  - `EncryptionLayerConnection.interceptionSkipReason()` returns `OUT_OF_SCOPE`, the learned
    reason's name, or null. `wouldIntercept()` is now defined through it, so the QUIC block rule
    still follows the same decision. `TlsConnection` records the reason through the new
    `persistPassthroughReason()` when it decides not to intercept a connection while MitM is on.
    With MitM off nothing is recorded.
  - Database: `Connection.passthroughReason` (nullable `String`, so that PKT-57 can add
    `ALPN_UNSUPPORTED` without another type change), `ConnectionDao.updatePassthroughReason()`,
    `DatabaseConnector.updateConnectionPassthroughReason()` (waits for the row like the other
    updates), version 9. `CLAUDE.md` updated. The database screen shows "Not decrypted: …" with a
    readable label. `emulator-traffic.sh` has a `passthrough` column in its TLS table.
  - Tests: `TlsPassthroughCacheTest` +3. `TlsPassthroughLearningTest` +2: an upstream failure
    (the fixture's new `trustAllUpstream = false` makes Heimdall reject the test server) resets
    the client, learns the pair, marks the row, and the retry is passed through with the real
    certificate and the same reason; an intercepted connection records no reason. Plus an
    `OUT_OF_SCOPE` assertion on the scope test. 370 `core:vpn` and 15 `app` tests pass.
  - Stress suite: new `tlsupstream` test (in the default set) and a SKIP outcome, which the
    summary counts separately. Fixed `tlspinning` on the way: its idle case's third connection
    closed straight after the handshake, which counted as one quick close, so a second run in
    the same VPN session learned the host. It now stays open as long as the first two. Its
    no-MitM note now also names the other cause, a host learned earlier in the session.
  - Emulator:

    | `tlsupstream` | Before (PKT-55 build) | After |
    |---|---|---|
    | `expired.badssl.com` | reset, reset: FAIL | reset, then real issuer (COMODO): PASS |
    | `self-signed.badssl.com` | reset, reset: FAIL | reset, then real issuer: PASS |
    | `untrusted-root.badssl.com` | reset, reset: FAIL | reset, then real issuer (BadSSL Untrusted Root): PASS |

    Without the VPN all three pass (trust-all client). Full suite, run one test at a time:
    21/21 tests, 79 checks, no failure. `emulator-traffic.sh run` is clean, and its TLS table
    shows `CLIENT_CLOSED_DURING_HANDSHAKE` for the `tls` group's later `www.wikipedia.org`
    connections and `-` for intercepted ones.
  - Environment, not this packet: the first stress run after installing this build failed DNS
    for about 80 s, with `NetworkMonitor` reporting a data stall before the VPN was even
    started; the rerun was clean. A full-suite run later stalled for 30 minutes while the Mac's
    load average was around 25, and `adb` calls hung; run test by test once the host recovered,
    the suite passed. Also seen once, about two minutes before the VPN was started:
    `Scudo OOM: The process has exhausted 256M for size class 1104` in the freshly installed
    Heimdall process. The VPN was not running, so it is not `core:vpn`. The scan Heimdall runs
    after a package install is the likely source; not investigated.
- **Commit:** `feat(vpn): pass through hosts whose upstream TLS handshake fails, and record why a connection was not decrypted`

### PKT-57 — Negotiate ALPN as HTTP/1.1 explicitly, and pass through clients that do not offer it

- **Priority:** Medium · **Depends on:** PKT-56
- **Resolves:** V-61 (the HTTP/1.1 part; decrypting HTTP/2 is left for a design document of
  its own)
- **Approach:**
  - At the ClientHello (`TlsConnection.handleOutboundRecord()`, where `doMitm` is decided,
    `:273-294`): if the client offers ALPN and `http/1.1` is not among its protocols, do not
    intercept the connection. Record `passthroughReason = ALPN_UNSUPPORTED` (PKT-56's column).
    This lets gRPC (`h2` only) and non-HTTP protocols that use ALPN through instead of breaking
    them. It is decided per connection, so nothing is cached.
  - Otherwise, on API 29+ (`SSLParameters.setApplicationProtocols`): offer the server exactly
    `http/1.1` when the client offered ALPN, and nothing when it did not (as today). On the
    client-facing engine, offer `http/1.1` exactly when the server selected it, so that the
    client sees the same answer the server gave. Set the protocols in
    `CertificateSniffingMitmManager` / `SSLEngineSource` from parameters, not in `TlsConnection`
    directly.
  - A server that only speaks HTTP/2 rejects the `http/1.1` offer with
    `no_application_protocol`. That is an upstream handshake failure, so PKT-56 learns the
    host and the app's retry is passed through, where today the server is spoken to in
    HTTP/1.1 without ALPN.
  - Below API 29 the engines get no ALPN, as today. The passthrough rule above works on every
    API level, because it only reads the ClientHello.
  - HTTP/2 decryption (letting `h2` through and recording it) needs an HTTP/2 frame and HPACK
    parser in place of `RawConnection`. That is a project of its own and belongs in a separate
    design document, like `docs/records/quic-mitm.md` for QUIC.
- **Files:** `connection/encryptionLayer/TlsConnection.kt`, `mitm/SSLEngineSource.kt`,
  `mitm/CertificateSniffingMitmManager.kt`; `scripts/stress/StressClient.java`.
- **Tests:**
  - Unit: the ALPN decision for no ALPN, `h2,http/1.1`, `h2` only, and `http/1.1` only.
  - Device: let the stress client's TLS test offer ALPN (by reflection, as `--release 8`
    lacks the API). Through MitM, `h2,http/1.1` negotiates `http/1.1` with issuer Heimdall,
    and `h2` alone negotiates `h2` with the real issuer and `ALPN_UNSUPPORTED` in the database.
    `tls` and `tlsparallel` still pass.
- **Implementation notes (2026-10-03):**
  - New `mitm/Alpn`: `offer()`, `selected()` and `interceptable()`. It looks the API up by
    reflection (`SSLParameters.setApplicationProtocols`, `SSLEngine.getApplicationProtocol`)
    instead of checking `Build.VERSION.SDK_INT >= 29`. The same check then holds on a device
    and in JVM unit tests, where the SDK level reads 0, and lint sees no API-29 call. Below
    API 29, `supported` is false and engines negotiate no ALPN, as before. `offer()` changes
    only the protocols and keeps the engine's other parameters, because `newSSLEngine()` has
    already replaced them for hostname verification.
  - `CertificateSniffingMitmManager.createServerSSLEngine()` and `createClientSSLEngineFor()`
    take the protocols as a parameter (default none). `TlsConnection` keeps the client's offer
    from the ClientHello. It offers the server `http/1.1` if the client offered ALPN at all, and
    offers the client `http/1.1` exactly when the server selected it.
  - At the ClientHello, after the scope check, a client whose ALPN offer lacks `http/1.1` is
    passed through with `passthroughReason = ALPN_UNSUPPORTED` (`TlsConnection.ALPN_UNSUPPORTED`).
    Nothing is learned. The database screen has a label for it.
  - Tests: new `AlpnTest` (5). `TlsPassthroughLearningTest` +4, with `FakeTlsServer` and
    `FakeClientTlsDriver` now able to speak ALPN. The cases: `h2,http/1.1` is intercepted with
    `http/1.1` on both sides; `h2` only is passed through, gets `h2` from the real server and
    records the reason; no ALPN is intercepted without ALPN; a server that only speaks `h2`
    rejects Heimdall's offer, PKT-56 learns it, and the retry gets `h2`. The mocks in
    `TlsRecordHandlingTest` were updated to the new signatures. 379 `core:vpn` and 15 `app`
    tests pass. Lint reports nothing in the changed files.
  - Stress suite: new `tlsalpn` test (in the default set) against `www.cloudflare.com`. The
    first version closed its intercepted connections without data, so the third connection
    met PKT-54's pinning detection and was passed through. Every connection that could be
    intercepted now sends a `HEAD` request.
  - Emulator:

    | `tlsalpn` | Without VPN | Before (PKT-56 build) | After |
    |---|---|---|---|
    | no ALPN | real issuer, none | Heimdall, none | Heimdall, none |
    | `h2,http/1.1` | real issuer, `h2` | Heimdall, none: FAIL | Heimdall, `http/1.1` |
    | `h2` only | real issuer, `h2` | Heimdall, none: FAIL | real issuer, `h2` |

    Two runs in one VPN session gave the same result, and nothing was learned. Full suite, run
    one test at a time: 22/22 tests, 82 checks, no failure. `emulator-traffic.sh run` is
    clean, and the `tls` group's canned `sni-differs` ClientHello (ALPN `h2` only) now shows
    `ALPN_UNSUPPORTED`. With `--quic-policy block`, YouTube's TLS fallback negotiates
    `http/1.1`: 22 requests decrypted, no upstream handshake failure, no crash.
- **Commit:** `feat(vpn): negotiate HTTP/1.1 via ALPN through the MitM and pass through clients that do not offer it`

### PKT-58 — Fill the DNS cache when the resolver uses TCP or DNS over TLS

- **Priority:** Medium · **Depends on:** none
- **Resolves:** V-63, and V-68 (found while implementing it)
- **Approach:**
  - Move the code that fills `DnsCache` from a DNS answer out of `DnsConnection` into a shared
    function, used by `DnsConnection` (UDP) and a new `DnsStreamConnection` for DNS over a
    stream. The stream form frames each message with a two-byte length (RFC 1035 section 4.2.2), and a
    message may be split across segments or several may share one. `DnsStreamConnection`
    reassembles inbound messages, fills the cache from each, and passes all bytes on unchanged
    in both directions. A message that does not parse is passed on and ignored.
  - In `AppLayerConnection.getInstance()` (`:42-43`), use `DnsStreamConnection` for TCP to
    port 53 and for a decrypted TLS connection to port 853. Today TCP/53 goes to
    `DnsConnection`, which parses the length prefix as part of the message. That is the same
    defect on a path that is rarely taken: the resolver uses TCP when a UDP answer was
    truncated.
  - In Private DNS "automatic" (opportunistic) mode, answer a TCP SYN to the VPN's DNS server
    on port 853 with a reset (at the place of the commented-out DoT code in
    `TransportLayerConnection.getInstance()`, `:441-445`). The resolver then marks DNS over TLS
    as unavailable on the VPN network and uses plain DNS, which Heimdall sees in both modes.
    `HeimdallVpnService` determines the mode before establishing the interface, from the
    default network's `LinkProperties`: `isPrivateDnsActive` with no
    `privateDnsServerName` means opportunistic. It passes a flag to `ComponentManager`. Do not
    do this in strict mode (a named Private DNS server): DNS would then fail entirely. In
    strict mode the gap stays, and the setting description should say so.
  - In `HttpConnection.persistMessage()`, when the transport layer has no hostname, use the
    request's `Host` header (port stripped) for the request's `remoteHost`, and fill the
    transport layer's hostname from it the way `refineRemoteHost()` does for a missing name
    (never replacing one that is known).
- **Files:** `connection/appLayer/DnsConnection.kt`, new
  `connection/appLayer/DnsStreamConnection.kt`, `connection/appLayer/AppLayerConnection.kt`,
  `connection/appLayer/HttpConnection.kt`,
  `connection/transportLayer/TransportLayerConnection.kt`, `components/ComponentManager.kt`;
  `app/.../service/HeimdallVpnService.kt`; `scripts/emulator-traffic.sh`.
- **Tests:**
  - `DnsStreamConnectionTest`: length prefix split across segments, two messages in one
    segment, a malformed message passed through, and the cache filled from A and AAAA answers.
  - Opportunistic-mode refusal: a SYN to the DNS address on 853 gets a reset when the flag is
    set and is connected when it is not.
  - `HttpConnection`: a request without a transport hostname is recorded with the `Host`
    header's name.
  - Device: in the `dns` group, add a DNS query over TCP (with a length prefix, through `nc`),
    and its answer's name appears on a later connection. After a few VPN restarts with the
    default Private DNS setting, `Creating TCP Connection to ...:443 (null)` no longer appears
    for hosts resolved through the system resolver. `dumpsys connectivity` shows Private DNS
    not validated on the VPN network.
- **Implementation notes (2026-10-03):**
  - `DnsConnection.cacheAnswers()` holds the code that fills the cache from a response (A and
    AAAA), shared by `DnsConnection` (UDP) and the new `DnsStreamConnection`. A message that
    cannot be read now returns false instead of throwing. `DnsConnection` passes queries on
    without parsing them; it used to parse them and throw on anything that was not DNS.
    `DnsStreamConnection` passes every byte on at once and reassembles responses on the side,
    with at most one message (65,537 bytes) pending. A zero length marks the stream as not
    framed DNS, and it is not read any further.
  - `AppLayerConnection` decides by transport and port: UDP or TCP to port 53 over the plaintext
    layer, and port 853 over a TLS connection that is decrypted (`doMitm`), are DNS. UDP gets
    `DnsConnection`, a stream `DnsStreamConnection`. A passed-through DoT connection hands over
    ciphertext and gets `RawConnection`. The packet variant still also takes a pcap4j
    `DnsPacket` over UDP for DNS, as before (pcap4j only produces one for UDP port 53, and
    `DnsResolutionTest` relies on it).
  - Refusal: new `ComponentManager.refuseDnsOverTlsTo`. `TransportLayerConnection.getInstance()`
    answers a SYN to that address on port 853 with the new `TcpConnection.buildSynRefusal()`
    (RST-ACK acknowledging the SYN; the stray-reset builder does not set ACK, and a device in
    SYN-SENT ignores a reset without it). The commented-out DoT code there is gone.
  - Deviation from the plan, in how the mode is detected: the packet said to read
    `isPrivateDnsActive` with no `privateDnsServerName` on the default network. Private DNS is
    validated per network, against that network's own DNS servers. The Wi-Fi network's state
    therefore says nothing about the VPN network, which uses 1.1.1.1, and on the emulator Wi-Fi
    showed no Private DNS while the VPN network had DoT validated. `HeimdallVpnService` now only
    asks whether strict mode is on (`privateDnsServerName` set on the default network, API 28+),
    before establishing the interface, and refuses DoT to the VPN's DNS server otherwise. With
    Private DNS off, the resolver never connects to port 853, so the refusal changes nothing.
  - Not done: the note about strict mode in the DNS setting's description. `StringPreference`
    has no description, only the dialog title, and changing the shared settings component for
    one note is outside this packet. Strict mode stays a gap; this section and V-63 record it.
  - `HttpConnection`: when the connection has no hostname, the request's `Host` header (port
    removed; ignored if it is an IP address) names it through the new
    `TransportLayerConnection.fillMissingRemoteHost()`, which never replaces a known name.
  - V-68, found while verifying this packet and fixed in it: `EncryptionLayerConnection` no
    longer runs TLS or QUIC detection for port 53, and runs TLS detection only for TCP flows and
    QUIC detection only for UDP flows.
  - Tests: new `DnsStreamConnectionTest` (7), `AppLayerSelectionTest` (5),
    `DnsOverTlsRefusalTest` (3). `HttpParsingTest` +3 (Host header). `ProtocolDetectionTest` +2:
    a DNS query whose ID begins with `0x16` passes `detectTls()` and still gets the plaintext
    layer, and TLS bytes over UDP are not TLS. 399 `core:vpn` and 15 `app` tests pass.
  - `emulator-traffic.sh`: the `dns` group also sends an A query for `neverssl.com` over TCP,
    then connects to the answered address with non-HTTP bytes, so that only the TCP answer can
    name it. The report checks that name and shows whether Private DNS is in use on the VPN
    network.
  - Emulator:

    | | Before (PKT-57 build) | After |
    |---|---|---|
    | Connection to the DNS-over-TCP answer's address | no name | `neverssl.com` |
    | Private DNS on the VPN network | `ValidatedPrivateDnsAddresses: [1.1.1.1]` | not in use |
    | Port-443 connections without a name, `tls` test in three fresh VPN sessions | 127/127 in the audit's DoT session | 0/25, 0/20, 0/20 |

    The service logs `Private DNS strict mode: false; refusing DNS over TLS to: 1.1.1.1`, and the
    resolver's attempt at VPN start is refused once. Full suite, run one test at a time, after
    the V-68 fix: 22/22 tests, 82 checks, no DNS query handed to TLS in any of the run's logs.
    The run before that fix had one failure, the V-68 case above. `emulator-traffic.sh run` is
    clean.
- **Commit:** `fix(vpn): fill the DNS cache from DNS over TCP and keep opportunistic DNS over TLS off the VPN`

### PKT-59 — Store HTTP bodies as bytes, with a configurable limit

- **Priority:** Medium · **Depends on:** none; before PKT-60
- **Resolves:** V-64
- **Approach:**
  - Change `Request.content` and `Response.content` from `String` to a `ByteArray` (BLOB),
    together with `contentLength` (the real body length) and a new `contentTruncated` flag.
    Headers stay text. Bump `HeimdallDatabase` to the next version (destructive).
  - In `HttpConnection`, keep message bodies as bytes from the reassembly buffer to the
    database. Only the header block is decoded, as ASCII/UTF-8, and the chunked path removes
    its framing on bytes (`dechunkHttpMessage`, `combineChunks`).
  - Replace the fixed 1 MB `maximumMessageSize` (`HttpConnection.kt:84`) with a preference
    (proto field 51, "Largest HTTP body to keep", default 256 KB, at most 1 MB). Of a larger
    body, store the first limit bytes and set `contentTruncated` instead of storing a
    placeholder. The upper bound is not arbitrary: Android's `CursorWindow` holds at most 2 MB
    per row, so a larger row cannot even be read back. Today's 1 MB binary bodies stored as
    2 MB of text already come close.
  - Readers: `CsvExport` writes a body as text when its `Content-Type` is textual (`text/*`,
    JSON, XML, form data, JavaScript) and as Base64 otherwise, with a column that says which.
    Any UI that shows a body does the same, with a hex preview for binary bodies.
  - Optional, as a separate commit within the packet: store `gzip`/`deflate`-encoded bodies
    decompressed (`java.util.zip`; the JDK has no Brotli), with a flag, within the same limit.
- **Files:** `connection/appLayer/HttpConnection.kt`, `connection/appLayer/ChunkedBodyTracker.kt`
  (if it touches the body bytes), `components/DatabaseConnector.kt`,
  `components/RoomDatabaseConnector.kt`; `core/database/.../entity/Request.kt`,
  `entity/Response.kt`, `HeimdallDatabase.kt`; `core/export/.../csv/CsvExport.kt`;
  `core/datastore-proto/.../preferences.proto`, `core/datastore` (initial value, serializer,
  data source); the traffic scanner preferences screen; `scripts/emulator-traffic.sh` (report
  queries).
- **Tests:**
  - `HttpConnection`: a binary body (all 256 byte values) is stored byte-identical, with
    `Content-Length`, chunked, and close-delimited framing. A body above the limit is stored
    truncated to the limit, with its real length and the flag set.
  - `CsvExport`: text versus Base64.
  - Device: after `run-stress.sh download`, the stored body of `/bytes?n=1000000` has the
    hash the server reports (or is truncated to the limit, with the right length). After the
    full suite, the database is a fraction of the 439 MB measured in V-64. Record the number
    in the notes.
- **Implementation notes (2026-10-03):**
  - Database: `Request.content` and `Response.content` are `ByteArray` (BLOB), with a new
    `contentTruncated` flag; `RequestWithConnectionIsTracker` follows. Version 10 (destructive).
    `CLAUDE.md` updated.
  - `HttpConnection` keeps each direction's current body in a `BoundedBody`: the first
    `maximumBodySize` bytes plus the real length. That replaces the chunk cache, the
    `tooLarge` path and the `<too large: N bytes>` placeholder. Memory per direction is now
    bounded by the limit for every framing. Only the header block is decoded as text.
    `persistMessage()` takes the header block and the body separately; `parseBody()`,
    `dechunkHttpMessage()` and `combineChunks()` are gone.
  - `ChunkedBodyTracker.feed()` takes an optional sink that receives the chunk data as it is
    read, so a chunked body is decoded in the same pass that finds its end.
  - Truncation: a body over the limit keeps its first limit bytes, with `contentLength` set to
    the real length and `contentTruncated` set. A response delimited by connection close keeps
    what arrived with its headers and is always marked truncated, because its end is never
    seen. That is PKT-33's behaviour (parsing stops after such a response), unchanged here;
    keeping more would need the app layer to learn about the connection's close.
  - Limit: proto field 51 `mitm_http_body_limit_kb`, a "Largest HTTP body to keep (KB)" setting
    (1 to 1024), `HttpBodyLimitResolver` in the service and `ComponentManager.maxHttpBodySize`.
    Installs from before this field read 0, so 0 means the default (256 KB) rather than "keep
    nothing". The resolver caps the limit at 1 MB (`HttpConnection.MAX_BODY_SIZE_LIMIT`).
  - `CsvExport`: textual bodies (`text/*`, JSON, XML, JavaScript, form data, `+json`, `+xml`)
    are written as text in their declared charset, everything else as Base64 (own encoder:
    `java.util.Base64` needs API 26), with `contentEncoding` and `contentTruncated` columns.
    Fixed on the way: the header row listed a `reqResId` column that the rows did not have, so
    every column after it was shifted. Fields were never escaped, although `csvEscape()`
    existed; they are now, and it also quotes line breaks (the stored headers are multi-line).
    No UI shows bodies, so there was nothing else to change.
  - Not done: the optional storing of gzip/deflate bodies decompressed.
  - `emulator-traffic.sh report` summarises the stored bodies (rows, kept bytes, real bytes,
    truncated).
  - Tests: `HttpParsingTest` updated for bytes, with the old placeholder tests rewritten for
    truncation, plus 5 new ones: a binary body with all 256 byte values, unsplit and split;
    chunked with CRLF bytes in the data; close-delimited; and a limit from the preference.
    New `CsvExportTest` (7, with JUnit added to `core:export`) and `HttpBodyLimitResolverTest`
    (3). 404 `core:vpn`, 7 `core:export` and 18 `app` tests pass. Lint reports nothing in the
    changed files.
  - Emulator, `run-stress.sh download` (the server sends each body's SHA-256): every body with
    `Content-Length` or chunked encoding up to the limit is stored with the server's hash. The
    5 MB and 50 MB bodies are stored as their first 262,144 bytes, with the real length and the
    flag. Full suite, run one test at a time: 21 of 22 tests passed. The exception was
    `tlsparallel`, with 3 of 72 requests to `stackoverflow.com` timing out. In reruns it passed
    2 of 3 times, and it also failed without the VPN (`heise.de` reset, `amazon.com` aborting
    39 of 72): the public sites throttle the test. `emulator-traffic.sh run` is clean.
  - Size: after the download test, the full suite and the traffic script, the database is
    75 MB. Bodies in it: 68 MB kept of 367 MB received, in 5,290 rows, 135 of them truncated.
    The old encoding would have stored roughly 38 MB (all text) to 76 MB (all binary, at about
    twice the size) for the same rows. Bodies over 1 MB were a placeholder then, and each now
    keeps 256 KB, which offsets the end of the doubling. So the gain is correctness (bodies are
    stored exactly) and bounded rows, not a smaller database for this workload. The 439 MB in
    V-64 came from a longer workload and is not directly comparable. A lower default limit
    would shrink the database further.
  - Observed on the first start after installing this build: the stress script's first two
    connections timed out. `tun0` was up about 20 s before the traffic threads started, so
    nothing read the tunnel in between. The likely cause is the first database access after
    the schema change, which runs Room's destructive migration before the session row can be
    written. It only affects the first start after a schema change; the next run was clean. It
    may also explain the DNS failures seen right after installing PKT-56, which were put down
    to the network at the time.
- **Commit:** `fix(vpn): store HTTP bodies as bytes with a configurable size limit`

### PKT-60 — Do not discard responses whose request row is late

- **Priority:** Medium · **Depends on:** PKT-59 (measure again after it)
- **Resolves:** V-65
- **Approach:**
  - First repeat the plain-mode full stress run after PKT-59, and record whether any
    `No matching request ID became available in time` remain. V-64's oversized rows are the
    likely cause of the write backlog.
  - Either way, remove the 30 s correlation timeout as a reason to drop data
    (`REQUEST_CORRELATION_TIMEOUT_MS`, `HttpConnection.kt:639`, `:447-454`). The request's
    deferred ID always completes: `persistMessage()` completes it on success and completes it
    exceptionally on failure. So the response coroutine can wait for it without a short
    timeout. Keep a long safety bound (10 minutes) that only logs an error. A response whose
    request failed to persist is still dropped, with an error log, as today.
  - Run the HTTP persistence of one connection on a single sequential writer (a channel
    consumed by one coroutine per connection, or a `limitedParallelism(1)` view of
    `Dispatchers.IO`) instead of one unbounded coroutine per message. Writes then happen in
    wire order, the queue's length is visible, and a burst cannot start thousands of
    concurrent inserts.
- **Files:** `connection/appLayer/HttpConnection.kt`.
- **Tests:**
  - `HttpConnection` with a database connector whose request insert takes longer than 30 s
    (virtual time): the response is persisted, linked to its request.
  - With a failing request insert: the response is dropped with an error log, and nothing
    hangs.
  - Device: the plain-mode full stress run logs no discarded responses, and the number of
    responses equals the number of requests that got one. Count both in the database.
- **Implementation notes (2026-10-04):**
  - Measured first, as planned. The plain-mode full suite on the PKT-59 build, run one test at a
    time, passed 22/22 and discarded no response (V-65 counted 143). PKT-59's bounded rows
    removed the write backlog that caused them. In that database, 4,838 of 4,906 requests have a
    response. All 68 without one are requests that never got a complete response: 60
    client-aborted downloads (`clientabort`, two runs), 2 `/rst` (server reset mid-body), 2
    `/hang` and the 4 public-site requests that `tlsparallel` saw time out or reset.
  - `HttpConnection` queues each database write behind the connection's earlier ones
    (`queueWrite()`): a fair `Mutex`, so writes run one at a time in the order the messages were
    seen. Each coroutine is started `UNDISPATCHED`, so it joins the mutex's queue on the thread
    that saw the message. `queuedWrites` counts the backlog, and the log says when a connection
    reaches 200.
  - Deviation from the plan, in how writes are serialised: the packet offered a
    `limitedParallelism(1)` view of `Dispatchers.IO`. That does not serialise suspending work:
    a write that suspends inside Room lets the next one start, and the new ordering test caught
    exactly that (`/1`, the slow write, finished last). A channel with one consumer per
    connection would work, but it would leave one coroutine parked for every HTTP connection
    ever seen, since the app layer never learns that its connection closed. A mutex leaves
    nothing behind.
  - Deviation, in where the safety bound sits: with writes serialised, a response's write only
    starts after its request's write has finished, so its wait for the ID is always already
    complete. The 30 s timeout on that wait is gone, and the response simply awaits the ID. A
    failed request write still drops its response, with an error log. The 10-minute bound
    applies to each write instead: a write that never returns would otherwise hold up every
    later message of the connection. One that is given up is logged, and its request ID is
    failed with it.
  - Also fixed: request and response timestamps are now taken when the message is seen, not
    when its row is written, which can be later with a queue. The response write is wrapped in
    a `try` like the request write; an exception escaping it would have crashed the app.
  - Tests: new `HttpPersistenceTest` (5, on virtual time): a request row that takes 45 s is
    still followed by its response; a failed request write drops the response without hanging;
    a write that never returns is given up after 10 minutes, and the connection's later
    messages are still written; writes run one at a time in wire order; pipelined responses are
    paired correctly while writes are queued. 409 `core:vpn` and 18 `app` tests pass.
  - Emulator, new build: the plain-mode full suite, run one test at a time, passed 22/22, with
    no discarded response and no backlog warning. Again, every request without a response is
    one of the cases above. In MitM mode, `keepalive,parallel,churn,tls,tlsbulk` passed 29/29.
- **Commit:** `fix(vpn): keep HTTP responses whose request is still being persisted`

### PKT-61 — Set UDP flows up off the packet thread

- **Priority:** Medium · **Depends on:** none (follows PKT-41's pattern)
- **Resolves:** V-67
- **Approach:**
  - Measure first, as for PKT-41. Time `UdpConnection`'s constructor (app lookup, protect,
    connect) on the emulator during an app start and during the `udp` and `dns` tests. Record
    the distribution in the notes, so that the change can be judged against it.
  - Then move the blocking part into a `setUp()` run on the same `setupScope` as
    `TcpConnection` (`Dispatchers.IO.limitedParallelism(8)`). Until it finishes, the
    connection is CONNECTING and keeps the datagrams that arrive in a small queue (bounded,
    e.g. 32 datagrams or 64 KB; the oldest are dropped beyond that, as UDP allows). It
    forwards them in order once the channel is connected and registered. Take the database row
    the same way as TCP (PKT-41's asynchronous insert). Registration uses the selector monitor
    barrier as TCP does.
  - DNS flows (port 53) skip the app lookup on the setup path. The query is sent as soon as
    the socket is protected and connected, and the lookup, which only matters for the record,
    runs afterwards. DNS flows are not persisted today (`createDatabaseEntity()` returns 0 for
    port 53), so only logging uses the result.
  - `QuicConnection` reads `appPackage` and `appId` for the scope decision (`wouldIntercept`, `EncryptionLayerConnection.kt:96-99`). Its inspector
    runs on datagrams, so make the decision wait for `setUp()` the same way: held datagrams
    are already queued under the Block policy, and under Passthrough nothing waits.
- **Files:** `connection/transportLayer/UdpConnection.kt`,
  `connection/encryptionLayer/QuicConnection.kt` (only if the decision needs the app ID
  before setup completes).
- **Tests:**
  - `UdpConnectionSetupTest` in the style of `TcpConnectionSetupTest`: datagrams that arrive
    before setup completes are forwarded in order afterwards; the queue bound drops the
    oldest; a failed setup closes the flow and drops the queue.
  - `QuicBlockPolicyTest` still passes, including a block decided before setup finished.
  - Device: the measurement above again, then the full stress suite (`udp` tests) and the
    `quic` and `dns` groups of `emulator-traffic.sh`.
- **Implementation notes (2026-10-04): measured, then closed without a code change.**
  - Measurement, as planned, with temporary timing around each step of `UdpConnection`'s
    constructor (removed again). The emulator ran `emulator-traffic.sh run dns quic apps`, which
    starts the Play Store and YouTube, and `run-stress.sh udp`. Times are per flow, on the thread
    that handles the device's packets:

    | | Flows | App lookup p50 / p90 / max | Socket open, protect, connect p50 / p90 / max | Registration p50 / p90 / max | Total p50 / p90 / max |
    |---|---|---|---|---|---|
    | Traffic script, DNS flows | 23 | 0.4 / 1.7 / 10.2 ms | 0.6 / 1.3 / 1.7 ms | 0.2 / 0.4 / 1.3 ms | 1.4 / 2.4 / 10.7 ms |
    | Traffic script, other flows (QUIC, NTP, app starts) | 13 | 0.4 / 0.6 / 0.6 ms | 0.7 / 1.9 / 5.0 ms | 0.2 / 0.3 / 0.7 ms | 1.5 / 3.7 / 5.6 ms |
    | `run-stress.sh udp` | 108 | 0.9 / 1.5 / 4.7 ms | 1.9 / 3.6 / 8.1 ms | 0.5 / 1.2 / 9.4 ms | 3.9 / 7.0 / 12.0 ms |

    The package lookup took under 0.4 ms in every case, and the database insert has been
    asynchronous since PKT-41. For comparison, TCP setup on the thread before PKT-41 took
    12.9 ms at the median, 384 ms at p99 and up to 2,466 ms. A burst of 20 DNS lookups now
    holds the packet thread for roughly 30–80 ms in total.
  - Decision (2026-10-04): not worth the change. The asynchronous version would queue datagrams
    until setup completes and make QUIC's scope decision wait for it. That adds new failure
    modes to the UDP and QUIC paths to remove a few milliseconds per flow. V-67 is lowered to
    Low and stays open in the register. If profiling a real device ever shows these calls
    adding up, this packet is still the plan.
- **Commit:** none (no code change).

**Order for PKT-53 to PKT-61:** PKT-53 and PKT-54 first (High). PKT-55 next: it is small,
and it makes what apps send under Heimdall closer to what they send without it, which every
later measurement benefits from. PKT-56 before PKT-57, which relies on PKT-56's learning for
HTTP/2-only servers and on its `passthroughReason` column. PKT-58 is independent. PKT-59 before
PKT-60, which starts by measuring again after PKT-59. PKT-61 last. PKT-56 and PKT-59 change the
database schema (destructively, as before); doing them in this order means two version bumps.

### PKT-62 — Remove dead code and stale comments in the MitM package

- **Priority:** Low · **Depends on:** none
- **Resolves:** A-2, A-3, A-4, A-5, A-11, A-15
- **Approach:**
  - Delete the dead files: `mitm/nio/NioSslServer.java`, `mitm/nio/NioSslClient.java` and
    `mitm/nio/NioSslPeer.kt` (only those two use it), and in `app/src/test`, the fully
    commented-out `DirectHttpTest.kt` and `TimberExtension.kt` (A-2).
  - Delete `CertificateSniffingMitmManager.createSingleton()` / `getSingleton()` and their
    companion object, together with their only caller, `Authority.generateCertificate()` and
    any helper only it uses (`getStringFromFile()`, if nothing else calls it). That also
    removes the swallowed `""` failure of A-11 (A-3).
  - Delete `KeyStoreHelper.initializeServerCertificates()`, which writes a leaf certificate's
    private key unencrypted and has no callers (A-4).
  - Delete `CertificateSniffingMitmManager.createServerSSLSocket()` (both overloads) and
    `SSLEngineSource.newSSLSocket()` (both), which only reference each other (A-15).
  - Replace `e.printStackTrace()` in `Authority.aliasFile()` with `Timber.e(e, ...)` (A-11).
  - Fix the stale comments: `SSLEngineSource.kt:155` (the key size is
    `CertificateHelper.FAKE_KEY_SIZE`, 2048; drop the SHA1PRNG remark, or fix it with PKT-64),
    and `CertificateSniffingMitmManager.kt:60-63` (say why the upstream CN and SANs are copied:
    the forged certificate must match what the client asked for) (A-5).
  - Before deleting, check once more with a repository-wide search that nothing, including
    `app` and the tests, references what goes.
- **Files:** `core/vpn/.../mitm/nio/*` (deleted), `mitm/CertificateSniffingMitmManager.kt`,
  `mitm/Authority.kt`, `mitm/KeyStoreHelper.kt`, `mitm/SSLEngineSource.kt`;
  `app/src/test/.../DirectHttpTest.kt` and `TimberExtension.kt` (deleted).
- **Tests:** nothing new; the change removes code. All `core:vpn` and `app` tests pass, and
  `./gradlew build` (with lint) succeeds. Device: `emulator-traffic.sh run` and
  `run-stress.sh tls,tlsbulk` are clean, and the CA (generated through the adb trigger, see
  `docs/records/ca-adb-trigger-plan.md`) is unaffected: an existing install keeps its CA and
  intercepts as before.
- **Implementation notes (2026-10-04):**
  - Deleted, after a repository-wide search found no references outside the deleted code
    (`KeyStoreHelperTest`'s `generateCertificate` calls are `CertificateFactory`'s):
    - `mitm/nio/NioSslServer.java`, `NioSslClient.java` and `NioSslPeer.kt`, so the `nio`
      package is gone;
    - `app/src/test/.../DirectHttpTest.kt` and `TimberExtension.kt`;
    - `CertificateSniffingMitmManager`'s companion object (`createSingleton()` /
      `getSingleton()`) and both `createServerSSLSocket()` overloads;
    - `SSLEngineSource.newSSLSocket()` (both);
    - `Authority.generateCertificate()` with `getStringFromFile()` and
      `convertStreamToString()`, which only it used. `loadOrCreatePassword()` stays, since
      `getDefaultInstance()` uses it;
    - `KeyStoreHelper.initializeServerCertificates()`.
  - `Authority.aliasFile()` logs through Timber instead of `printStackTrace()`. The wildcard
    `java.io.*` and the `java.lang` imports were replaced with what is used. An unused
    `PrivateKey` import in `KeyStoreHelper` went with the deleted function.
  - Comments: `SSLEngineSource.createCertForHost()` now says what it returns (a server-mode
    engine with a forged certificate, a 2048-bit RSA key, the context cached per common name),
    and `CertificateSniffingMitmManager` says why the upstream CN and SANs are copied. The
    remark about `SHA1PRNG` went with the old comment; PKT-64 replaces the algorithm itself.
  - Tests: no new ones. 413 `core:vpn` and 18 `app` tests pass, and lint reports nothing in the
    changed files.
  - Emulator: the CA's PEM had the same SHA-256 before and after installing this build and
    starting the VPN, and no new keystore files appeared, so an existing install keeps its CA.
    `run-stress.sh tls,tlsbulk,tlsupstream,tlsalpn` 30/30 with issuer Heimdall where
    intercepted, and `emulator-traffic.sh run` is clean.
- **Commit:** `refactor(vpn): remove dead MitM code and fix stale comments`

### PKT-63 — Keep traffic out of the logs, and smaller robustness fixes

- **Priority:** Low (A-12 is a privacy matter and the most worth doing) · **Depends on:** none
- **Resolves:** A-8, A-12, A-13, A-17, A-19
- **Approach:**
  - A-12: log no traffic outside the `log` flag. In `TlsConnection.kt:1250-1251` (invalid
    record type), log the direction, the record type byte and the payload length; the full hex
    dump only `if(log)`. In `HttpConnection.kt:521` and `:564` (unparseable status line or
    headers), log the length and at most the first line, cut short (e.g. 80 characters), and
    never the header block, which can hold `Cookie` and `Authorization`. Check the rest of
    `core:vpn` for the same pattern (`Timber.*\$message`, `bytesToHex` outside `if(log)`) and
    treat what turns up the same way.
  - A-13: build `headerString` in `TransportLayerConnection.getInstance()` from the flags with
    `listOfNotNull(...).joinToString("-")`, so that a FIN-ACK logs as `FIN-ACK`.
  - A-8: return early from `TlsConnection.prepareRecords()` for an empty payload, before
    `payload[0]`.
  - A-17: where a coroutine catches `Throwable`, catch `CancellationException` first. In
    `HttpConnection`'s request write, fail the deferred (so its response is dropped, as now)
    and rethrow, so that PKT-60's safety bound sees the cancellation and logs that the write
    was given up. In `TlsConnection` (`:163, :211, :537, :559`), rethrow it after the cleanup
    that already happens there.
  - A-19: make the reason of `TlsPassthroughCache.put()` a required parameter, and pass it in
    the tests that call it.
- **Files:** `connection/encryptionLayer/TlsConnection.kt`, `connection/appLayer/HttpConnection.kt`,
  `connection/transportLayer/TransportLayerConnection.kt`, `metadata/TlsPassthroughCache.kt`, and
  the tests that call `put()`.
- **Tests:**
  - `HttpParsingTest`: a request with an unparseable header block and a `Cookie` header leaves
    no log line containing the cookie. Plant a Timber tree that records the lines.
  - `TlsRecordHandlingTest`: an invalid record type logs no hex unless `log` is on, and an
    empty payload is handled without an exception.
  - `HttpPersistenceTest`: with a request write that never returns, the "did not finish" error
    is logged when the safety bound gives the write up (recording tree), as well as dropping the
    response.
  - Device: `run-stress.sh tls,tlsbulk,keepalive` and `emulator-traffic.sh run`, then search
    logcat for request header values the tests send (e.g. `User-Agent: heimdall-stress`) and
    for long hex runs; none may appear.
- **Implementation notes (2026-10-04):**
  - A-12: `TlsConnection` logs an invalid record type as type and payload length; the hex dump
    only `if(log)`. `HttpConnection`'s two parse-failure logs go through a new
    `describeForLog()`: the message length and its first token, at most 16 characters (the method,
    or `HTTP/1.1`). That is stricter than the plan's "first line, cut short": a request line
    carries the path, and query strings carry tokens. A search of `core:vpn` for traffic in
    logs outside `if(log)` (`bytesToHex`, `$message`, payloads, header blocks) found no other
    case. QUIC's one line per flow with SNI and ALPN is connection metadata, at the same level
    as the existing "connection to host" lines, and was left.
  - A-13: `headerString` is built with `listOfNotNull(...).joinToString("-")`.
  - A-8: `prepareRecords()` returns early for an empty payload.
  - A-17: `CancellationException` is caught before `Throwable` and rethrown in
    `HttpConnection`'s request write, response wait and response write, and in `TlsConnection`'s
    four coroutines. The request write fails its deferred with an `IllegalStateException`
    wrapping the cancellation, so the response treats it as a failed request (logged and
    dropped) rather than as a cancellation of its own. Checked against the old code: the
    safety bound's log already appeared there, because the swallowed cancellation still ended
    `withTimeoutOrNull`. So this is defensive. The `TlsConnection` coroutines do not suspend
    today, so they cannot be cancelled mid-way either.
  - A-19: `TlsPassthroughCache.put()` requires its reason; 14 test calls pass it.
  - Tests: new `RecordingTree` (test support). `TlsRecordHandlingTest` +2 (no hex for an
    invalid record type; an empty payload). `HttpParsingTest` +1 (a request line with
    `?token=s3cr3t` and no headers is logged without the token). `ConnectionTeardownTest` +1
    (a FIN-ACK for an unknown flow logs as `FIN-ACK`). `HttpPersistenceTest`'s stuck-write
    test now also checks both log lines. Against the old main sources, the first four fail and
    the last passes, as explained under A-17. 413 `core:vpn` and 18 `app` tests pass.
  - Emulator: `run-stress.sh tls,tlsbulk,keepalive,tlsalpn` 28/28 and `emulator-traffic.sh run`
    clean. In both logcats, Heimdall's lines contain no request header values (`User-Agent`,
    `heimdall-stress`, `Cookie`, `Authorization`) and no hex run of 24 bytes or more. These logs
    only ever appeared on parse failures, so a clean run is the expected outcome, not a
    before/after comparison; the unit tests cover the failure paths.
- **Commit:** `fix(vpn): keep traffic out of error logs and rethrow cancellation`

### PKT-64 — Small protocol and certificate fixes

- **Priority:** Low · **Depends on:** none; best after PKT-62 (touches the same MitM files)
- **Resolves:** A-6, A-7, A-9, A-10, A-14, A-16, A-18
- **Approach:**
  - A-6: for newly generated CAs, mark `KeyUsage` critical and limit it to what a CA needs
    (`keyCertSign`, `cRLSign`, `digitalSignature`), and drop `ExtendedKeyUsage` from the CA, or
    at least `anyExtendedKeyUsage` (`CertificateHelper.kt:132-144`). Leaf certificates keep
    `serverAuth`. An existing CA is not regenerated: V-04/V-05 keep it stable on purpose. A user
    who wants the new extensions regenerates the CA (and installs it again).
  - A-7: generate keys with `SecureRandom()` instead of `SecureRandom.getInstance("SHA1PRNG")`
    (`CertificateHelper.kt:37, 277`), and remove the constant.
  - A-9: draw the initial sequence number from the full 32-bit range with a shared
    `SecureRandom` (`TcpConnection.kt:71`), as an unsigned value in the `Long`.
  - A-10: set the VPN interface's MTU explicitly (`Builder.setMtu`, 1500, as a constant in
    `core:vpn`), and size `DevicePollThread`'s read buffer from the same constant, removing the
    `TODO`. Keep the buffer reused across reads as now.
  - A-14: build stray resets per RFC 9293 §3.10.7.1. For a segment with ACK, as now: sequence
    number = its acknowledgement number, no ACK. For one without ACK: sequence number 0, ACK set,
    acknowledgement number = its sequence number plus its length (plus one each for SYN and
    FIN). Merge `buildStrayRst()` and PKT-58's `buildSynRefusal()` into this one function.
  - A-16: replace `SSLEngineSource.tryHostNameVerificationJava7()` with a direct call:
    `engine.sslParameters = engine.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }`.
    That keeps the engine's other parameters (the method is available on every supported API
    level).
  - A-18: open the database before establishing the VPN interface: in
    `HeimdallVpnService.launchServiceComponents()`, before `establishInterface()`, touch it on
    the IO dispatcher (e.g. `database.openHelper.writableDatabase`). A destructive migration
    then runs while the device's traffic still bypasses the VPN, rather than while the tunnel
    is up and nobody reads it.
- **Files:** `mitm/CertificateHelper.kt`, `mitm/SSLEngineSource.kt`,
  `connection/transportLayer/TcpConnection.kt`, `components/DevicePollThread.kt`,
  `components/ComponentManager.kt` (if the MTU constant lives there),
  `app/.../service/HeimdallVpnService.kt`.
- **Tests:**
  - `CertificateHelperTest`: a new CA has a critical `KeyUsage` with exactly the CA bits, and no
    `anyExtendedKeyUsage`; a leaf certificate still has `serverAuth`.
  - `TcpConnectionSetupTest` (or a small unit test): initial sequence numbers spread over the
    full 32-bit range (a sample of them includes values above `0x0FFFFFFF`).
  - `ConnectionTeardownTest`: a bare FIN for an unknown flow draws a reset with ACK set and the
    acknowledgement number one past the FIN; an ACK for an unknown flow draws one as before.
  - `InsecureTrustManagerTest` / a new test: an upstream engine from `SSLEngineSource` has
    endpoint identification `HTTPS` and keeps the cipher suites set before it.
  - Device:
    - `ip link show tun0` shows the explicit MTU, and the full stress suite passes.
    - Generate a new CA through the adb trigger and install it; `run-stress.sh tls,tlsalpn` and
      `emulator-traffic.sh run` pass with it, so Android accepts the stricter extensions.
    - Install a build with a bumped schema version (on a scratch branch, not committed) and
      check that the first `run-stress.sh download` after it no longer has timed-out first
      connections.
- **Implementation notes (2026-10-04):**
  - A-6: a new CA's `KeyUsage` is critical, with `keyCertSign`, `cRLSign` and
    `digitalSignature`. Its `ExtendedKeyUsage` keeps `serverAuth` and `clientAuth` and drops
    `anyExtendedKeyUsage` (the plan's "at least" option). Dropping the extension entirely
    would make the CA valid for every purpose again, which is what removing
    `anyExtendedKeyUsage` is meant to avoid. **Deviation:** the planned test "a leaf
    certificate still has `serverAuth`" was not written, because leaves never had an
    `ExtendedKeyUsage`. Giving them one is V-09's subject, which stays deferred. Existing CAs
    are not regenerated.
  - A-7: `generateKeyPair()` initialises the generator with `SecureRandom()`;
    `SECURE_RANDOM_ALGORITHM` is gone.
  - A-9: `TcpConnection.newInitialSequenceNumber()` draws 32 bits from a shared
    `SecureRandom`, as an unsigned value in the `Long`.
  - A-10: `VPN_MTU = 1500` is a top-level constant in `ComponentManager.kt`.
    `HeimdallVpnService` passes it to `Builder.setMtu()`, and `DevicePollThread` sizes its
    reused buffer from it. The `TODO` is gone.
  - A-14: `TcpConnection.buildResetFor(segment)` replaces `buildStrayRst()` and
    `buildSynRefusal()`:
    - for a segment with ACK, the reset has sequence number = its acknowledgement number and
      no ACK;
    - otherwise, the reset has sequence number 0, ACK set, and acknowledges the segment's
      sequence number plus its payload length, plus one each for SYN and FIN;
    - the window is 0.
    Both stray paths in `TransportLayerConnection` call it.
  - A-16: `SSLEngineSource.enableHostnameVerification()` sets `endpointIdentificationAlgorithm`
    on the engine's own parameters and writes them back. It is called in
    `newSSLEngine(host, port)` before the weak-cipher filter. The throwaway engine that
    `initialiseSSLContext()` built only to call the old reflective method is gone.
  - A-18: `launchServiceComponents()` opens the database on the IO dispatcher after reading
    the Private DNS mode and before `establishInterface()`.
    - Before the change, the premise was not reproduced on a quiet host:
      - the old build's start, from "Ready to establish VPN interface" to "Traffic handlers
        initialised", took 0.52 s normally;
      - it took 1.63 s after a simulated schema change on a 192 MB database, and 0.76–0.97 s on
        a 159 MB synthetic one.
    - With this build, on a heavily loaded host (load average ~8), a schema change on the
      159 MB database spent **20.5 s** in Room's destructive migration between "MitM scope"
      and "Beginning interface establishment", so the tunnel did not exist yet. The tunnel
      was then unserved for 7.06 s, about the same as a normal start under that load. That is
      the length of the gap seen after PKT-59, so its likely cause was a migration on a busy
      host. It now happens before the tunnel is up.
  - Tests:
    - `CertificateHelperTest` +2: `KeyUsage` is critical with exactly bits 0, 5 and 6; the
      EKU has `serverAuth` and `clientAuth` but not `anyExtendedKeyUsage`.
    - New `CaChainValidationTest`: a new CA and a forged leaf validate under PKIX with the CA
      as the only anchor. With `HEIMDALL_WRITE_CA_CHAIN` set, it writes both as PEM for the
      device check below.
    - New `InitialSequenceNumberTest`: values above `0x0FFFFFFF` occur, and all are in the
      unsigned 32-bit range.
    - `ConnectionTeardownTest` +2: a bare FIN for an unknown flow draws a RST with ACK,
      sequence number 0 and the acknowledgement one past the FIN; an ACK draws a RST without
      ACK, with its acknowledgement number as the sequence number.
    - `InsecureTrustManagerTest` +1: an upstream engine has endpoint identification `HTTPS`,
      keeps its ALPN offer, and still has the weak DHE suites filtered out.
    - In total, 420 `core:vpn` and 18 `app` tests pass. Lint reports nothing new.
  - Emulator:
    - `ip link show tun0` shows `mtu 1500`, and ConnectivityService logs `MTU: 1500` for the
      VPN network.
    - The full `run-stress.sh` gives 81 passed and 1 failed. The failure is `udp-burst-500`,
      which fails without the VPN too (emulator NAT, see the baseline above). There were no
      crash lines.
    - `emulator-traffic.sh run` is clean. 150 requests were decrypted over 153 TLS
      connections using the installed (old) CA, so leaves from the changed key generation are
      accepted.
  - **Deviation in the CA check:** the planned check "generate a new CA through the adb
    trigger and install it" was not run on the emulator. It would replace the CA installed
    in its system store and break decryption for the installed apps until that CA is
    reinstalled. Instead:
    - `CaChainValidationTest` checks the chain with the JVM's PKIX validator;
    - a probe run on the emulator (API 33) with `app_process` validated the same CA and leaf
      with Conscrypt's `TrustManagerImpl`, Android's own validator: chain OK.
    To check it with real apps, regenerate the CA through the adb trigger, install it in the
    system store, and run `run-stress.sh tls,tlsalpn`.
  - A start-time comparison was made under load, because the slow starts above looked like a
    regression. This build and the previous commit were installed alternately, three rounds
    each. They took the same time:
    - after install: 5.9–7.9 s with this build, 6.5–8.2 s with the previous commit;
    - restart: 4.0–4.6 s with this build, 3.7–4.3 s with the previous commit.
    The time goes to GC and the hosts trie, whose build took 1.5–4.6 s, against 0.26–0.38 s
    on a quiet host.
- **Commit:** `fix(vpn): tighten CA extensions, ISN range, stray resets and MTU handling`

**Order for PKT-62 to PKT-64:** independent of each other. PKT-63 first, for the logging (A-12),
which is the only item with a privacy impact. PKT-62 before PKT-64, which edits the same MitM
files and is easier to review once the dead code around them is gone.

**Deferred / lower priority (V-07, V-08, V-09, V-17, V-26, V-27, V-28):** each is real but either
narrow-trigger (V-07 needs a CN shared across differing-SAN certs within a 5-minute window; V-17
needs an actively hostile or badly-behaved TCP peer; V-27/V-28 are minor selector/teardown
hygiene with no correctness impact observed) or a genuinely open architectural question (V-26,
confining all of a `TlsConnection`'s mutation to a single-threaded per-connection dispatcher, is
a bigger refactor than a packet — worth a dedicated design pass rather than a quick fix). Revisit
after PKT-01 through PKT-25 land.

---

## Appendix — low-severity / code smell (not given full packets)

Reviewed again on 2026-10-04, after PKT-53 to PKT-61, against the code at that point. Each item
says whether it still applies. A-12 to A-19 were added then, from things noticed while
implementing the second-audit packets. Line numbers are those of 2026-10-04.

Packets: PKT-62 removes dead code and fixes stale comments (A-2, A-3, A-4, A-5, A-11, A-15);
implemented 2026-10-04, so those six are resolved.
PKT-63 keeps traffic out of the logs and fixes smaller robustness issues (A-8, A-12, A-13, A-17,
A-19); implemented 2026-10-04, so those five are resolved.
PKT-64 makes the small protocol and certificate fixes (A-6, A-7, A-9, A-10, A-14, A-16, A-18);
implemented 2026-10-04, so those seven are resolved. A-18's cause turned out to be a destructive
migration on a heavily loaded host (see PKT-64's notes).

### Resolved

- **A-1 — Debug scaffolding in production `TlsConnection`.** *Resolved* (commit `48af91e`,
  2026-09-29): no `System.err.println` and no stack-trace dump are left, and `log` is
  `private val log = false`. Two traffic dumps outside the `log` flag remained; see A-12.

### Still open

- **A-2 — Dead files.** `mitm/nio/NioSslServer.java` and `mitm/nio/NioSslClient.java` are still
  commented out past their package line. Also dead: `mitm/nio/NioSslPeer.kt`, live code
  referenced only by those two files, and in `app/src/test`, `DirectHttpTest.kt` and
  `TimberExtension.kt`, both commented out entirely (`DirectHttpTest` still imports a package
  that no longer exists and uses JUnit 5, which is not a dependency). Delete all five.
- **A-3 — Unused, unsynchronised singleton.** `CertificateSniffingMitmManager.createSingleton()`
  / `getSingleton()` (`:105-120`) are still there. The original note was imprecise: the
  singleton does have a caller, `Authority.generateCertificate()` (`Authority.kt:100-125`), but
  that function has none, apart from the commented-out `DirectHttpTest`. Delete both;
  `ComponentManager` builds its own manager.
- **A-4 — Latent plaintext private-key export.**
  `KeyStoreHelper.initializeServerCertificates()` (`:139-160`) still writes a leaf key to
  `-<commonName>-key.pem` unencrypted and still has no callers. Delete it.
- **A-5 — Stale comments.** `SSLEngineSource.kt:155` still says "1024 bit RSA key pair using
  SHA1PRNG" (the size is 2048). `CertificateSniffingMitmManager.kt:60-63` still says that using
  the upstream CN and SANs "is not necessary", right above code that uses them.
- **A-6 — CA certificate extensions.** Unchanged: `KeyUsage` is non-critical
  (`CertificateHelper.kt:137`), and the CA's `ExtendedKeyUsage` includes `anyExtendedKeyUsage`
  (`:143`). Only newly generated CAs would change, and existing installs keep their CA (V-04/V-05
  keep it stable on purpose), so this can be done at any time without disturbing anyone.
- **A-7 — `SHA1PRNG`.** Still pinned for key generation (`CertificateHelper.kt:37, 277`). Other
  places in the same file and in `Authority` already use `SecureRandom()`. Use it here too.
- **A-8 — `payload[0]` in `prepareRecords`.** Still read unconditionally
  (`TlsConnection.kt:1184`). `checkForSnippets()` returns the raw payload unchanged when no
  snippet is pending, and the transport layer never passes an empty payload, so it cannot
  throw today. A guard costs nothing and V-10 makes the case for it.
- **A-9 — 28-bit initial sequence number.** Still `(Math.random() * 0xFFFFFFF)`
  (`TcpConnection.kt:71`). Harmless for the client-facing side (the device is the only peer
  that sees it, and the reorder buffer and window checks are wrap-safe), but it is also
  needlessly predictable. Draw 32 bits from `SecureRandom`.
- **A-10 — 1500-byte device read buffer.** Still `ByteArray(1500)` with its `TODO`
  (`DevicePollThread.kt:32`). The builder sets no MTU, and the interface came up with
  `mtu 1500` on the emulator, so reads fit today. Set the MTU explicitly
  (`Builder.setMtu`) and size the buffer from the same constant, so the two cannot drift. Since
  PKT-46, fragments are reassembled after the read, so nothing else depends on 1500.
- **A-11 — `printStackTrace()` and the swallowed CA-generation failure in `Authority`.**
  `aliasFile()` (`:36-37`) and `generateCertificate()` (`:121-123`) still use
  `printStackTrace()`. `generateCertificate()` still returns `""` on failure, but it is dead
  (A-3); deleting it settles that part.

### Added on 2026-10-04

- **A-12 — Traffic in error logs.** Three logs write traffic to logcat whatever `log` says:
  - `TlsConnection.kt:1250-1251`: the whole payload as hex when a record type is invalid. That
    is how the DNS query of V-68 ended up in the log; for misclassified plaintext it is the
    plaintext.
  - `HttpConnection.kt:521` and `:564`: the whole header block when a status line or header
    block cannot be parsed, including `Cookie` and `Authorization` headers.

  PKT-56 already put the upstream-handshake hex dump behind `log`; do the same here. Log
  lengths and the first bytes' types instead. (Logcat can be read by anything with `READ_LOGS`,
  and it ends up in bug reports.)
- **A-13 — Misbuilt log line.** `TransportLayerConnection.kt:465` builds `headerString` as
  `if (fin) "FIN" else "" + if (ack) "ACK" else ...`. Operator precedence makes a FIN-ACK log as
  just `FIN`, and the `rst` part can never show, because reset segments are handled before.
  Cosmetic.
- **A-14 — Stray reset for a segment without ACK.** `TcpConnection.buildStrayRst()` (`:1575`)
  always clears ACK and uses the segment's acknowledgement number as its sequence number. That
  is right for a segment that carries ACK (RFC 9293 §3.10.7.1). For one without ACK (a bare
  FIN), the reset should carry ACK, sequence number 0 and acknowledge the segment. The device
  otherwise ignores the reset. PKT-58's `buildSynRefusal()` does it right for SYNs and could
  be generalised. Rare in practice.
- **A-15 — Unused socket API.** `CertificateSniffingMitmManager.createServerSSLSocket()` (both
  overloads) and `SSLEngineSource.newSSLSocket()` (both) are only referenced by each other.
  Delete them.
- **A-16 — Java 7 reflection for hostname verification.**
  `SSLEngineSource.tryHostNameVerificationJava7()` looks up
  `SSLParameters.setEndpointIdentificationAlgorithm` by reflection (available on every
  supported API level), and it replaces the engine's parameters with a fresh `SSLParameters`
  object, which would wipe anything set on them before. PKT-57's `Alpn.offer()` sets its
  protocols afterwards, so nothing is lost today. Call the method directly on
  `engine.sslParameters` and write them back.
- **A-17 — Cancellation swallowed in persistence code.** `HttpConnection`'s request write
  (`:462`) catches `Throwable`, which includes the `CancellationException` of PKT-60's safety
  bound. The request ID is still failed and the response dropped, as intended, but the bound's
  own "did not finish" log may not appear. Catch `CancellationException` separately, complete
  the deferred, and rethrow it. The same pattern appears in `TlsConnection`'s coroutines
  (`:163, :211, :537, :559`), where swallowing is less harmful but still masks cancellation.
- **A-18 — First start after a schema change leaves the tunnel unserved.** Seen after PKT-59's
  install: `tun0` was up for about 20 s before the traffic threads started, so every packet sent
  in that time went unanswered. The likely cause is Room's destructive migration running on
  the first database access while `launchServiceComponents()` creates the session. It only
  happens once per schema change (destructive migration stays by design, see `CLAUDE.md`).
  Opening the database before establishing the interface would avoid it.
- **A-19 — Test-only defaults in production code.** `TlsPassthroughCache.put()` defaults its
  reason to `CLIENT_HANDSHAKE_ERROR` only to spare the tests an argument (PKT-56). Make the
  reason a required parameter, or move the helper to the tests.

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
