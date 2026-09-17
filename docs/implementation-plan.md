# Heimdall — Implementation Plan for `docs/architecture-issues.md`

> Each packet below is implemented and committed on its own, on request. This document makes no code changes itself.

## Context

`docs/architecture-issues.md` (revised 2026-09-15 after verification against the `ui-rework` tree) lists ~35 findings. About ten are live bugs:
- the live dashboard stays empty
- install/uninstall scans never run
- VPN service crashes and teardown races
- ScanWorker ignores prefs and cancels itself
- offline scans permanently hide trackers
- system-app detection is broken
- byte counters are never written
- exporting a score report crashes
- MITM_PROXY mode is dead
- a TCP threading race

The rest are latent risks: destructive migrations, a broken CSV exporter, disabled upstream certificate checks, duplicated MitM stacks, and unbounded in-memory lists.

This plan resolves all of them as **packets**. Each packet:
- is one commit
- leaves `./gradlew build` green
- adds tests that would have caught its bug, where testable
- lists the findings it resolves, its dependencies, the files touched, its tests, and a suggested commit message (in the repo's lowercase past-tense style)

### Decisions made with the user
- **Proxy:** remove MITM_PROXY mode and delete `core:proxy`. One MitM implementation (`core:vpn`) remains.
- **Upstream certificates:** a new preference, **"Trust all upstream servers" (default off)**. When it's off, upstream certificates are validated with hostname verification. On a handshake failure the (app, host) pair is recorded in `TlsPassthroughCache`, so later connections pass through without interception.
- **Byte counters:** implement real byte tracking in `core:vpn` with batched Room flushes.

### Defaults (flag during review if you disagree)
- `core:export` gets fixed and tested but stays **unwired** from the UI.
- Room schema export is on. Future version bumps need an explicit `Migration`/`AutoMigration`. Destructive fallback stays only for legacy versions 1–5 and for downgrades.
- Live lists use Paging 3 (new `androidx.paging`/`room-paging` catalog entries). Analytics use SQL aggregates.

### Conventions for every packet
- Tests in `core:vpn` build packets with `IpV4Packet.newPacket()` from raw bytes (see `integration/support/PacketFixtures.kt`), not `TcpPacket.Builder`.
- A packet that needs test dependencies adds them to `gradle/libs.versions.toml` and that module's `build.gradle.kts`. The `core/vpn/build.gradle.kts` setup is the model (junit, mockk, `kotlinx-coroutines-test`, `isReturnDefaultValues = true`), plus robolectric and `androidx-test-core` where Android classes are needed.

---

## Packet overview

| # | Packet | Depends on | Kind |
|---|---|---|---|
| **Group A: Foundation** ||||
| A1 | Remove stale tests and debug output | — | hygiene |
| A2 | Room schema export, migration policy, DB test harness | A1 | latent data loss |
| **Group B: Live app-layer bugs** ||||
| B1 | Pass capture session ID to the VPN service | A1 | live bug |
| B2 | Shared `isSystemApp` helper | A1 | live bug |
| B3 | ScanWorker input data and unique work names | A1 | live bug |
| B4 | Boot receiver: `goAsync`, QUICKBOOT, full-removal handling | B3 | live bug |
| B5 | Runtime package-added receiver and uninstall reconciliation | B4 | live bug |
| B6 | Score report export without app-context `startActivity` | A1 | live bug (crash) |
| B7 | Observable row expansion on the Database screen | A1 | live bug |
| **Group C: Proxy removal** ||||
| C1 | Remove MITM_PROXY mode and `core:proxy` | B1 | live bug + duplication |
| **Group D: VPN pipeline** ||||
| D1 | VPN service lifecycle state machine | C1 | live bug (crash/races) |
| D2 | Per-connection lock for the TCP/TLS stack | A1 | live bug (race) |
| D3 | TCP split-payload sequence number fix | D2 | bug |
| D4 | `ConnectionCache` as an instance with a 5-tuple key | D2 | bug |
| D5 | Ordered async capture writer | A2, D4 | performance |
| D6 | Byte tracking | D5 | live bug |
| D7 | Poll buffer sized from `maxPacketSize` | A1 | latent |
| D8 | DNS cache fixes and dead-code removal | A1 | bug |
| D9 | Remove the MitM singleton and `Authority.generateCertificate` | A1 | cleanup |
| **Group E: MitM trust** ||||
| E1 | Bounded passthrough cache, filled on handshake failure | D2 | bug |
| E2 | "Trust all upstream servers" preference and validation | C1, E1 | security |
| **Group F: Data and scanner** ||||
| F1 | Retryable tracker signatures (offline scans) | B3 | live bug |
| F2 | `ExodusUpdater` injection and stable tracker IDs | A2, F1 | latent |
| F3 | CSV export: shared model, columns, escaping | A2 | latent |
| F4 | TeX export entry point | F3 | latent |
| F5 | Datastore serializer round-trip test | E2 | tests |
| **Group G: App-layer structure** ||||
| G1 | Shared `AppScanCoordinator` | B2, F1 | duplication + bugs |
| G2 | Split scoring (`ScoreModule`) from Compose cards | A1 | coupling |
| G3 | Paged Database screen and SQL analytics | A2 | scalability |
| G4 | Bounded live dashboard; `ScoreViewModel` flows and concurrency | G3 | scalability |
| G5 | Remove `MainRepository` and dead scanner dialog state | A1 | cleanup |
| **Group H: Docs** ||||
| H1 | Update ARCHITECTURE.md, CLAUDE.md, README, issues doc | all | docs |

Group B, the D2–D9 set, and G2/G5 can be done in any order once their dependencies are met.

---

## Group A: Foundation

### A1: Remove stale tests and debug output
**Resolves:** part of "Test coverage gaps" (app tests don't compile), plus leftover debug output in `TlsConnection`.
**Changes:**
- **Stale tests:** delete `app/src/test/java/de/tomcory/heimdall/DirectHttpTest.kt`, which imports the removed `de.tomcory.heimdall.vpn.mitm`. Check `HttpTest.java`, `ExtendedShadowOs.java`, and `TimberExtension.kt`: keep any that still compile and are used, delete the rest.
- **Debug output** in `core/vpn/.../encryptionLayer/TlsConnection.kt`: remove `System.err.println` and the stack dump in `closeConnection` (437-438), plus the `DBG-PROD` prints at 411 and 416.
- **Stray file:** delete `core/database/src/main/java/de/tomcory/heimdall/core/database/dao/ggg.txt`.

**Verify:** `./gradlew build` (this includes `:app:testDebugUnitTest`).
**Commit:** `removed stale app tests and leftover debug output`

### A2: Room schema export, migration policy, DB test harness
**Resolves:** "Silent destructive-migration fallback with no migrations"; the foundation for DAO tests.
**Changes:**
- **Schema export:**
  - `core/database/build.gradle.kts`: add `ksp { arg("room.schemaLocation", "$projectDir/schemas") }`, add the schemas dir to test assets, and add test deps (junit, robolectric, `androidx-test-core`, `androidx-room-testing`, `kotlinx-coroutines-test`).
  - `libs.versions.toml`: add `androidx-room-testing` (Room 2.7.1).
  - `HeimdallDatabase.kt:42`: set `exportSchema = true`, and commit the generated `schemas/.../6.json`.
- **Migration policy** (`DatabaseModule.kt:22`): replace `.fallbackToDestructiveMigration()` with `.fallbackToDestructiveMigrationFrom(true, 1, 2, 3, 4, 5)` and `.fallbackToDestructiveMigrationOnDowngrade(true)`.

**Tests:** new `core/database/src/test/.../HeimdallDatabaseSchemaTest.kt` (Robolectric). It creates v6 via `MigrationTestHelper` and opens an in-memory `HeimdallDatabase`.
**Commit:** `enabled room schema export and replaced destructive migration fallback`

---

## Group B: Live app-layer bugs

### B1: Pass capture session ID to the VPN service
**Resolves:** "Live traffic dashboard observes a session the VPN never writes to."
**Changes:**
- **Service** (`HeimdallVpnService.kt`): add `const val EXTRA_SESSION_ID = "de.tomcory.heimdall.core.vpn.SESSION_ID"` and use it at line 81.
- **ViewModel** (`TrafficScannerViewModel.kt`): `launchVpn` (207-212) takes `sessionId` and adds `putExtra(EXTRA_SESSION_ID, sessionId)`. `startVpnStack` passes the session created at line 189. If `persistSession` returned -1, don't set `_currentSessionId` and don't pass the extra; the service's `ComponentManager` creates one.

**Verify:** on a device, start capture: `LiveDashboard` shows connections.
**Commit:** `fixed live dashboard by passing the capture session id to the vpn service`

### B2: Shared `isSystemApp` helper
**Resolves:** "System-app detection broken in both scanner ViewModels."
**Changes:**
- **Helper** (`core/util/.../OsUtils.kt`): add `fun isSystemApp(flags: Int?): Boolean = ((flags ?: 0) and ApplicationInfo.FLAG_SYSTEM) != 0`, and use it in `getSystemApps()` (24).
- **Callers:** replace the broken expressions in `PermissionScannerViewModel.kt:130,162,175`, `LibraryScannerViewModel.kt:135,166,179`, and `ScanWorker.kt:113,166`.

**Tests:** `core/util/src/test/.../OsUtilsTest.kt` (JVM): flags 0, only FLAG_SYSTEM, FLAG_SYSTEM plus other bits, other bits only, null. This adds junit to `core/util`.
**Commit:** `fixed system app detection in the scanner viewmodels`

### B3: ScanWorker input data and unique work names
**Resolves:** "`ScanWorker` enqueueing ignores preferences and cancels in-flight scans."
**Changes** (`ScanWorker.kt:203-221`):
- **Input data:** always call `setInputData(workDataOf(KEY_PACKAGE_NAME to packageName, KEY_SCAN_LIBRARIES to …, KEY_SCAN_PERMISSIONS to …))`.
- **Unique names:** full scans use `"scan-full"` with `ExistingWorkPolicy.KEEP`. Single-package scans use `"scan-pkg-$packageName"` with `REPLACE`. Remove `UNIQUE_WORK_NAME`.

**Tests:** `app/src/test/.../ScanWorkerEnqueueTest.kt` (Robolectric plus `WorkManagerTestInitHelper`, adding `androidx.work:work-testing` to the catalog):
- A full-scan request carries the preference flags.
- A second full-scan enqueue keeps the first.
- A single-package enqueue doesn't cancel a running full scan.

**Commit:** `fixed scan worker ignoring scan preferences and cancelling running scans`

### B4: Boot receiver: `goAsync`, QUICKBOOT, full-removal handling
**Resolves:** "`HeimdallBroadcastReceiver` uses an unmanaged CoroutineScope," the unreachable `PACKAGE_REMOVED` handler, and the QUICKBOOT fall-through.
**Changes:**
- **Manifest** (`AndroidManifest.xml:60-66`): add a second `<intent-filter>` for `android.intent.action.PACKAGE_FULLY_REMOVED` with `<data android:scheme="package"/>`. This broadcast is exempt from implicit-broadcast limits.
- **Receiver** (`HeimdallBroadcastReceiver.kt`):
  - Map `QUICKBOOT_POWERON` to the boot path, and `ACTION_PACKAGE_FULLY_REMOVED` to `appDao().updateIsInstalled`. Remove the unreachable `ACTION_PACKAGE_REMOVED` branch.
  - Wrap work in `val pending = goAsync()` with a coroutine that calls `pending.finish()` in `finally`.
  - Move the bodies into `internal suspend fun handle(context, action, packageName)`.

**Tests:** Robolectric `HeimdallBroadcastReceiverTest`:
- boot with `bootScanService=true` enqueues work
- QUICKBOOT behaves like boot
- full removal marks the app uninstalled (in-memory DB)

**Commit:** `fixed boot receiver lifecycle and handled full package removal`

### B5: Runtime package-added receiver and uninstall reconciliation
**Resolves:** "Package install/uninstall handlers are unreachable" (installs, and removals missed while the process was dead).
**Changes:**
- **Runtime registration** (`HeimdallApplication.onCreate`): register `HeimdallBroadcastReceiver` for `ACTION_PACKAGE_ADDED` (with the `package` scheme) via `ContextCompat.registerReceiver(…, RECEIVER_NOT_EXPORTED)`. The receiver treats `ACTION_PACKAGE_ADDED` (including `EXTRA_REPLACING`) as a single-package scan.
- **Reconciliation:**
  - `AppDao`: add `@Query("SELECT packageName FROM App WHERE isInstalled = 1") suspend fun getInstalledPackageNames(): List<String>`.
  - `ScanWorker.performFullScan`: after the loop, mark DB-installed packages missing from `getInstalledPackages` as uninstalled.

**Tests:** extend `HeimdallBroadcastReceiverTest` so `PACKAGE_ADDED` enqueues `scan-pkg-<name>`. Add a Robolectric `ScanWorker` test (`TestListenableWorkerBuilder`, shadow `PackageManager`) showing removed packages get `isInstalled = 0`.
**Commit:** `registered package install receiver at runtime and reconciled uninstalled apps in full scans`

### B6: Score report export without app-context `startActivity`
**Resolves:** "Exporting a score report crashes on API 28+."
**Changes:**
- `ScoreViewModel.kt:185-197`: replace `exportToJson()` with `suspend fun buildReportJson(): String? = withContext(Dispatchers.IO) { evaluator.exportReportToJson(selectedAppLatestReport.value) }`.
- `AppScoreScreen.kt:~141`: call it, then `LocalContext.current.startActivity(Intent.createChooser(Intent(ACTION_SEND).setType("text/json").putExtra(EXTRA_TEXT, json), null))`.

**Verify:** on an API 34 emulator, export from an app's score screen: the share sheet opens.
**Commit:** `fixed crash when exporting a score report`

### B7: Observable row expansion on the Database screen
**Resolves:** "Connection rows probably don't expand on tap."
**Changes:**
- `DatabaseViewModel.kt:94-101`: expose `val expandedConnectionId: StateFlow<Int?>` and remove `isExpanded()`.
- `DatabaseScreen.kt:~101`: `val expandedId by viewModel.expandedConnectionId.collectAsState()`, then `expanded = expandedId == conn.id`.

**Verify:** on a device, tap a row with capture stopped: it expands immediately.
**Commit:** `fixed connection rows not expanding on the database screen`

---

## Group C: Proxy removal

### C1: Remove MITM_PROXY mode and `core:proxy`
**Resolves:** "`MITM_PROXY` mode never routes traffic through the proxy," "Duplicated MitM/TLS stacks in two modules," and the proxy half of "Upstream certificate validation is disabled."
**Changes:**
- **Build:**
  - `settings.gradle.kts`: remove `include(":core:proxy")`. `app/build.gradle.kts:167`: remove the dependency. Delete `core/proxy/`.
  - `libs.versions.toml`: remove entries only proxy used (grep first: `dnssec4j`, `lightbody-mitm`, `jzlib`, …). **Keep** `netty-all`, which `core:vpn` uses.
- **`TrafficScannerViewModel.kt`:**
  - `VpnMode { BASE, MITM_VPN }`.
  - Delete `proxyServer`, `launchProxy` (214-237), and the `useProxy` branches in `onScan`/`startVpnStack`/`onVpnModeChanged`.
  - Rename `stopProxyAndVpn` to `stopVpn`, and simplify the `init` mode mapping.
- **UI:**
  - `TrafficScannerCard.kt`: mode list at 195-197, help text at 296, indicator at 350-352, and the proxy previews at 550-585.
  - `ScannerControlStrip.kt`: 222-240.
  - `TrafficScannerPreferences.kt`: 82-92.
  - `PreferencesScreen.kt`: the commented proxy text and block at 35-37 and 270-289.
- **Service** (`HeimdallVpnService.kt`): remove the `useProxy` computation (217-225), the `setHttpProxy` block (351-368), and the proxy mode labels in `createForegroundNotification`.
- **Application** (`HeimdallApplication.onCreate`): remove `setProxyActive(false)`.
- **Datastore:**
  - `PreferencesDataSource.kt`, `PreferencesInitialValues.kt` (13-14, 51), `PreferencesSerializer.kt`: remove `vpnUseProxy`, `vpnProxyAddress`, `proxyActive`.
  - `preferences.proto`: delete fields 7, 8, and 42, and add `reserved 7, 8, 42;` plus `reserved "vpn_use_proxy", "vpn_proxy_address", "proxy_active";`.
- **Docs:** remove `core/proxy` from the CLAUDE.md module list (the full docs pass is H1).

**Verify:** `./gradlew clean build`. `grep -r "core.proxy\|MITM_PROXY\|vpnUseProxy" app core` is empty. The mode selector shows Off/VPN only.
**Commit:** `removed mitm proxy mode and the core proxy module`

---

## Group D: VPN pipeline

### D1: VPN service lifecycle state machine
**Resolves:** "VPN service start/stop lifecycle is unsafe" (sticky-restart crash, duplicate START teardown, ignored STOP, orphaned pipeline).
**Changes:**
- **New controller:** `app/src/main/java/de/tomcory/heimdall/service/VpnLifecycleController.kt`, pure Kotlin.
  - `sealed interface Command { data class Start(val sessionId: Int); object Stop }` and `enum class State { IDLE, STARTING, RUNNING, STOPPING }`.
  - A `Channel<Command>` with a single consumer coroutine gives strict FIFO. It receives `start: suspend (Int) -> Boolean` and `stop: suspend () -> Unit` lambdas.
  - START in STARTING or RUNNING does nothing. STOP in IDLE does nothing. A failed start returns to IDLE.
- **`HeimdallVpnService.kt`:**
  - `onStartCommand(intent: Intent?, …)`: a null intent (sticky restart) or `VpnService.SERVICE_INTERFACE` means `Start(-1)`. The method only calls `controller.trySend`.
  - A service-owned `scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)` hosts the controller. Remove the unscoped `CoroutineScope(Dispatchers.IO).launch` calls at 93 and 108.
  - The start lambda runs `establishInterface` plus `ComponentManager`. On failure it calls `stopSelf()` and sets `vpnActive=false`.
  - The stop lambda runs `componentManager?.stopComponents()`, then `vpnInterface?.close()`, **nulls both fields**, stops notification updates, calls `stopForeground(STOP_FOREGROUND_REMOVE)`/`stopSelf()`, and updates prefs. Remove the `componentsActive` flag.
  - `onDestroy`: send `Stop` and cancel `scope` when the consumer is idle.
  - `createForegroundNotification`: compute the mode label once at start (no `runBlocking` on the main looper every second).

**Tests:** `app/src/test/.../VpnLifecycleControllerTest.kt` (`kotlinx-coroutines-test`):
- START,START → one start
- START,STOP → start then stop
- STOP while STARTING → the stop runs after start completes
- a failed start → IDLE, and a later START retries

**Verify:** the lifecycle checks in the end-to-end checklist.
**Commit:** `serialized vpn service start and stop through a lifecycle state machine`

### D2: Per-connection lock for the TCP/TLS stack
**Resolves:** "Unsynchronized TCP connection state shared across threads."
**Changes:**
- **Lock:** `TransportLayerConnection.kt` gets `internal val lock = Any()`, and `state` (102) becomes `@Volatile`.
- **Acquire it at every entry point:**
  - `OutboundTrafficHandler.kt:44`: `synchronized(connection.lock) { connection.unwrapOutbound(ipPacket.payload) }`.
  - `InboundTrafficHandler.kt:42`: `synchronized(attachment.lock) { attachment.unwrapInbound() }`, nested inside the existing `selectorMonitor` block.
  - `TlsConnection.kt`: coroutine bodies at 306-309, 320-323, and 415-417 take `synchronized(transportLayer.lock)` around `setupServerSSLEngine`/`setupClientSSLEngine`/`continueHandshake`. The delegated `tasks.forEach { it.run() }` (409) runs **outside** the lock.
  - `ConnectionCache.closeAllAndClear`: `synchronized(connection.lock)` around `closeSoft()`.
- **Lock order** (KDoc on `lock` and `ComponentManager.selectorMonitor`): `selectorMonitor` before `connection.lock`, never the reverse. Audit that no `unwrap*`/`wrap*`/`close*` path takes `selectorMonitor`; today only the constructors at `TcpConnection.kt:120` and `UdpConnection.kt:110` do.

**Tests:** extend `core/vpn/src/test/.../integration/ConcurrentConnectionsTest.kt`. Interleave outbound data segments and inbound readable events for one `TcpConnection` from two threads over many iterations. Assert that SEQ/ACK in packets sent to the mocked device-writer `Handler` are monotonic and consistent with the bytes exchanged.
**Commit:** `confined tcp and tls connection state to a per-connection lock`

### D3: TCP split-payload sequence number fix
**Resolves:** "TCP sequence number over-advanced when splitting large inbound payloads."
**Changes:** `TcpConnection.kt:236`: `increaseOurSeqNum(temp.size)`.
**Tests:** new `connection/transportLayer/TcpSplitPayloadTest.kt`. `wrapInbound` gets a payload of `2 × maxPacketSize + 100` bytes. Assert three segments with sequence numbers `s`, `s + max`, `s + 2·max`.
**Commit:** `fixed tcp sequence numbers when splitting large inbound payloads`

### D4: `ConnectionCache` as an instance with a 5-tuple key
**Resolves:** "Global static `ConnectionCache` with a collision-prone key."
**Changes:**
- **Cache** (`cache/ConnectionCache.kt`): make it an instance class with `ConcurrentHashMap<ConnectionKey, TransportLayerConnection>`, `data class ConnectionKey(val remoteAddress: InetAddress, val protocol: Int, val localPort: Int, val remotePort: Int)`, and `values(): Collection<TransportLayerConnection>` (needed by D6). Delete the companion.
- **Owner:** `ComponentManager.kt` adds `val connectionCache = ConnectionCache()`, and `stopComponents` (174) calls `connectionCache.closeAllAndClear()`.
- **Callers** use `componentManager.connectionCache`: `TcpConnection.kt:273,344`, `TransportLayerConnection.kt:182,216,263`.

**Tests:** new `cache/ConnectionCacheTest.kt`: `1.2.3.4:443`/local 40000 and `1.2.4.4:443`/local 40007 stay distinct; TCP and UDP on the same tuple stay distinct; remove works.
**Commit:** `replaced the global connection cache with a per-session instance keyed by 5-tuple`

### D5: Ordered async capture writer
**Resolves:** "Blocking DB insert on the outbound packet thread."
**Changes:**
- **Writer:** new `core/vpn/.../components/CaptureWriter.kt`. A single consumer on `Dispatchers.IO` reads an unbounded `Channel<suspend () -> Unit>`. `fun <T> submit(block: suspend () -> T): Deferred<T>`, plus `suspend fun closeAndDrain()`. It logs when the backlog passes a threshold. Ordering matters because foreign keys chain Session → Connection → Request → Response.
- **ID allocation:**
  - `ConnectionDao`: add `@Query("SELECT IFNULL(MAX(id), 0) FROM Connection") suspend fun getMaxId(): Int`.
  - `DatabaseConnector`/`RoomDatabaseConnector`: add `getMaxConnectionId()`, and give `persistTransportLayerConnection` an explicit `id: Int` that is set on the entity.
  - `ComponentManager`: owns `val captureWriter` and `connectionIds = AtomicInteger(getMaxConnectionId())`, seeded in `init` next to the session insert.
- **Connection writes** (`TransportLayerConnection.kt:134-160`): `createDatabaseEntity()` allocates `connectionIds.incrementAndGet()` synchronously and submits the insert. `deleteDatabaseEntity()` submits the delete. Remove `runBlocking`.
- **HTTP writes** (`HttpConnection.kt:~170-200`): request and response inserts go through `captureWriter.submit`. The response awaits the request's `Deferred<Int>`, which replaces `requestIdChannel`.
- **Shutdown** (`ComponentManager.stopComponents`): `captureWriter.closeAndDrain()` before `updateSession`.
- **Fixture:** update `integration/support/RecordingDatabaseConnector.kt`.

**Tests:**
- `CaptureWriterTest`: preserves submission order and drains on close.
- An integration test asserts Connection insert → Request → Response order in `RecordingDatabaseConnector`, and that no DB call runs on the outbound handler thread (record the thread name).
- `core/database` Robolectric: `getMaxId` on empty and non-empty tables.

**Commit:** `moved capture persistence off the packet thread into an ordered writer`

### D6: Byte tracking
**Resolves:** "Byte counters are shown in the UI but never written" (including the `updateBytesOut` SQL bug).
**Changes:**
- **Counting:**
  - `TransportLayerConnection.kt`: `private val pendingOut = AtomicLong()`, `pendingIn = AtomicLong()`, `internal fun addOut(n)`/`addIn(n)`, and `fun drainByteDeltas(): Pair<Long, Long>` (skip when `id <= 0`).
  - `TcpConnection.kt`: `addOut(payload.length())` in `handleAckData` (249) and `addIn(bytesRead)` in `unwrapInboundReadable` (326).
  - `UdpConnection.kt`: the matching send and receive sites.
- **DAO** (`ConnectionDao.kt:24-28`): delete `updateBytesOut`/`updateBytesIn`. Add `@Query("UPDATE Connection SET bytesOut = bytesOut + :bytesOut, bytesIn = bytesIn + :bytesIn WHERE id = :id") suspend fun addBytes(id: Int, bytesOut: Long, bytesIn: Long)`.
- **Connector:** `DatabaseConnector`/`RoomDatabaseConnector` add `addConnectionBytes(deltas: List<ByteDelta>)`, run inside `database.withTransaction`. Update the test fixture.
- **Flushing:**
  - `ComponentManager`: a flush coroutine every 2 s drains `connectionCache.values()` and submits one batch to `captureWriter`. `stopComponents` flushes once more before draining the writer.
  - `TransportLayerConnection.closeHard()` (180): drain and submit its final delta before removal from the cache.

**Tests:**
- `core/database` Robolectric `ConnectionDaoTest.addBytes`: both columns accumulate independently.
- `core:vpn` integration: after data in both directions and a flush, `RecordingDatabaseConnector` holds the expected totals, including for a connection closed between flushes.

**Commit:** `implemented per-connection byte tracking with batched database flushes`

### D7: Poll buffer sized from `maxPacketSize`
**Resolves:** "Buffer-size contract mismatch."
**Changes:** `DevicePollThread.kt` takes a `maxPacketSize` constructor parameter (passed from `ComponentManager.kt:135-140`), and `run()` allocates `ByteArray(maxPacketSize)` (32). Remove the TODO.
**Commit:** `sized the device poll buffer from the configured max packet size`

### D8: DNS cache fixes and dead-code removal
**Resolves:** "DNS cache quirks and a dead duplicate."
**Changes:**
- `metadata/DnsCache.kt:36-41`: an expired entry is removed and returns `null`.
- Delete `core/vpn/.../cache/DnsCache.kt` (no callers).

**Tests:** update `metadata/DnsCacheTest.kt`, whose expired-entry case currently expects the stale hostname, to expect `null`.
**Commit:** `fixed dns cache returning expired hostnames and removed the unused duplicate`

### D9: Remove the MitM singleton and `Authority.generateCertificate`
**Resolves:** "Leftover static MitM singleton."
**Changes:** delete the companion in `CertificateSniffingMitmManager.kt:95-110`, and `generateCertificate`/`getStringFromFile`/`convertStreamToString` in `Authority.kt:61-110`.
**Commit:** `removed the unused mitm manager singleton`

---

## Group E: MitM trust

### E1: Bounded passthrough cache, filled on handshake failure
**Resolves:** "TLS passthrough cache is never populated."
**Changes:**
- **Bounded cache** (`metadata/TlsPassthroughCache.kt`): an access-ordered `LinkedHashMap<TlsPassthroughCacheEntry, Long>` (value = expiry), following `metadata/DnsCache.kt`. `maxSize = 1000`, `ttlMinutes = 30`, behind the existing `ReentrantReadWriteLock`. `get()` treats expired entries as absent.
- **`TlsConnection.kt`:**
  - Add `private fun failHandshake(cause: Throwable?)`. If `state` is `SERVER_HANDSHAKE` or `CLIENT_HANDSHAKE`, call `componentManager.tlsPassthroughCache.put(transportLayer.appId ?: -1, hostname)` and log the side and cause, then `closeConnection()`.
  - Call it from the SSLException handlers in `handleWrap` (~648-656) and `handleUnwrap` (~756-763), the delegated-task catch (410-414), and the `NOT_HANDSHAKING` failure branch (379-382).
  - The lookup at 153 uses the same `appId ?: -1` key.

**Tests:**
- Update `metadata/TlsPassthroughCacheTest.kt`: TTL expiry, size cap, concurrency.
- `integration/TlsMitmHttpFlowTest.kt`: a client that aborts the MitM handshake populates the cache, and the next connection's records reach the app layer unmodified.

**Commit:** `populated and bounded the tls passthrough cache on handshake failures`

### E2: "Trust all upstream servers" preference and validation
**Resolves:** "Upstream certificate validation is disabled in both MitM stacks."
**Changes:**
- **Preference plumbing:**
  - `preferences.proto`: add `bool mitm_trust_all_upstream = 45;`.
  - `PreferencesDataSource.kt`: `mitmTrustAllUpstream` flow and `setMitmTrustAllUpstream`, following `mitmEnable` (32, 141-145).
  - `PreferencesInitialValues.kt`: `mitmTrustAllUpstreamInitial = false`. `PreferencesSerializer.kt`: set the default.
  - `TrafficScannerPreferences.kt`: a `BooleanPreference` under the MitM toggle (~110), with the warning "Intercepted apps can no longer detect invalid server certificates."
- **Wiring:**
  - `HeimdallVpnService.launchServiceComponents` reads the preference and passes `trustAllUpstream` to `ComponentManager` (new constructor parameter, default `false`).
  - `ComponentManager.kt:77` calls `CertificateSniffingMitmManager(authority, trustAllUpstream)`. `CertificateSniffingMitmManager.kt:13-17` takes a `trustAllServers` parameter instead of hardcoding `true`.
- **Hostname verification** (`mitm/SSLEngineSource.kt`):
  - `newSSLEngine(remoteHost, remotePort)` modifies `sslEngine.sslParameters` in place: `endpointIdentificationAlgorithm = "HTTPS"` when `!trustAllServers`, and `serverNames = listOf(SNIHostName(remoteHost))` for non-IP hosts. Assign the parameters back.
  - Delete the `tryHostNameVerificationJava7` reflection (minSdk 24 has the API) and its call in `initialiseSSLContext`.
  - Confirm `TlsConnection.setupServerSSLEngine` passes `sni ?: hostname`.

**Tests** (`integration/TlsMitmHttpFlowTest.kt` with `FakeTlsServer`; switch existing fixtures that rely on its self-signed certificate to `trustAllUpstream = true`):
- trust-all off plus the self-signed upstream: the first connection closes, the cache is populated, and the second passes through
- trust-all on: intercepted
- a hostname mismatch with trust-all off: passthrough

**Commit:** `validated upstream certificates by default with an opt-in trust-all preference`

---

## Group F: Data and scanner

### F1: Retryable tracker signatures (offline scans)
**Resolves:** "Scanning while offline permanently skips tracker detection."
**Changes:**
- **`LibraryScanner.kt`:** add `suspend fun ensureSignatures(): Boolean`, guarded by a `Mutex`. It sets `initialised = true` only when the trie is non-empty. `scanApp` calls it and keeps returning `ScanResult(false, …)`.
- **`ScannerModule.kt`:** `provideLibraryScanner` becomes `@Singleton`.
- **`ScanWorker.kt`:**
  - In `doWork`, when `scanLibraries` is true, call `ensureSignatures()` first and return `Result.retry()` if it fails.
  - `performFullScan`/`scanSinglePackage` upsert the `App` row **after** the requested scans (no FKs on `AppXPermission`/`AppXTracker`).
  - `enqueue` adds `Constraints(requiredNetworkType = NetworkType.CONNECTED)` and exponential backoff when `scanLibraries` is true.
- **`LibraryScannerViewModel.onScan`:** call `ensureSignatures()` first. On failure, show "Tracker signatures unavailable – check your connection" and skip `setLibraryLastUpdated`.

**Tests:** `core/scanner/src/test/.../LibraryScannerTest.kt` (mockk `ExodusUpdater`, Robolectric in-memory DB):
- empty DB plus a failing update → `false`
- a later successful update → `true`, and the trie gets populated

Add test deps to `core/scanner`.
**Commit:** `made tracker signature loading retryable so offline scans are not recorded as done`

### F2: `ExodusUpdater` injection and stable tracker IDs
**Resolves:** "`ExodusUpdater` couples to the concrete database and isn't transactional."
**Changes:**
- **Injection:**
  - `DatabaseModule.kt`: `@Provides fun provideTrackerDao(db: HeimdallDatabase) = db.trackerDao()`.
  - `ScannerModule.kt`: a `@Singleton` `ExodusAPIInterface` provider (Retrofit built once). `provideExodusUpdater(trackerDao, api)`.
  - `ExodusUpdater.kt`: constructor `(TrackerDao, ExodusAPIInterface)`, with no per-call `Retrofit.Builder`.
- **Stable IDs** (`TrackerDao.kt`): convert to an `abstract class` with `@Transaction open suspend fun syncTrackers(incoming: List<Tracker>)`. It reuses the existing `id` by `name`, inserts new trackers, and deletes those no longer present.

**Tests:** `core/database` Robolectric `TrackerDaoTest.syncTrackers`: existing IDs survive, new trackers are added, and removed trackers are deleted.
**Commit:** `injected exodus api and synced trackers transactionally with stable ids`

### F3: CSV export: shared model, columns, escaping
**Resolves:** "`core/export` is orphaned, and its CSV output is malformed" (CSV part), and "Unpaginated full-table queries" (export side).
**Changes:**
- **Shared model:** new `core/export/.../ExportModel.kt` with `ExportRequest` mapped once from `Request`. Add `fun parseStoredHeaders(raw: String): List<Pair<String, String>>`, which parses the `"Name: value\n"` format written by `RoomDatabaseConnector.kt:98,141`.
- **CSV** (`csv/CsvExport.kt`):
  - One `columns` list drives both header and row (fixes the 16-vs-15 mismatch at 18/24).
  - `csvField()` quotes fields containing `,`, `"`, `\r`, or `\n` and doubles quotes (replaces `csvEscape` at 33-38).
  - Writes to a caller-supplied `OutputStream`.
- **Keyset pagination:** `RequestDao`: add `@Query("SELECT * FROM Request WHERE id > :afterId ORDER BY id LIMIT :limit") suspend fun getPageAfter(afterId: Int, limit: Int)`.

**Tests:** `core/export/src/test/.../CsvExportTest.kt`:
- the header column count equals the row value count
- commas, quotes, CR/LF, and empty fields
- header parsing
- pagination across multiple pages (mockk `RequestDao`)

**Commit:** `fixed csv export column alignment and escaping`

### F4: TeX export entry point
**Resolves:** the TeX part of the `core/export` finding and "`core/export` is entity-coupled."
**Changes:**
- `tex/TexExport.kt`: add public `suspend fun exportRequestsToTex(requestDao, responseDao, out: OutputStream)`, streaming a JSON array of `TexRequest` built from `ExportModel`.
- Replace `headersJsonToHeadersList` with `parseStoredHeaders`, and delete `util/ExportUtils.swapJsonQuotes` if nothing else uses it.
- `README.md:76`: describe the format as the TeX JSON format, not LaTeX, and keep it marked as not yet available in the UI.

**Tests:** `TexExportTest`: a request with and without a response produces valid JSON (`Json.parseToJsonElement`) with the expected headers.
**Commit:** `added a public tex export entry point using the shared export model`

### F5: Datastore serializer round-trip test
**Resolves:** part of "Test coverage gaps."
**Changes:** `core/datastore/src/test/.../PreferencesSerializerTest.kt`: `defaultValue` has the expected initial values (including `mitmTrustAllUpstream == false`), `writeTo`/`readFrom` round-trips, and bytes carrying the reserved proxy field numbers parse without error. Add test deps to `core/datastore`.
**Commit:** `added datastore serializer round-trip tests`

---

## Group G: App-layer structure

### G1: Shared `AppScanCoordinator`
**Resolves:** "Duplicated scan logic has already diverged" (wrong preferences, main-thread scan).
**Changes:**
- **New class:** `app/src/main/java/de/tomcory/heimdall/service/AppScanCoordinator.kt`, `@Singleton @Inject(ScannerRepository, PermissionScanner, LibraryScanner)`.
  - `enum class ScanKind { PERMISSIONS, LIBRARIES }`.
  - `suspend fun scanInstalled(kind, isCancelled: () -> Boolean, onProgress: suspend (Float) -> Unit): ScanOutcome` runs `withContext(Dispatchers.IO)` and reads `permission*` or `library*` scope, whitelist, and blacklist per kind.
  - `fun predicate(scope, whitelist, blacklist): (PackageInfo) -> Boolean` uses `isSystemApp`.
  - `suspend fun scanPackage(pkgInfo, kinds: Set<ScanKind>): Boolean`, with App-row upsert ordering per F1.
- **Callers:**
  - `PermissionScannerViewModel.kt`/`LibraryScannerViewModel.kt`: delete `scanAllApps`/`getScanPredicate` and delegate to the coordinator. Remove the duplicated progress math.
  - `ScanWorker.kt`: `scanSinglePackage`/`performFullScan` call `scanPackage` and keep the incremental `isAppChanged` check. Get the coordinator via `ScanWorkerEntryPoint`.

**Tests:** Robolectric `AppScanCoordinatorTest`:
- the predicate for each `MonitoringScopeApps` value
- LIBRARIES reads `libraryMonitoringScope` (fake prefs)
- cancellation stops the loop

**Commit:** `extracted shared app scan coordinator for permission and library scans`

### G2: Split scoring (`ScoreModule`) from Compose cards
**Resolves:** "Scoring domain coupled to the Compose runtime" and "`Evaluator` provider is redundant and unscoped."
**Changes:**
- **Interface:** new `app/.../evaluator/ScoreModule.kt` with `name`, `weight`, `suspend fun calculateOrLoad(app, context, forceRecalculate = false)`, `fun exportToJsonObject(subReport)`, and `fun exportToJson(subReport) = exportToJsonObject(subReport).toString()`. Delete `evaluator/module/Module.kt`.
- **Modules:** `StaticPermissionsScore.kt`, `TrackerScore.kt`, `PrivacyPolicyScore.kt` implement `ScoreModule` with `@Inject` constructors taking only the DAOs they use (add DAO `@Provides` to `DatabaseModule` as needed). Remove their `BuildUICard` and Compose code.
- **UI cards:** new `app/.../ui/evaluator/modulecards/`:
  - `ModuleCardFrame.kt` (the old `UICard`, `Module.kt:93-143`)
  - `StaticPermissionsCard.kt`, `TrackerCard.kt`, `PrivacyPolicyCard.kt` (code moved from each module's `BuildUICard`, using `LocalContext.current` instead of an injected context)
  - `ModuleCardRegistry.kt`: `val moduleCards: Map<String, @Composable (ReportWithSubReports?) -> Unit>` keyed by module `name`, plus a generic fallback
- **Screen:** `AppScoreScreen.kt:169-171` renders `moduleCards[module.name] ?: FallbackCard`.
- **DI:** `Evaluator.kt` becomes `@Singleton class Evaluator @Inject constructor(staticPermissions, trackers, privacyPolicy, database)`, with `modules = listOf(...)`. Delete `AppModule.provideEvaluator` (25-30).

**Tests:** JVM `TrackerScoreTest` with mocked DAOs checks the score for 0 and n trackers. `StaticPermissionsScoreTest` does the same for dangerous-permission counts.
**Commit:** `split scoring modules from their compose ui cards`

### G3: Paged Database screen and SQL analytics
**Resolves:** "Unbounded in-memory connection list with recomputed analytics" and "Unpaginated full-table queries" (UI side).
**Changes:**
- **Catalog:** add `androidx-paging-runtime`, `androidx-paging-compose`, `androidx-room-paging`. `core:database` gets `room-paging`, `app` gets `paging-compose`.
- **`ConnectionDao.kt`:**
  - `@Query("SELECT * FROM Connection WHERE (:trackersOnly = 0 OR isTracker = 1) AND (:protocol IS NULL OR protocol LIKE '%' || :protocol || '%') ORDER BY initialTimestamp DESC") fun pagingSource(trackersOnly: Boolean, protocol: String?): PagingSource<Int, Connection>`
  - `timelineSince(since: Long): Flow<List<BucketCount>>` (`GROUP BY (initialTimestamp - :since) / 60000`)
  - `topApps(limit): Flow<List<KeyCount>>`, `topTrackerHosts(limit): Flow<List<KeyCount>>`
  - Delete `getAll`/`getAllObservable` (30-34) after grep confirms no users.
- **`RequestDao`/`ResponseDao`/`SessionDao`:** delete `getAll*`/`getAllPaginated` where grep shows no users; export uses `getPageAfter` from F3.
- **`DatabaseViewModel.kt`:** `connections: Flow<PagingData<Connection>> = activeFilter.flatMapLatest { Pager(PagingConfig(pageSize = 50)) { dao.pagingSource(…) }.flow }.cachedIn(viewModelScope)`. `analyticsData` combines the three aggregate flows, with the timeline window refreshed each minute.
- **`DatabaseScreen.kt`:** `collectAsLazyPagingItems()`, `items(count, key = itemKey { it.id })`.

**Tests:** `core/database` Robolectric `ConnectionDaoPagingTest` (filter combinations through `PagingSource.load`) and aggregate query tests.
**Commit:** `paged the database screen and computed analytics in sql`

### G4: Bounded live dashboard; `ScoreViewModel` flows and concurrency
**Resolves:** the live-dashboard part of the unbounded-list finding, and "`ScoreViewModel` repeats the load-everything pattern."
**Changes:**
- **Live dashboard:**
  - `ConnectionDao`: `getRecentForSessionObservable(sessionId, limit)` (`ORDER BY initialTimestamp DESC LIMIT :limit`).
  - `TrafficScannerViewModel.kt:86-91`: use it with `limit = 200`. Totals come from the existing count queries (39-46), exposed as flows if the dashboard shows them.
- **`ScoreViewModel.kt`:**
  - `apps`/`deviceStats` add `.flowOn(Dispatchers.Default)` plus `distinctUntilChanged()`.
  - `scoreAllApps()` (174-178) uses `coroutineScope { apps.map { async { semaphore.withPermit { scoreApp(it) } } }.awaitAll() }` with `Semaphore(2)` (Play Store scraping), and exposes `scoreProgress: StateFlow<Float>`.

**Tests:** a Robolectric DAO test for the limit and ordering. A `ScoreViewModel` test with a fake `Evaluator` checks that at most 2 scores run at once.
**Commit:** `bounded the live dashboard query and parallelized scoring with a small limit`

### G5: Remove `MainRepository` and dead scanner dialog state
**Resolves:** "`MainRepository` is an empty scaffold" and "Dead export-dialog state."
**Changes:** delete `ui/main/MainRepository.kt` and its injection at `MainViewModel.kt:19`. Delete `showExportDialogInitial`, `_showExportDialog`/`showExportDialog`, and `onShowExportDialog`/`onDismissExportDialog` from `ScannerViewModel.kt:18,23-24,34-40`.
**Commit:** `removed empty main repository and unused export dialog state`

---

## Group H: Docs

### H1: Update ARCHITECTURE.md, CLAUDE.md, README, issues doc
**Changes:**
- **`docs/ARCHITECTURE.md` and `CLAUDE.md`:**
  - drop `core:proxy`
  - `AppModule` no longer provides the database or `Evaluator`
  - `ScoreModule` plus the card registry replace `Module`/`BuildUICard`
  - schema export and migration policy
  - scan triggers (runtime receiver, reconciliation, `scan-full`/`scan-pkg-*`)
  - `CaptureWriter`, byte tracking, the per-connection lock order
  - the trust-all preference and passthrough behavior
- **`README.md`:** MitM trust setting, export status.
- **`docs/architecture-issues.md`:** mark each finding resolved with its packet ID, or replace it with a short "resolved" note.

**Commit:** `updated architecture docs after resolving the architecture issues`

---

## End-to-end verification (after all packets)

**Automated:** `./gradlew build` plus these module test tasks:
- `:core:vpn:testDebugUnitTest`
- `:core:database:testDebugUnitTest`
- `:core:export:testDebugUnitTest`
- `:core:scanner:testDebugUnitTest`
- `:core:datastore:testDebugUnitTest`
- `:core:util:testDebugUnitTest`
- `:app:testDebugUnitTest`

**Manual, on an API 34+ emulator or device:** `./gradlew installDebug`, then `adb logcat` and Android Studio's Database Inspector.

1. **Capture (B1, D6):** start VPN mode and browse in a non-Chrome browser. The live dashboard fills, and byte counts are non-zero and grow during a download.
2. **Lifecycle (D1):**
   - start then cancel immediately: stopped, notification gone
   - start twice quickly: one running VPN
   - stop from the notification
   - `adb shell run-as de.tomcory.heimdall kill <pid>`: the service restarts without crashing
3. **Scan triggers (B3–B5):**
   - `adb install` a test APK while the app is running: a single-package scan runs
   - `adb uninstall` it: `isInstalled = 0`
   - reboot with library scanning off: no DEX scan
   - install an app during a full scan: the full scan still completes
4. **Offline (F1):** clear data and disable the network, then run a library scan. The UI reports signatures unavailable and the worker retries. Re-enable the network: trackers get populated.
5. **Scopes (B2, G1):** the "non-system apps" scope scans user apps. `isSystem` is correct, and library scope settings take effect.
6. **MitM trust (E1, E2):**
   - trust-all off, `https://expired.badssl.com` in Firefox: the first load fails, and after a reload the browser's own certificate warning appears (passthrough)
   - a valid site: requests are captured
   - trust-all on: the expired site is intercepted
7. **Export (B6):** the share sheet opens from an app's score screen.
8. **Database screen (B7, G3):** rows expand on tap. Scrolling thousands of connections stays smooth, and filters and analytics update.
9. **Proxy removal (C1):** no Proxy mode anywhere, and a clean build has no `core:proxy`.
