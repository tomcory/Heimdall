# Heimdall — Architectural Issues

A point-in-time snapshot from a code audit of the whole codebase (2026-09-15), revised after a line-by-line check against the `ui-rework` working tree. It is not a tracked issue list. Findings are grouped by subsystem and ranked High/Medium/Low. Each entry gives the file and line, the issue, a concrete failure scenario, and a one-line fix direction. It points at where to look; it doesn't prescribe full fixes. See [`ARCHITECTURE.md`](ARCHITECTURE.md) for how these subsystems are supposed to fit together.

## Start here: live correctness bugs

Most findings below are design risks with a plausible future failure. These ones are already broken on the current branch and are reachable through normal use:

- **The live traffic dashboard watches the wrong session** (Network interception, High): it stays empty for the whole capture.
- **App install/uninstall scans never run** (App layer, High): the receiver isn't registered for package broadcasts.
- **VPN service lifecycle bugs** (Network interception, High): the service crashes on a sticky restart, a duplicate START tears down a running VPN, and a STOP during startup is ignored.
- **`ScanWorker` enqueueing** (App layer, High): full scans ignore the user's scan preferences, and any new scan request cancels a scan already running.
- **Scanning while offline permanently skips tracker detection** (Data & support modules, High).
- **System-app detection is broken in both scanner ViewModels** (App layer, High): nearly every app is stored as a system app.
- **Byte counters are shown but never written** (Data & support modules, High): every connection shows 0 B.
- **Exporting a score report crashes** on API 28+ (App layer, High).
- **`MITM_PROXY` mode never routes traffic through the proxy** (Network interception, Medium).
- **Unsynchronized TCP connection state** (Network interception, High): a genuine data race on every bidirectional TCP connection.

---

## Network interception (`core/vpn`, `core/proxy`, `HeimdallVpnService`, `TrafficScannerViewModel`)

### High

**Unsynchronized TCP connection state shared across threads**
`core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/connection/transportLayer/TcpConnection.kt:51-52`, `TransportLayerConnection.kt:102`
`theirSeqNum`/`ourSeqNum` (and the inherited `state`) are plain `var`s with no `synchronized`, `@Volatile`, or atomic wrapper. Two threads use them:
- `unwrapOutbound()` runs on the `OutboundTrafficHandler` `HandlerThread`. It advances `theirSeqNum`, reads `ourSeqNum` when building ACKs, and changes `state`.
- `unwrapInbound()` and the `wrapInbound()` calls it triggers run on the `InboundTrafficHandler` selector thread. They advance `ourSeqNum`, read `theirSeqNum`, and change `state`.

Any bidirectional TCP session, which is the normal case, therefore reads and writes these fields from both threads at once. The race can corrupt ACK/SEQ tracking or state transitions, producing dropped segments or spurious resets that depend on thread timing and are hard to reproduce. Fix direction: confine each connection's mutation to one thread through message-passing, or make the counters and state atomic.

**VPN service start/stop lifecycle is unsafe**
`app/src/main/java/de/tomcory/heimdall/service/HeimdallVpnService.kt:80, 93-99, 108-110, 228-231, 256, 269, 447, 461-462`
- **Crash on sticky restart:** `onStartCommand(intent: Intent, …)` declares the intent non-null but returns `START_STICKY`. When the system restarts the service after killing the process, it passes a null intent, and Kotlin's parameter null check throws.
- **A duplicate START tears down a running VPN:** if the interface already exists, `establishInterface` returns `false` (line 269) and `launchServiceComponents` calls `stopSelf()` (line 230). `onDestroy` then runs `shutDown()`. The trigger can be a boot-time start racing a user start, or a start from the notification or another entry point.
- **A STOP during startup is ignored:** `shutDown()` does nothing unless `componentsActive` is true, and that flag is only set after the `ComponentManager` exists (line 256). A STOP that arrives mid-startup does nothing, so the VPN comes up anyway while `TrafficScannerViewModel.stopProxyAndVpn` has already marked it inactive.
- **Concurrent starts orphan a pipeline:** each START launches its own coroutine, and `vpnInterface`/`componentsActive` are unsynchronized. Two starts can both pass the null check before either reaches `builder.establish()` (line 447). The second `establish()` replaces the interface, and `componentManager` is overwritten, so the first pipeline (four threads plus a session row) leaks and is never stopped.

Fix direction: accept `Intent?`, serialize start and stop through a `Mutex` or a single state machine (idle → starting → running → stopping), and treat START while running as a no-op rather than a failure.

**Live traffic dashboard observes a session the VPN never writes to**
`app/src/main/java/de/tomcory/heimdall/ui/scanner/traffic/TrafficScannerViewModel.kt:189-191, 207-212`; `HeimdallVpnService.kt:81`; `core/vpn/.../components/ComponentManager.kt:105-109`
`startVpnStack` inserts its own `Session` and points `liveConnections` at it. But `launchVpn` never passes the `de.tomcory.heimdall.core.vpn.SESSION_ID` extra, so the service gets `-1` and `ComponentManager` creates a second session. All captured connections go into that second session. `LiveDashboard` (`ScannerScreen.kt:76`) therefore stays empty for the whole capture. In proxy mode `launchProxy` adds a third session (line 232). The post-capture stats look correct only because `getLatestSession()` happens to pick the VPN's session. Fix direction: create the session in exactly one place and pass its ID to the service, or have the service publish the ID it created.

**Global static `ConnectionCache` with a collision-prone key**
`core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/cache/ConnectionCache.kt:13-14, 78-85`; `TransportLayerConnection.kt:216-218`
`ConnectionCache` is a process-wide singleton (`companion object { private val cache = ConnectionCache() }`) rather than an instance owned by a `ComponentManager`. Its key is `remoteAddress.hashCode() xor (protocol shl 16) xor (localPort shl 8) xor remotePort`:
- `Inet4Address.hashCode()` is the raw address, so all 32 bits overlap the port and protocol terms.
- `localPort shl 8` (bits 8-23) overlaps both `remotePort` (bits 0-15) and `protocol shl 16` (bits 16-23).

Example: `1.2.3.4:443` from local port 40000 and `1.2.4.4:443` from local port 40007 produce the same key. When that happens, `getInstance` finds the *existing* connection for the new flow's first packet and returns it, so the new flow is never created and its packets go to the wrong connection object. (The "Flow overwritten" branch in `addConnection` is practically unreachable, because lookup and insert use the same key.) Fix direction: key the map on a 5-tuple data class, and make the cache an instance owned by `ComponentManager`.

### Medium

**`MITM_PROXY` mode never routes traffic through the proxy**
`TrafficScannerViewModel.kt:162, 184-187`; `HeimdallVpnService.kt:218-225`
Selecting `MITM_PROXY` sets both `vpnUseProxy = true` and `mitmEnable = true`. The service then logs "Proxy cannot be used in MitM mode, disabling proxy" and never calls `setHttpProxy`. The ViewModel still starts a `HeimdallHttpProxyServer`, but no traffic reaches it, so the mode behaves like `MITM_VPN` with an idle proxy. Fix direction: decide which combination the mode means, and make the ViewModel and service agree on it. That also settles whether the proxy stack is needed at all (next finding).

**Duplicated MitM/TLS stacks in two modules**
`core/vpn/mitm/{CertificateSniffingMitmManager,CertificateHelper,MergeTrustManager,SubjectAlternativeNameHolder,Authority}.kt` and `SSLEngineSource.kt` are Kotlin ports of `core/proxy/littleshoot/mitm/{same names}.java` and `BouncyCastleSslEngineSource.java`, the original LittleProxy-mitm sources. Both are instantiated at runtime: `ComponentManager.kt:77` builds the `core/vpn` manager, and `TrafficScannerViewModel.kt:214-231` builds the `core/proxy` manager and server. Any TLS-handling fix (trust handling, hostname verification, cipher selection) has to be made twice, and nothing enforces that both copies stay in sync. Because of the previous finding, the proxy copy currently handles no traffic at all. Fix direction: consolidate on one MitM implementation, or extract a shared certificate/TLS library that both modules depend on.

**Upstream certificate validation is disabled in both MitM stacks**
`core/vpn/.../mitm/CertificateSniffingMitmManager.kt:17` → `SSLEngineSource.kt:139-143`; `core/proxy/.../mitm/CertificateSniffingMitmManager.java:32`
Both managers hardcode `trustAllServers = true`, which selects Netty's `InsecureTrustManagerFactory` for the upstream connection. When MitM is on, a server presenting an expired, self-signed, or attacker-issued certificate is silently re-signed with Heimdall's trusted CA. The intercepted app can no longer detect the problem, so an on-path attacker's certificate is effectively laundered through Heimdall. The `MergeTrustManager` path already exists but can't be reached. Fix direction: validate upstream certificates by default (`MergeTrustManager`), and on failure either pass through without MitM or fail the client handshake. Make any "trust all" setting an explicit, visible option.

**Blocking DB insert on the outbound packet thread**
`core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/connection/transportLayer/TransportLayerConnection.kt:134-160`
`createDatabaseEntity()`/`deleteDatabaseEntity()` wrap Room writes in `runBlocking`. They're called from the `TcpConnection`/`UdpConnection` constructors, which `getInstance()` runs on the single `OutboundTrafficHandler` `HandlerThread` that handles *all* outbound packets. Every new non-DNS connection therefore blocks that thread on disk I/O, stalling packet processing for every other connection until the write completes. Fix direction: persist asynchronously (a queued writer or a fire-and-forget coroutine), and resolve the row ID lazily wherever a caller actually needs it.

**TLS passthrough cache is never populated**
`core/vpn/src/main/java/de/tomcory/heimdall/core/vpn/metadata/TlsPassthroughCache.kt:18`; `TlsConnection.kt:153`
`TlsConnection` checks `tlsPassthroughCache.get(...)` before deciding to intercept, but nothing in main code ever calls `put()`. The cache is always empty. The fallback it was built for, remembering (app, host) pairs where interception failed so later connections pass through, doesn't work: an app with certificate pinning fails the MitM handshake on every connection. Fix direction: call `put()` when a client-side MitM handshake fails, and then bound the cache (the size-capped, TTL-evicting `DnsCache` pattern is a good model).

**TCP sequence number over-advanced when splitting large inbound payloads**
`TcpConnection.kt:226-238`
In the split branch of `wrapInbound`, each segment calls `increaseOurSeqNum(payload.size)` instead of `temp.size`. For a payload that splits into *n* segments, every segment after the first carries a sequence number that is too high by the full payload size, so the client sees gaps, stalls, and eventually resets. Any inbound payload larger than `maxPacketSize` takes this branch. Fix direction: advance by `temp.size`, and add a unit test for the split path.

### Low

**Buffer-size contract mismatch**
`core/vpn/components/DevicePollThread.kt:32` hardcodes `ByteArray(1500)` (with its own `// TODO: actually implement a reusable buffer`), while `ComponentManager.maxPacketSize` defaults to 16413 and sizes the transport-layer buffers (`TransportLayerConnection.kt:66,72`). The service never calls `setMtu`. If the TUN MTU is ever raised, packets over 1500 bytes are truncated on read and then dropped by `parsePacket`'s length-mismatch check. Fix direction: size the poll buffer from `maxPacketSize` or the configured MTU.

**Leftover static MitM singleton**
`core/vpn/mitm/CertificateSniffingMitmManager.kt:95-110` keeps a `@Volatile` singleton with a TODO admitting the pattern is wrong. `ComponentManager` constructs its own instance (`ComponentManager.kt:77`). The only caller of `createSingleton` is `Authority.generateCertificate()` (`Authority.kt:82`), and the only caller of *that* is `app/src/test/.../DirectHttpTest.kt`, which no longer compiles (see Test coverage gaps). `core/proxy/ProxyUtils.java:23` has its own `generateCertificate`. Fix direction: delete the singleton and `Authority.generateCertificate`, and keep passing the instance through constructors.

**DNS cache quirks and a dead duplicate**
- `core/vpn/.../metadata/DnsCache.kt:36-41`: `get()` on an expired entry removes it but still returns its hostname, so a connection can be labeled with a stale hostname once.
- `removeEldestEntry` only evicts expired entries when a new one is inserted.
- `core/vpn/.../cache/DnsCache.kt` is a second, global-singleton `DnsCache` with no callers.

Fix direction: return `null` for expired entries, and delete the unused `cache/DnsCache.kt`.

---

## App layer (`app/` UI, ViewModels, DI, Evaluator, services)

### High

**Package install/uninstall handlers are unreachable**
`app/src/main/AndroidManifest.xml:60-66`; `app/src/main/java/de/tomcory/heimdall/service/HeimdallBroadcastReceiver.kt:33-34, 67-88`
The receiver's intent filter lists only `BOOT_COMPLETED` and `QUICKBOOT_POWERON`, and nothing registers it at runtime. `ACTION_PACKAGE_ADDED` and `ACTION_PACKAGE_REMOVED` are never delivered. As a result, newly installed apps are never scanned automatically and uninstalled apps are never marked `isInstalled = false`. This contradicts CLAUDE.md and ARCHITECTURE.md, which say scans are triggered on install and remove. `QUICKBOOT_POWERON` also falls through to the `else` branch, so it runs no boot scan. Fix direction: register for package broadcasts at runtime (manifest-declared receivers no longer get these implicit broadcasts on API 26+), or reconcile installed packages in `ScanWorker` on each run. Handle `QUICKBOOT_POWERON` like `BOOT_COMPLETED`.

**`ScanWorker` enqueueing ignores preferences and cancels in-flight scans**
`app/src/main/java/de/tomcory/heimdall/service/ScanWorker.kt:64-65, 203-221`
- **Preferences ignored on full scans:** `enqueue` only sets input data when `packageName` is non-empty. A full scan (`packageName = ""`, as on boot) has no input data, so `doWork` falls back to `scanLibraries = true, scanPermissions = true`. A user who turned off library scanning still gets the costly DEX scan on every boot.
- **In-flight scans cancelled:** every request, full or single-package, uses the same unique work name `"initial-scan"` with `ExistingWorkPolicy.REPLACE`. Any new request cancels a full scan in progress, and two quick single-package requests cancel each other.

Fix direction: always pass input data, and use a distinct unique name per package (or `APPEND_OR_REPLACE` for single-package work) so full scans aren't cancelled.

**System-app detection broken in both scanner ViewModels**
`ui/scanner/permission/PermissionScannerViewModel.kt:130, 162, 175`; `ui/scanner/library/LibraryScannerViewModel.kt:135, 166, 179`
`(applicationInfo?.flags ?: (0 and ApplicationInfo.FLAG_SYSTEM))` applies the mask to the `0` fallback instead of to `flags`, so the system bit is never isolated:
- `isSystem` becomes `flags != 0`, which is true for virtually every app.
- The `APPS_NON_SYSTEM` and `APPS_NON_SYSTEM_BLACKLIST` scopes only match apps whose flags are all zero, which is almost none.

`ScanWorker.kt:113, 166` computes the flag correctly, so the stored `App.isSystem` depends on which scanner wrote last. Fix direction: use `((flags ?: 0) and FLAG_SYSTEM) != 0` from a single shared per-app helper in `core:util`, next to `OsUtils.getSystemApps()` (`OsUtils.kt:20-28`), which already does the check correctly.

**Duplicated scan logic has already diverged**
`ui/scanner/permission/PermissionScannerViewModel.kt:80-178` and `ui/scanner/library/LibraryScannerViewModel.kt:85-182`
`scanAllApps()` and `getScanPredicate()` are near-copies: package enumeration, scope filtering, progress reporting, and cancellation checks. The copies have already drifted:
- **Wrong preferences:** `LibraryScannerViewModel.kt:90-92` reads `permissionMonitoringScope`, `permissionWhitelist`, and `permissionBlacklist` instead of the `library*` preferences that exist in `PreferencesDataSource.kt:45-47`. The library scanner's scope settings have no effect.
- **Different threading:** the library ViewModel scans on `Dispatchers.IO` (line 57). The permission ViewModel runs `scanAllApps` directly in `viewModelScope` (lines 52-55), on the main thread. `getInstalledPackages`, `loadLabel`, and per-app preference writes all happen there, and `PermissionScanner` doesn't switch dispatchers itself.
- **Different `lastUpdated` handling:** one updates it per app, the other once at the end.

The FLAG_SYSTEM bug above exists in both copies. Fix direction: extract a shared scan coordinator that takes the scanner and its preference set as parameters, and run it on `Dispatchers.IO`. `ScanWorker` should use it as well.

**Exporting a score report crashes on API 28+**
`app/src/main/java/de/tomcory/heimdall/ui/evaluator/ScoreViewModel.kt:185-196`, called from `AppScoreScreen.kt:141`
`exportToJson()` calls `startActivity` on the injected `@ApplicationContext` with a chooser intent that lacks `FLAG_ACTIVITY_NEW_TASK`. Starting an activity from a non-Activity context without that flag throws `AndroidRuntimeException` on API 28+. Fix direction: return the JSON (or an event) to the UI and launch the share sheet from the composable's Activity context, or add `FLAG_ACTIVITY_NEW_TASK`.

### Medium

**Scoring domain coupled to the Compose runtime**
`app/src/main/java/de/tomcory/heimdall/evaluator/module/Module.kt:44-46, 82-83, 93-143`
The abstract `Module` class, the contract every scoring axis implements, declares `@Composable abstract fun BuildUICard(...)` and includes a concrete `@Composable UICard` next to `calculateOrLoad()`. Every scoring module (`StaticPermissionsScore`, `TrackerScore`, `PrivacyPolicyScore`) is therefore both a scoring class and a UI component, and `Evaluator`'s doc comment even calls it responsible for "module specific UI elements". Two consequences:
- **Every scoring axis must ship a UI card**, whether or not one is needed.
- **Unit tests are harder than they should be.** Compose alone doesn't block JVM tests of `calculateOrLoad()`, but the concrete `HeimdallDatabase` constructor parameter and the `Context` parameter do.

Fix direction: split `Module` into a pure scoring interface that depends on DAOs, plus a separate UI renderer registry used only by the UI layer.

**Unbounded in-memory connection list with recomputed analytics**
`ui/database/DatabaseViewModel.kt:32-34, 47-55, 59-90`
`allConnections` loads *every* `Connection` row through `getAllObservable()` with no paging. Each time the table is invalidated (every new connection during a live capture), Room re-queries the whole table, `filteredConnections` re-filters it, and `analyticsData` re-runs `groupBy`/`sortedByDescending` over it. Over a long capture the table reaches tens of thousands of rows, so each insert costs a full reload plus an O(n log n) recompute, risking UI jank and eventually running out of memory. `TrafficScannerViewModel.liveConnections` has the same pattern per session. Fix direction: back the list with Paging 3 and compute analytics with SQL aggregates.

**`ScoreViewModel` repeats the load-everything pattern**
`ui/evaluator/ScoreViewModel.kt:56-111, 174-178`
`apps` and `deviceStats` reduce the entire `AppWithReportsAndSubReports` list on every emission. `scoreAllApps()` scores apps strictly one after another, and since `PrivacyPolicyScore` scrapes the Play Store, a full rescore is slow and network-bound. Fix direction: compute device stats with SQL aggregates. If scoring is parallelized, keep the concurrency small so the Play Store scraper isn't throttled.

**`HeimdallBroadcastReceiver` uses an unmanaged CoroutineScope**
`app/src/main/java/de/tomcory/heimdall/service/HeimdallBroadcastReceiver.kt:43`
`actionBootCompleted` launches `CoroutineScope(Dispatchers.IO)` work (DataStore reads, `ScanWorker.enqueue`, the VPN service start) and returns from `onReceive` without calling `goAsync()`. Once `onReceive` returns, Android may consider the process idle and kill it. Right after boot, with many receivers competing, that can happen before the coroutine enqueues the scan or starts the VPN, silently dropping both. The same pattern appears at lines 68 and 85, but those handlers are currently unreachable (see above). Fix direction: call `goAsync()` and `finish()` the `PendingResult` when the coroutine completes.

### Low

**`ScanWorker` scans apps sequentially**
`app/src/main/java/de/tomcory/heimdall/service/ScanWorker.kt:133-186`
`performFullScan` awaits each app's permission and DEX scan before starting the next. On first run, with hundreds of apps, this can approach WorkManager's roughly 10-minute execution window. The impact is limited because the scan is incremental (only new or changed apps are scanned, lines 152-155) and WorkManager reschedules stopped work, so an interrupted scan resumes instead of being lost. Fix direction: if first-run time becomes a problem, add small bounded concurrency. DEX parsing is memory-heavy, so keep it to about 2-3 workers.

**Connection rows probably don't expand on tap**
`ui/database/DatabaseScreen.kt:101`; `DatabaseViewModel.kt:94-101`
The composable calls `viewModel.isExpanded(conn.id)`, which reads `_expandedConnectionId.value` directly rather than collecting it as Compose state. `expandConnection()` updates the flow, but nothing tells Compose to recompose, so the row only reflects the change on the next unrelated recomposition (for example, when a new connection arrives). Fix direction: expose `expandedConnectionId` as a `StateFlow` and `collectAsState()` it in the screen.

**Dead export-dialog state**
`ui/scanner/ScannerViewModel.kt:18, 23-24, 34-40`
`showExportDialog`, `onShowExportDialog`, and `onDismissExportDialog` have no references outside the ViewModel; `ScannerScreen.kt` only uses the preferences dialog state. Fix direction: remove them until an export UI ships (see `core/export` below for why that module isn't ready to wire up).

**`Evaluator` provider is redundant and unscoped**
`app/src/main/java/de/tomcory/heimdall/application/AppModule.kt:25-30`
`provideEvaluator` has no `@Singleton`, which contradicts `docs/ARCHITECTURE.md`, and it duplicates `Evaluator`'s own `@Inject constructor`. Each `ScoreViewModel` gets a fresh `Evaluator` and three `Module` instances. The cost is small, but the documented contract doesn't hold. ARCHITECTURE.md also says `AppModule` provides the database; it's actually `core/database/.../DatabaseModule.kt`. Fix direction: delete the provider and annotate the class `@Singleton`, then correct ARCHITECTURE.md.

**`MainRepository` is an empty scaffold**
`ui/main/MainRepository.kt:8-11`
It has a public `preferences` property, a private `database`, and no methods. It's injected into `MainViewModel.kt:19`, which never uses it. Fix direction: remove it or give it real responsibilities before the branch merges.

---

## Data & support modules (`core/database`, `core/datastore(-proto)`, `core/scanner`, `core/export`)

### High

**Byte counters are shown in the UI but never written**
`core/database/.../dao/ConnectionDao.kt:24-28`; `core/database/.../entity/Connection.kt:34-35`; `app/.../ui/database/DatabaseScreen.kt:225, 275-276`; `app/.../ui/scanner/ScannerDashboard.kt:326`
No code anywhere calls `updateBytesIn` or `updateBytesOut`, and `core/vpn` never records transferred bytes. Every connection keeps its default `0`, and both the Database screen and the live dashboard display "0 B" for all traffic. `updateBytesOut` also has a latent SQL bug, `SET bytesOut = bytesIn + :delta`, which will overwrite the outbound counter with an inbound-derived value as soon as it gets a caller. Fix direction: fix the query to `bytesOut + :delta`, add a DAO test, and have the transport layer report byte deltas in batches (not one DB write per packet). Until then, hide the byte columns.

**Scanning while offline permanently skips tracker detection**
`core/scanner/.../LibraryScanner.kt:27-34, 85-109`; `app/.../service/ScanWorker.kt:152-181`; `app/.../ui/scanner/library/LibraryScannerViewModel.kt:61-63, 140-144`
On first use, `LibraryScanner.init()` fetches tracker signatures from the Exodus API. If that request fails (no network, or the API is down), the trie stays empty and every `scanApp` returns `ScanResult(false, "Tracker signatures not initialised.")`. No caller checks the result:
- `LibraryScannerViewModel` reports "Scan completed." and updates `libraryLastUpdated`.
- `ScanWorker` has already saved each app with its current version before scanning (lines 160-169). Later full scans consider those apps unchanged (lines 152-155) and never rescan them.

The affected apps show no trackers until they happen to update. Fix direction: return failure when signatures are missing, and have callers check it. In `ScanWorker`, only record an app as scanned after a successful scan, and return `Result.retry()` when the signatures couldn't be loaded.

**Silent destructive-migration fallback with no migrations**
`core/database/src/main/java/de/tomcory/heimdall/core/database/DatabaseModule.kt:22` calls `.fallbackToDestructiveMigration()`. No `Migration` object exists anywhere in the module, and `HeimdallDatabase.kt:42` sets `exportSchema = false`. This isn't live yet, since this branch changes no entities and the version stays 6. But the next version bump will silently drop every table: all captured sessions, connections, requests, and responses, plus scan and score history. For a data-capture tool, that's the most damaging latent failure in the codebase. Fix direction: enable `exportSchema` and check the schema JSON in, then write real `Migration`s (or `AutoMigration`s) with a `MigrationTestHelper` test before the next schema change.

### Medium

**`core/export` is orphaned, and its CSV output is malformed**
`app/build.gradle.kts:166` declares `implementation(project(":core:export"))`, but nothing under `app/src` imports `de.tomcory.heimdall.core.export`. The README claims export tooling for "CSV, LaTeX" exists at the data layer. In reality:
- **Misaligned columns:** `exportRequestsToCSV` writes a 16-column header that includes `reqResId` (`CsvExport.kt:18`), but each row has only 15 values (line 24). Every column from `headers` onward sits under the wrong header.
- **No escaping:** free-form `headers` and `content` from captured HTTP traffic are written unescaped. `csvEscape()` (lines 33-38) is never called, and it wouldn't be enough anyway: it only quotes values containing commas, not quotes or newlines.
- **TeX export has no entry point:** `TexExport.kt` has only private mapping functions plus `headersJsonToHeadersList`, so nothing can export. The format is a JSON schema (`TexData.kt`), not LaTeX.

`core/export/src/test` and `src/androidTest` are empty, so nothing caught these. Fix direction: fix the column list, use an RFC 4180-compliant escaper (or a CSV library), add a public TeX export function, and cover both with tests before wiring export into the UI.

**Test coverage gaps**
- **Scanner and datastore:** `core/scanner` and `core/datastore` have no test source sets at all.
- **Database and export:** `core/database` and `core/export` have `src/test`/`src/androidTest` directories, but they're empty.
- **Util and proxy:** `core/util` and `core/proxy` have no tests.
- **App:** `app/src/test/java/de/tomcory/heimdall/DirectHttpTest.kt:3` imports `de.tomcory.heimdall.vpn.mitm.Authority`, a package that no longer exists, so the app's unit-test source set doesn't compile.

Only `core/vpn` has a working suite. There is no Room DAO or migration test, no scanner test, and no DataStore round-trip test, which is how the `updateBytesOut` SQL bug and the CSV column mismatch went unnoticed. Fix direction: delete or repair the stale app tests, then start with an in-memory Room test for `ConnectionDao` and a `MigrationTestHelper` setup.

### Low

**`ExodusUpdater` couples to the concrete database and isn't transactional**
`core/scanner/src/main/java/de/tomcory/heimdall/core/scanner/ExodusUpdater.kt:13-65`
- **Hard to test:** it takes the whole `HeimdallDatabase` although it only needs `TrackerDao`, so tests have to build the full database.
- **Client rebuilt per call:** it builds a new Retrofit client on every call. That costs little today, because `LibraryScanner.init()` only calls `updateAll()` when the tracker table is empty.
- **Latent orphaning:** `deleteAllTrackers()` followed by `insertTrackers()` isn't wrapped in a transaction, and `Tracker.id` is auto-generated. If this is ever used for a periodic refresh of a non-empty table, tracker IDs are reassigned and existing `AppXTracker` rows (which have no foreign key) point to the wrong trackers or to none.

Fix direction: inject `TrackerDao` and a shared API instance through Hilt, upsert trackers by a stable natural key, and run the update inside `withTransaction`.

**Unpaginated full-table queries**
`ConnectionDao.kt:30-34` (`getAll`, `getAllObservable`) and `RequestDao.kt:23, 29` (`getAll`, `getAllObservable`) load entire tables with no limit. The Database screen uses `ConnectionDao.getAllObservable()` directly (see the App layer finding). `getAllPaginated` exists on `RequestDao`, `ResponseDao`, and `SessionDao`, but only the orphaned CSV exporter uses one, and its `LIMIT/OFFSET` paging slows down on large tables. Fix direction: use Paging 3 `PagingSource` queries for live screens and keyset pagination for export.

**Stray data file in the DAO package**
`core/database/src/main/java/de/tomcory/heimdall/core/database/dao/ggg.txt` is an untracked file of numeric pairs sitting in the source tree. Fix direction: delete it or move it out of `src/main`.

**Module dependency direction is clean**
This is the one area where the audit found no problem. `settings.gradle.kts` and each module's `build.gradle.kts` form a one-way graph:
- `core:scanner` → `database` + `datastore` + `util`
- `core:export` → `database`
- `core:vpn` and `core:proxy` → `database` + `util`
- `core:datastore` → `datastore-proto`
- nothing depends on `app`

`core/scanner/LibraryScanner.kt` imports only core modules, the Android framework, and apk-parser; it has no app or UI imports. The real risks in this subsystem are live data bugs, orphaned code, and missing migrations, not dependency direction.

---

## If you fix one thing per subsystem

1. **Network interception**: make `HeimdallVpnService` start/stop a single serialized state machine that accepts a null intent. That fixes the sticky-restart crash, the duplicate-START teardown, the ignored STOP, and the orphaned pipeline together. While you're in there, pass the session ID to the service; that one-line change fixes the empty live dashboard.
2. **App layer**: fix the background scan triggers. Register for package broadcasts at runtime, always pass input data to `ScanWorker`, and stop sharing one `REPLACE`d work name. As it stands, automatic scanning only happens at boot, ignores user preferences, and can be cancelled by any other scan request.
3. **Data & support modules**: make `LibraryScanner` failures visible and retryable so an offline first scan doesn't permanently hide trackers. Then add schema export and real migrations before anyone bumps the database version.
