# Heimdall — Architecture Overview

This is the deep, human-facing reference for Heimdall's architecture. It complements [`CLAUDE.md`](../CLAUDE.md) (the terse, agent-instruction file at the repo root) rather than duplicating it — read this for the "why" and the detail; read `CLAUDE.md` for the quick-reference version an agent needs to start working.

Heimdall is an on-device Android privacy-analysis toolkit. It lets researchers and developers inspect what installed apps actually do at runtime: which permissions they request, which tracking SDKs they embed, and what network traffic they send — including decrypted HTTPS when a MitM certificate is trusted. No data leaves the device.

---

## Table of Contents

1. [What the App Does](#1-what-the-app-does)
2. [Module Structure](#2-module-structure)
3. [Architecture](#3-architecture)
4. [UI Screens](#4-ui-screens)
5. [VPN / Traffic Inspection Pipeline](#5-vpn--traffic-inspection-pipeline)
6. [Evaluator & Scoring Modules](#6-evaluator--scoring-modules)
7. [Background Services & Workers](#7-background-services--workers)
8. [Database Schema](#8-database-schema)
9. [Key Dependencies](#9-key-dependencies)
10. [External Integrations](#10-external-integrations)

**Known issues**: see [`records/architecture-issues.md`](records/architecture-issues.md) for a severity-ranked audit of coupling, concurrency, testability, and scalability problems found in the current implementation.

---

## 1. What the App Does

| Feature | Description |
|---|---|
| **Permission analysis** | Scans installed apps for declared permissions; classifies each as dangerous, signature, or normal |
| **Tracker/library detection** | Scans APK DEX bytecode for known tracking SDK class signatures (Exodus Privacy database) |
| **Network traffic capture** | Runs a local VPN that intercepts all device traffic; logs connections, bytes, remote hosts |
| **HTTPS decryption (MitM)** | With Heimdall's generated CA trusted (in practice: in the system store of a rooted device), decrypts TLS to log HTTP/1.1 requests/responses |
| **Privacy scoring** | Computes a per-app score (0–1) from permissions, trackers, and privacy-policy analysis |
| **Data export** | CSV and LaTeX export logic exists at the data layer (`core/export`); not yet wired into the UI |

**Min SDK**: 24 (Android 7) · **Target/Compile SDK**: 36 · **Language**: Kotlin

---

## 2. Module Structure

```
Heimdall/
├── app/                    Main application — UI, navigation, DI wiring, services
└── core/
    ├── database/           Room database: entities, DAOs, migrations
    ├── scanner/             PermissionScanner, LibraryScanner, Exodus API client
    ├── vpn/                VPN service components, packet pipeline, MitM engine
    ├── util/               Trie, AppFinder, file/network utilities
    ├── export/             CSV, TeX export logic
    ├── datastore/          DataStore preferences (type-safe wrappers)
    └── datastore-proto/    Protocol Buffer schema for preferences
```

Each `core:*` module is a pure Android library; only `app` depends on all of them.

---

## 3. Architecture

**Pattern**: MVVM with Repository, Hilt DI, reactive Flows

- **ViewModels** (`ScannerViewModel`, `ScoreViewModel`, `DatabaseViewModel`, …) own UI state as `StateFlow`/`Flow` and expose it to Compose screens.
- **Repositories** (`ScannerRepository`, `MainRepository`) abstract data sources — Room DAOs, DataStore, and scanner results.
- **Hilt** (`@HiltAndroidApp` on `HeimdallApplication`) wires everything together at compile time; `AppModule` provides singletons for the database, `ScannerRepository`, and `Evaluator`.
- **WorkManager** (`ScanWorker`) handles background scans as `CoroutineWorker`.
- **Plugin-style modules**: The `Evaluator` class iterates over `Module` implementations to calculate scores; adding a new scoring axis is a matter of implementing the abstract `Module` class.

---

## 4. UI Screens

Navigation uses a bottom bar with three destinations (`ui/nav/Navigation.kt`):

### Scanner (route: `traffic`)
Entry point for all scanning. Contains three cards:

- **PermissionScannerCard** — trigger a permission manifest scan; shows last-updated time
- **LibraryScannerCard** — trigger DEX tracker scan; shows last-updated time
- **TrafficScannerCard** — start/stop VPN capture; shows VPN mode and session timer

Top-bar menu opens the **PreferencesScreen** (`ui/settings/PreferencesScreen.kt`; VPN routing, MitM config, monitoring scope, boot options). `ScannerViewModel` also carries `showExportDialog` state, but no export dialog is currently rendered in `ScannerScreen.kt` — the export UI is scaffolded, not wired.

### Score (route: `score`)
- List of all evaluated apps sorted by privacy score, with a visual indicator.
- Tap an app → **AppScoreScreen**: expandable cards rendered by each `Module` (donut chart for permissions, tracker list, policy analysis summary).

### Database (route: `database`)
- Live viewer for captured **Connections**, **Requests**, and **Responses**, with an analytics summary and a filter bar (by app, hostname, protocol).
- Per-row detail view. No export UI exists here yet — see [Data export](#1-what-the-app-does) above.

### Cold start
No longer a custom Compose splash screen — `MainActivity` uses the AndroidX `SplashScreen` API (`installSplashScreen()`), kept on screen via `viewModel.showSplashScreen` until the initial scan completes.

---

## 5. VPN / Traffic Inspection Pipeline

```
Device apps
    │ (TUN interface, MTU 1500)
    ▼
DevicePollThread          reads raw IP packets from the VPN fd, reassembles IPv4 fragments
    │
    ▼
OutboundTrafficHandler    finds or creates the connection a packet belongs to
    │
    ▼
┌─ per connection ──────────────────────────────────────────────────────────┐
│ Transport layer     TcpConnection (transparent TCP proxy) / UdpConnection │
│ Encryption layer    TlsConnection / QuicConnection / PlaintextConnection  │
│ Application layer   HttpConnection / DnsConnection / DnsStreamConnection  │
│                     / RawConnection                                       │
└───────────────────────────────────────────────────────────────────────────┘
    │ protected sockets                         │ RoomDatabaseConnector
    ▼                                           ▼
Remote hosts                               Session, Connection, Request, Response
    │
    ▼
InboundTrafficHandler     NIO selector loop over the outward-facing sockets
    │                     (data travels up and down the same connection stack)
    ▼
DeviceWriteThread         writes rebuilt IP packets back to the TUN fd
    │
    ▼
Device apps
```

Heimdall terminates every TCP connection locally and opens its own socket to the real server, so
it is a proxy rather than a packet forwarder. What happens above the transport layer depends on
the first payload of a flow:

- **TLS over TCP.** The ClientHello is parsed for SNI, ALPN and ECH, which are stored on the
  connection. With MitM on, the connection is decrypted unless it is outside the MitM monitoring
  scope, the client's ALPN excludes `http/1.1`, or a passthrough has been learned for the app and
  host. Decryption uses two TLS sessions: Heimdall first completes its own handshake with the
  server, then answers the app with a leaf certificate forged from the real certificate's names and
  signed by Heimdall's CA. HTTP/1.1 messages between the two are recorded.
- **Passthrough learning.** If an app rejects the forged certificate (handshake error, close during
  the handshake, or repeated closes without data right after it), or Heimdall's own handshake with
  the server fails, later connections of that app to that host are forwarded undecrypted for the
  rest of the VPN session. `Connection.passthroughReason` records why.
- **QUIC over UDP.** Never decrypted. The client's Initial packets are decrypted passively to
  record SNI and ALPN. With the QUIC policy set to *Block* (and MitM on), HTTP/3 flows that the TLS
  MitM would intercept are dropped and answered with ICMP port unreachable, so the app falls back
  to TLS over TCP. The default is *Passthrough*.
- **DNS.** Answers over UDP, TCP and decrypted DNS over TLS fill an IP → hostname cache that names
  later connections. DNS over TLS to the VPN's own DNS server is refused unless Private DNS is in
  strict mode, so the resolver falls back to plain DNS.
- **Everything else** is forwarded unchanged and recorded as connection metadata.

**Key classes:**

| Class | Location | Role |
|---|---|---|
| `HeimdallVpnService` | `app/service/` | Android `VpnService`; resolves preferences, establishes the TUN interface, starts/stops the pipeline. `VpnServiceLifecycle` serialises its start and stop requests |
| `ComponentManager` | `core:vpn/components/` | Owns the four threads, the selector, the caches, the tracker trie and the MitM manager for one VPN session |
| `DevicePollThread` / `DeviceWriteThread` | `core:vpn/components/` | Read from and write to the TUN fd |
| `OutboundTrafficHandler` / `InboundTrafficHandler` | `core:vpn/components/` | Handle packets from the device / run the NIO selector for the sockets |
| `TcpConnection` / `UdpConnection` | `core:vpn/connection/transportLayer/` | TCP proxy with ordering, flow control and half-close handling; datagram relay |
| `TlsConnection` | `core:vpn/connection/encryptionLayer/` | TLS record reassembly, dual-`SSLEngine` MitM, passthrough learning |
| `QuicConnection` + `core:vpn/quic/` | `core:vpn/connection/encryptionLayer/` | Passive Initial inspection, QUIC block policy |
| `HttpConnection` | `core:vpn/connection/appLayer/` | HTTP/1.1 parsing; pairs and persists requests and responses |
| `CertificateSniffingMitmManager`, `SSLEngineSource`, `CertificateHelper`, `KeyStoreHelper` | `core:vpn/mitm/` | CA keystore and per-host forged certificates (BouncyCastle) |
| `MitmScope`, `QuicPolicy` | `core:vpn/mitm/`, `core:vpn/quic/` | Preference values resolved by the app (`MitmScopeResolver`, `QuicPolicyResolver`) |
| `RoomDatabaseConnector` | `core:vpn/components/` | Persists sessions, connections, requests, responses |
| `DnsCache` / `TlsPassthroughCache` | `core:vpn/metadata/` | Per-session caches for DNS names and learned passthrough |

**Packet library**: Pcap4j parses/constructs IP/TCP/UDP headers.
**Tracker detection**: Hostnames matched against a Trie built from Steven Black's unified hosts file.
**Monitoring scope**: Two independent scopes. The *VPN* scope decides which apps are routed into the tunnel (all, non-system, whitelist, blacklist). The *MitM* scope decides which apps and hosts are decrypted.

Earlier versions also offered an alternative interception path via a LittleProxy-mitm-derived HTTP proxy (`core/proxy`). That module has been removed; the VPN/TUN-based engine above is the sole interception mechanism. `TrafficScannerViewModel.VpnMode` is `OFF`, `PLAIN_VPN` or `MITM_VPN`.

For the full component-by-component reference (threading model, TLS MitM deep dive, configuration, limitations), see [`core/vpn/README.md`](../core/vpn/README.md). Diagrams of the component (architecture, sequence, BPMN) are in [`docs/diagrams/`](diagrams/README.md). The findings and fix packets behind the current implementation are in [`records/vpn-mitm-audit.md`](records/vpn-mitm-audit.md); the QUIC analysis is in [`records/quic-mitm.md`](records/quic-mitm.md).

### Generating the CA via adb

The MitM root CA can also be generated without the UI, which is useful for emulator setups that install it into the system CA store. `CaCertificateCommandReceiver` (`app/service/`) handles the broadcast. It is guarded by `android.permission.DUMP`, which only the shell and system hold.

```bash
adb shell am broadcast -f 0x20 \
  -n de.tomcory.heimdall/.service.CaCertificateCommandReceiver \
  -a de.tomcory.heimdall.action.GENERATE_CA_CERT [--ez force true]
# Broadcast completed: result=-1, data="status=generated hash=<hash> pem=<path> system=<path>"
adb pull /sdcard/Android/data/de.tomcory.heimdall/files/ca/ .
```

- The pulled directory contains `heimdallmitm.pem` and `<subject_hash_old>.0`, the file name the system CA store (`/system/etc/security/cacerts`) expects.
- Without `force`, an existing valid CA is reused (`status=reused`). With `force true`, a new CA is generated, which invalidates any installed copy. A forced run is refused while the VPN is active (`status=refused reason=vpn_active`, result=0).
- `-f 0x20` (`FLAG_INCLUDE_STOPPED_PACKAGES`) lets the command work on a fresh install that has never been launched.

---

## 6. Evaluator & Scoring Modules

`Evaluator` (`app/evaluator/Evaluator.kt`) iterates over registered `Module` instances, calls `calculateOrLoad()` on each, computes a weighted average, and persists a `Report` + `SubReport` per module to the database.

### Abstract `Module` contract (`app/evaluator/module/Module.kt`)

```kotlin
abstract suspend fun calculateOrLoad(app: App, context: Context, forceRecalculate: Boolean): Result<ModuleResult>
abstract fun BuildUICard(report: ReportWithSubReports?)  // Composable
abstract fun exportToJsonObject(subReport: SubReport?): JsonObject
```

### Implemented Modules

| Module | Score formula | Data source |
|---|---|---|
| `StaticPermissionsScore` | `max(1 - dangerous×0.4 - signature×0.02 - normal×0.01, 0)` | `AppXPermission` table; PermissionScanner |
| `TrackerScore` | `max(1 - trackerCount×0.2, 0)` | `AppXTracker` table; LibraryScanner |
| `PrivacyPolicyScore` | `fullyMentionedTrackers / allTrackers` (0 if either is 0) | Play Store scrape + bundled parent-company JSON |

Each module also provides a Compose `UICard` used on the Score detail screen.

---

## 7. Background Services & Workers

| Component | Type | Trigger | Purpose |
|---|---|---|---|
| `HeimdallVpnService` | `VpnService` (foreground) | User action / boot | Runs the traffic capture pipeline; notification shows elapsed time and Stop button |
| `ScanWorker` | `CoroutineWorker` (WorkManager) | App launch, boot, package install/remove | Scans installed apps for permissions and tracker libraries |
| `HeimdallBroadcastReceiver` | `BroadcastReceiver` (exported) | `BOOT_COMPLETED`, `PACKAGE_ADDED/REMOVED` | Schedules scans on boot; triggers single-package scan on install; marks apps uninstalled |
| `NotificationActionReceiver` | `BroadcastReceiver` (not exported) | VPN notification Stop button | Sends `STOP_SERVICE` intent to `HeimdallVpnService` |
| `HeimdallApplication` | `Application` | Process start | Hilt init, Timber setup, notification channel creation, resets stale scan states |

---

## 8. Database Schema

Room database, version 10, 14 entities. There is no migration path yet: every schema change bumps the version and wipes local data (`fallbackToDestructiveMigration`). See [`records/database-schema-audit.md`](records/database-schema-audit.md).

```
App ──────── AppXPermission ── Permission
 │
 ├────────── AppXTracker ───── Tracker ── TrackerXCategory ── Category
 │
 └────────── Report ────────── SubReport

Session ──── Connection ──── Request ──── Response

SessionSummary (standalone: rolled-up summary of a pruned Session)
```

Foreign keys with `CASCADE` delete are declared on every edge shown.

### Entity summary

| Entity | PK | Notable columns |
|---|---|---|
| `App` | `packageName` | `label`, `versionName`, `isInstalled`, `isSystem` |
| `Permission` | `permissionName` | `dangerous: Boolean` |
| `AppXPermission` | (`packageName`, `permissionName`) | FK → App, FK → Permission |
| `Tracker` | `id` (assigned by the Exodus API) | `name`, `codeSignature`, `networkSignature`, `web` |
| `Category` / `TrackerXCategory` | `name` / (`trackerId`, `categoryName`) | Tracker categories |
| `AppXTracker` | (`packageName`, `trackerId`) | FK → App, FK → Tracker |
| `Session` | `id` (auto) | `startTime`, `endTime` |
| `SessionSummary` | `id` (auto) | `sessionStartTime`, `sessionEndTime`, connection, host and tracker counts, `bytesOut/In` |
| `Connection` | `id` (assigned by `RoomDatabaseConnector`) | `sessionId`, `protocol` (`TCP`/`UDP`), `ipVersion`, `initiatorId`, `initiatorPkg`, `remoteHost`, `remoteIp`, `remotePort`, `isTracker`, `bytesOut/In`, `securityProtocol` (`PLAIN`/`TLS`/`QUIC`), `sni`, `alpn`, `echOffered`, `blocked`, `passthroughReason` |
| `Request` | `id` (auto) | `connectionId`, `method`, `remoteHost`, `remotePath`, `headers`, `content` (bytes), `contentLength`, `contentTruncated` |
| `Response` | `id` (auto) | `requestId`, `statusCode`, `statusMsg`, `headers`, `content` (bytes), `contentLength`, `contentTruncated` |
| `Report` | `reportId` (auto) | `appPackageName`, `mainScore`, `timestamp` |
| `SubReport` | (`reportId`, `module`) | `score`, `additionalDetails` (JSON) |

All DAO methods are `suspend` functions or return `Flow`; relationships are expressed with Room `@Relation` and `@Embedded` composite types (`ReportWithSubReports`, `AppWithReports`, `TrackerWithCategories`).

---

## 9. Key Dependencies

| Library | Version | Purpose |
|---|---|---|
| Jetpack Compose | 1.8.1 | Declarative UI |
| Material3 | — | UI components |
| Room | 2.7.1 | SQLite ORM |
| Hilt | 2.56.2 | Dependency injection |
| WorkManager | 2.10.1 | Background task scheduling |
| DataStore + Protobuf | 1.1.6 | Type-safe preferences |
| Retrofit + OkHttp | 2.9.0 / 5.0.0-alpha.2 | HTTP networking (Exodus API) |
| Pcap4j | 1.7.6 | IP/TCP/UDP packet parsing |
| BouncyCastle | 1.69 | TLS certificate generation |
| multidexlib2 | — | APK/DEX parsing |
| JSoup | 1.14.3 | HTML scraping (Play Store privacy policy) |
| Vico / MPAndroidChart | 1.12.0 / 3.1.0 | Charts in Compose and View |
| Timber | 4.7.1 | Structured logging |
| Kotlinx Serialization | — | JSON serialization |

---

## 10. External Integrations

**Exodus Privacy API** (`https://reports.exodus-privacy.eu.org/api/trackers`)
Fetched once (or on demand) to populate the `Tracker` table with code/network signatures used by `LibraryScanner`. Result is cached locally; the scanner works offline after the first fetch.

**Google Play Store** (scraping via JSoup + OkHttp)
`PrivacyPolicyScore` fetches the Play Store page for an app, extracts the linked privacy policy URL, fetches the policy document, and checks whether each detected tracker (or its parent company) is named in the policy text.

**Bundled host list** (Steven Black's unified hosts file, compiled into a `Trie`)
Used at runtime to label `Connection` and `Request` rows as `isTracker = true` without any network call.

**Bundled tracker-parent JSON**
Maps tracker names to parent companies for the PrivacyPolicy module's partial-match logic.
