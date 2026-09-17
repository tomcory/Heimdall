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

**Known issues**: see [`architecture-issues.md`](architecture-issues.md) for a severity-ranked audit of coupling, concurrency, testability, and scalability problems found in the current implementation.

---

## 1. What the App Does

| Feature | Description |
|---|---|
| **Permission analysis** | Scans installed apps for declared permissions; classifies each as dangerous, signature, or normal |
| **Tracker/library detection** | Scans APK DEX bytecode for known tracking SDK class signatures (Exodus Privacy database) |
| **Network traffic capture** | Runs a local VPN that intercepts all device traffic; logs connections, bytes, remote hosts |
| **HTTPS decryption (MitM)** | On rooted devices with the bundled CA trusted, decrypts TLS to log HTTP requests/responses |
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
    │ (TUN interface)
    ▼
DevicePollThread          reads raw IP packets from the VPN fd
    │
    ▼
OutboundTrafficHandler    routes packets by protocol (TCP=6, UDP=17)
    │                     manages per-connection state
    ├─ TCP connection ─────────────────────────────────────────────┐
    │     │                                                        │
    │  [MitM enabled?]                                             │
    │     │ Yes                                                    │
    │     ▼                                                        │
    │  CertificateSniffingMitmManager                              │
    │     • detects TLS ClientHello, extracts SNI                  │
    │     • generates per-host cert signed by bundled CA           │
    │     • proxies plaintext between app ↔ real server            │
    │     • passes HTTP requests/responses to RoomDatabaseConnector│
    │                                                              │
    └─ UDP connection ─────────────────────────────────────────────┘
    │
    ▼
InboundTrafficHandler     processes responses from internet
    │
    ▼
DeviceWriteThread         writes response packets back to TUN fd
    │
    ▼
Device apps
```

**Key classes:**

| Class | Location | Role |
|---|---|---|
| `HeimdallVpnService` | `app/service/` | Android `VpnService`; configures TUN, starts/stops pipeline |
| `ComponentManager` | `core:vpn/components/` | Orchestrates all threads, builds DNS/TLS caches and tracker Trie |
| `DevicePollThread` | `core:vpn/components/` | Polls VPN fd with `Os.poll()` |
| `OutboundTrafficHandler` | `core:vpn/components/` | `HandlerThread` dispatching packets to connections |
| `InboundTrafficHandler` | `core:vpn/components/` | Reconstructs inbound packets |
| `DeviceWriteThread` | `core:vpn/components/` | Writes back to TUN fd |
| `CertificateSniffingMitmManager` | `core:vpn/mitm/` | TLS interception; cert generation via BouncyCastle |
| `RoomDatabaseConnector` | `core:vpn/` | Persists sessions, connections, requests, responses |
| `DnsCache` / `TlsPassthroughCache` | `core:vpn/` | In-memory caches for DNS and pass-through TLS state |

**Packet library**: Pcap4j parses/constructs IP/TCP/UDP headers.
**Tracker detection**: Hostnames matched against a Trie built from Steven Black's unified hosts file.
**Monitoring scope**: Configurable — all apps, non-system only, whitelist, or blacklist.

Earlier versions also offered an alternative interception path via a LittleProxy-mitm-derived HTTP proxy (`core/proxy`). That module has been removed; the VPN/TUN-based MitM engine above is now the sole interception mechanism, selectable via the `VpnMode` enum (`BASE`, `MITM_VPN`) in `TrafficScannerViewModel`.

For the full component-by-component breakdown of this pipeline (threading model, TLS MitM deep dive, configuration), see [`core/vpn/README.md`](../core/vpn/README.md).

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

Room database, version 6, 11 entities.

```
App ──────────────── AppXPermission ──── Permission
 │
 └──────────────── AppXTracker ──────── Tracker
 │
 └──────────────── Report ─────────────  SubReport

Session ─────────── Connection ──────── Request ──── Response
```

### Entity summary

| Entity | PK | Notable columns |
|---|---|---|
| `App` | `packageName` | `label`, `versionName`, `isInstalled`, `isSystem` |
| `Permission` | `permissionName` | `dangerous: Boolean` |
| `AppXPermission` | `appPackageName` | FK → App, FK → Permission |
| `Tracker` | `id` (auto) | `codeSignature`, `networkSignature`, `categories`, `web` |
| `AppXTracker` | `appPackageName` | FK → App, FK → Tracker |
| `Session` | `id` (auto) | `startTime`, `endTime` |
| `Connection` | `id` (auto) | `sessionId`, `protocol`, `initiatorPkg`, `remoteHost`, `isTracker`, `bytesOut/In` |
| `Request` | `id` (auto) | `connectionId`, `method`, `remotePath`, `headers`, `content`, `isTracker` |
| `Response` | `id` (auto) | `requestId`, `statusCode`, `headers`, `content` |
| `Report` | `reportId` (auto) | `appPackageName`, `mainScore`, `timestamp` |
| `SubReport` | `id` (auto) | `reportId`, `module`, `score`, `additionalDetails` (JSON) |

All DAO methods are `suspend` functions; relationships are expressed with Room `@Relation` and `@Embedded` composite types (`ReportWithSubReports`, `AppWithReports`).

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
| Netty | 4.1.58 | TCP/TLS handling in the VPN's MitM engine |
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
