# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

Heimdall is an on-device Android privacy-analysis toolkit. It scans installed apps for permissions and embedded tracking SDKs, captures and optionally decrypts network traffic via a local VPN, computes per-app privacy scores, and exports results for offline analysis. No data leaves the device.

**Min SDK**: 24 (Android 7) · **Target/Compile SDK**: 36 · **Language**: Kotlin

## Build Commands

```bash
./gradlew assembleDebug          # Build debug APK
./gradlew assembleRelease        # Build release APK
./gradlew test                   # Run unit tests
./gradlew connectedAndroidTest   # Run instrumentation tests (requires device/emulator)
./gradlew clean build            # Clean rebuild
```

CI runs `./gradlew build` (JDK 17, macOS) on push/PR to main.

## Module Structure

```
app/                    Main application — UI, navigation, DI wiring, services
core/
  database/             Room database: entities, DAOs, migrations
  scanner/              PermissionScanner, LibraryScanner, Exodus API client
  vpn/                  VPN packet pipeline, MitM engine (Pcap4j + Netty + BouncyCastle)
  proxy/                LittleProxy-based HTTP proxy (alternative interception path)
  util/                 Trie, AppFinder, file/network utilities
  export/               CSV, JSON, TeX export logic
  datastore/            DataStore preferences (type-safe wrappers)
  datastore-proto/      Protocol Buffer schema for preferences
```

Each `core:*` module is a pure Android library. Only `app` depends on all of them; core modules have minimal inter-module dependencies.

## Architecture

**Pattern**: MVVM + Repository + Hilt DI + reactive Flows

- **ViewModels** own UI state as `StateFlow`/`Flow` and are injected via Hilt (`@HiltViewModel`).
- **Repositories** (`ScannerRepository`, `MainRepository`) abstract Room DAOs, DataStore, and scanner results.
- **Hilt** wired via `@HiltAndroidApp` on `HeimdallApplication`; `AppModule` provides singletons for the database, `ScannerRepository`, and `Evaluator`.
- **WorkManager** (`ScanWorker` as `CoroutineWorker`) handles background permission and library scans. Triggered on app launch, boot, and package install/remove.
- **UI** is Jetpack Compose with Material 3. Navigation uses a bottom bar with three destinations (`scanner`, `score`, `database`) defined in `ui/nav/Navigation.kt`.

## VPN / Traffic Inspection Pipeline

```
Device apps (TUN)
  → DevicePollThread          reads raw IP packets from VPN fd
  → OutboundTrafficHandler    routes by protocol (TCP/UDP); manages per-connection state
      ├─ TCP + MitM enabled → CertificateSniffingMitmManager (SNI detection, per-host cert via BouncyCastle, HTTP log)
      └─ UDP → DnsCache / TlsPassthroughCache
  → RoomDatabaseConnector     persists sessions, connections, requests, responses
  → InboundTrafficHandler     reconstructs inbound packets
  → DeviceWriteThread         writes back to TUN fd
```

Key classes: `HeimdallVpnService` (app/service), `ComponentManager` (core:vpn/components), `CertificateSniffingMitmManager` (core:vpn/mitm), `RoomDatabaseConnector` (core:vpn).

Hostname-based tracker detection uses a `Trie` built from Steven Black's bundled hosts file — no network call needed.

## Evaluator & Scoring

`Evaluator` (`app/evaluator/Evaluator.kt`) iterates over `Module` implementations, calls `calculateOrLoad()` on each, computes a weighted average, and persists a `Report` + `SubReport` per module.

To add a new scoring axis, implement the abstract `Module` class (`app/evaluator/module/Module.kt`):

```kotlin
abstract suspend fun calculateOrLoad(app: App, context: Context, forceRecalculate: Boolean): Result<ModuleResult>
abstract fun BuildUICard(report: ReportWithSubReports?)   // Composable
abstract fun exportToJsonObject(subReport: SubReport?): JsonObject
```

Existing modules: `StaticPermissionsScore`, `TrackerScore`, `PrivacyPolicyScore`.

## Database Schema (Room, v6, 11 entities)

```
App ──────── AppXPermission ── Permission
 │
 ├────────── AppXTracker ───── Tracker
 │
 └────────── Report ────────── SubReport

Session ──── Connection ──── Request ──── Response
```

All DAO methods are `suspend` functions. Composite types (`ReportWithSubReports`, `AppWithReports`) use `@Relation` / `@Embedded`. DAOs live in `core/database/src/main/java/.../dao/`.

## External Integrations

| Integration | How |
|---|---|
| **Exodus Privacy API** (`reports.exodus-privacy.eu.org/api/trackers`) | Fetched once via Retrofit; populates `Tracker` table; cached locally |
| **Google Play Store** | JSoup + OkHttp scraping for `PrivacyPolicyScore` |
| **Steven Black unified hosts file** | Bundled; compiled into `Trie` at runtime for `isTracker` labeling |
| **Tracker-parent JSON** | Bundled; maps tracker names → parent companies for privacy policy partial matching |

## Key Dependencies

Dependencies are centrally managed in `gradle/libs.versions.toml`.

| Library | Purpose |
|---|---|
| Jetpack Compose 1.8.1 + Material3 | UI |
| Room 2.7.1 | SQLite ORM |
| Hilt 2.56.2 | DI |
| WorkManager 2.10.1 | Background tasks |
| DataStore 1.1.6 + Protobuf | Type-safe preferences |
| Retrofit 2.9.0 + OkHttp 5.0.0-alpha.2 | Exodus API calls |
| Pcap4j 1.7.6 | IP/TCP/UDP packet parsing |
| Netty 4.1.58 | Proxy TCP |
| BouncyCastle 1.69 | TLS cert generation |
| multidexlib2 | APK/DEX parsing for tracker detection |
| JSoup 1.14.3 | Play Store HTML scraping |
| Timber 4.7.1 | Logging |
