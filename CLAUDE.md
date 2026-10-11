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
  vpn/                  VPN packet pipeline, MitM engine (Pcap4j + JSSE SSLEngine + BouncyCastle)
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
  → DevicePollThread          reads raw IP packets from the VPN fd; reassembles IPv4 fragments
  → OutboundTrafficHandler    finds or creates the packet's connection (ConnectionCache)
      → TcpConnection / UdpConnection           transparent proxy over protected sockets
          → TlsConnection / QuicConnection / PlaintextConnection     (encryption layer)
              → HttpConnection / DnsConnection / DnsStreamConnection / RawConnection   (app layer)
  → RoomDatabaseConnector     persists sessions, connections, requests, responses
  → InboundTrafficHandler     NIO selector loop over the outward-facing sockets
  → DeviceWriteThread         writes rebuilt IP packets back to the TUN fd
```

Every connection is a stack of transport, encryption and application layer objects; payloads go
up through `unwrapOutbound`/`unwrapInbound` and back down through `wrapOutbound`/`wrapInbound`.

- **TLS MitM** (`TlsConnection`): two JSSE `SSLEngine`s per connection, server-facing handshake
  first, then a client-facing one with a leaf certificate forged from the real certificate's CN and
  SANs (`CertificateSniffingMitmManager`, BouncyCastle). Only HTTP/1.1 is recorded; ALPN is
  negotiated down to `http/1.1`.
- **Passthrough**: a TLS connection is forwarded undecrypted if it is outside the `MitmScope`
  preferences, if the client's ALPN excludes `http/1.1`, or if `TlsPassthroughCache` has learned
  (per VPN session, per app and host) that the app rejects the forged certificate or that the
  upstream handshake fails. The reason is stored in `Connection.passthroughReason`.
- **QUIC** (`QuicConnection`, `core:vpn/quic`): never decrypted. The client Initial is decrypted
  passively for SNI/ALPN. With `QuicPolicy.BLOCK` (MitM on), HTTP/3 flows that the TLS MitM would
  intercept are dropped and answered with ICMP port unreachable, so the app falls back to TLS.
- **DNS**: answers over UDP, TCP and decrypted DoT fill `DnsCache` (IP → hostname). DoT to the VPN's
  DNS server is refused unless Private DNS is in strict mode.

Key classes: `HeimdallVpnService` (app/service), `ComponentManager` (core:vpn/components),
`TcpConnection` (core:vpn/connection/transportLayer), `TlsConnection`
(core:vpn/connection/encryptionLayer), `HttpConnection` (core:vpn/connection/appLayer),
`RoomDatabaseConnector` (core:vpn/components). Full reference: `core/vpn/README.md`; diagrams:
`docs/diagrams/`.

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

## Database Schema (Room, v10, 14 entities)

```
App ──────── AppXPermission ── Permission
 │
 ├────────── AppXTracker ───── Tracker ── TrackerXCategory ── Category
 │
 └────────── Report ────────── SubReport

Session ──── Connection ──── Request ──── Response

SessionSummary (standalone — rolled-up historical summary of a pruned Session)
```

Foreign keys with `CASCADE` delete are declared on every parent/child edge shown above (added as
part of the schema audit in `docs/records/database-schema-audit.md`). `Tracker.id` is the stable id
assigned by the Exodus Privacy API, not autogenerated locally — catalogue refreshes upsert by this
key instead of reassigning ids. `Connection`/`Request`/`Response`/`Session`/`Tracker` primary keys
are `Long`. `Connection.protocol` is a `Protocol` enum (`HeimdallTypeConverters`), not a raw string.
`Connection.securityProtocol` (`SecurityProtocol` enum: `PLAIN`/`TLS`/`QUIC`), `sni`, `alpn`,
`echOffered`, `blocked` and `passthroughReason` (why a TLS connection was not decrypted while
MitM was on) are filled in by the VPN's encryption layer after the row is created.

Traffic (`Session`→`Response`) and report (`Report`/`SubReport`) retention are user-configurable —
see the "Traffic retention" and "Report retention" preference sections and
`TrafficRetentionWorker`. There is still no real Room `Migration` path (`fallbackToDestructiveMigration`
remains in `DatabaseModule.kt` by design until the schema is judged stable — see PKT-00 in the audit
doc); every entity change here bumps `version` in `HeimdallDatabase.kt` and wipes local data on
upgrade.

All DAO methods are `suspend` functions or return `Flow`. Composite types (`ReportWithSubReports`,
`AppWithReports`, `TrackerWithCategories`) use `@Relation` / `@Embedded`. DAOs live in
`core/database/src/main/java/.../dao/`. See `docs/records/database-schema-audit.md` for the full findings
register and packet-by-packet implementation notes.

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
| BouncyCastle 1.69 | TLS cert generation |
| multidexlib2 | APK/DEX parsing for tracker detection |
| JSoup 1.14.3 | Play Store HTML scraping |
| Timber 4.7.1 | Logging |
