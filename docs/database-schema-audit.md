# Database schema audit — `core:database`

**Date:** 2026-09-18 · **Scope:** `core/database` (Room, `version = 6`, 11 entities), plus its
consumers in `core:vpn`, `core:scanner`, `core:export` and `app`.

This document is a findings register plus a set of **independently-committable packets**. Each
packet stands on its own: it lists what it resolves, which files it touches, how to verify it, and a
suggested commit message. Work through them one at a time; nothing here has been implemented.

All file:line references below were verified against the source at the time of writing. Line numbers
drift — use the surrounding quoted code to re-locate if they no longer match.

---

## 1. Findings register

Severity: **C** critical (silent data corruption / wrong data) · **H** high (integrity or
performance) · **M** medium (scalability) · **L** low (consistency, hygiene).

| ID | Sev | Finding |
|---|---|---|
| F-01 | C | Tracker catalogue refresh silently orphans every app↔tracker association |
| F-02 | C | `Request.isTracker` / `Response.isTracker` are never written, but are exported to CSV |
| F-03 | C | `ConnectionDao.updateBytesOut` updates from the wrong column |
| F-04 | H | No Room migration has ever existed; every version bump wipes all user data |
| F-05 | H | Missing foreign keys on four parent/child relationships |
| F-06 | H | Missing indices on three actively-queried columns |
| F-07 | H | Five redundant indices on primary-key / leading-composite-key columns |
| F-08 | L | `AppXTracker`'s join column is literally named `id` |
| F-09 | M | No retention policy: the traffic tables grow monotonically forever |
| F-10 | M | `Report`/`SubReport` are append-only; no supersession on re-scan |
| F-11 | M | `getAllAppsWithReportsAndSubReports()` loads the entire report graph as a hot `Flow` |
| F-12 | M | Over-fetching: whole rows returned where one column is used |
| F-13 | M | N+1 insert loop in `ScanWorker.performFullScan()` |
| F-14 | M | `ScoreViewModel.scoreAllApps()` materialises the full report graph for a name list |
| F-15 | L | Score types drift between `Float` and `Double` |
| F-16 | L | `CURRENT_TIMESTAMP` column default on `Long` timestamp columns |
| F-17 | L | `App.flags` is real data from one insert path, always `0` from two others |
| F-18 | L | High-volume primary keys are `Int` |
| F-19 | L | ~25 of ~55 DAO methods are unused |
| F-20 | L | Sentinel/default values that cannot be distinguished from real values |
| F-21 | L | `Tracker.categories` is a delimiter-joined string; no `TypeConverter`s exist |
| F-22 | L | `Session.startTime` unindexed despite `ORDER BY startTime DESC` |

### F-01 — Tracker refresh orphans app↔tracker associations (Critical)

`Tracker.id` is a surrogate `@PrimaryKey(autoGenerate = true)` with no uniqueness constraint on any
natural column (`entity/Tracker.kt:10-11`). `ExodusUpdater` refreshes the catalogue by wiping and
reloading it:

```kotlin
// core/scanner/src/main/java/de/tomcory/heimdall/core/scanner/ExodusUpdater.kt:55-56
database.trackerDao().deleteAllTrackers()
database.trackerDao().insertTrackers(*trackerList.toTypedArray())
```

Every refresh therefore reassigns every tracker's `id`. Meanwhile `AppXTracker.trackerId`
(`entity/AppXTracker.kt:13-14`) is a plain column with **no `@ForeignKey`**, written once per app
scan (`LibraryScanner.kt:66,80`) and never re-linked. After any refresh, previously-recorded
associations point at recycled ids — they silently join to the wrong tracker or to nothing. Refresh
is triggered whenever the tracker table is empty (`LibraryScanner.kt:88-95`), so this is reachable in
normal operation, not a theoretical edge case.

`insertTrackers` uses `OnConflictStrategy.IGNORE` (`dao/TrackerDao.kt:10-12`), which never fires:
with a surrogate key and no unique index on any other column, there is nothing to conflict on.

#### User Instructions

Fix this, and add cascading re-derivation of `Connection.isTracker` when the tracker catalogue
changes.

### F-02 — `Request`/`Response.isTracker` never populated, yet exported (Critical)

Both entities declare the field (`entity/Request.kt:37`, `entity/Response.kt:37`):

```kotlin
val isTracker: Boolean = false
```

The only production insert path never passes it — `RoomDatabaseConnector.persistHttpRequest` builds
`Request(...)` with fourteen named arguments and `isTracker` is not among them
(`core/vpn/.../components/RoomDatabaseConnector.kt:94-111`); `persistHttpResponse` is identical
(`:137-154`). The `DatabaseConnector` interface doesn't even expose the parameter
(`DatabaseConnector.kt:32-47` and `:49-65`), unlike `persistTransportLayerConnection` which does
(`DatabaseConnector.kt:25`).

Every `Request`/`Response` row ever written therefore has `isTracker = false` — and that column is
exported as fact by `core/export/src/main/java/de/tomcory/heimdall/core/export/csv/CsvExport.kt:18,24`.

Note `Connection.isTracker` (`entity/Connection.kt:33`) is **fine**: genuinely computed via
`TransportLayerConnection.kt:110` → `ComponentManager.labelConnection()` → trie lookup, and persisted
at `RoomDatabaseConnector.kt:58`. It is, however, a write-once denormalisation — never re-derived if
the tracker catalogue later changes (see F-01).

#### User Instructions

Remove the field from the `Request`/`Response` entities, keeping `Connection.isTracker` as the single
source of truth.

### F-03 — `updateBytesOut` reads the wrong column (Critical, currently dormant)

```kotlin
// core/database/.../dao/ConnectionDao.kt:24-28
@Query("UPDATE Connection SET bytesOut = bytesIn + :delta WHERE id = :id")
suspend fun updateBytesOut(id: Int, delta: Int)

@Query("UPDATE Connection SET bytesIn = bytesIn + :delta WHERE id = :id")
suspend fun updateBytesIn(id: Int, delta: Int)
```

`updateBytesOut` accumulates onto `bytesIn`, clobbering `bytesOut` with an unrelated running total.
Neither method currently has a caller, so no stored data is wrong today — but the bug must not
survive until byte accounting is wired up.

#### User Instructions

Fix this so that we can rely on the byte counts being correct for future callers.

### F-04 — No migrations have ever existed (High)

`DatabaseModule.kt:22` — `.fallbackToDestructiveMigration(dropAllTables = true).build()`. There are no
`Migration` objects, no `@AutoMigration`s, and `exportSchema = false` (`HeimdallDatabase.kt:42`), so
there is no schema history to migrate against. The version has been bumped to 6
(`HeimdallDatabase.kt:29`) across the project's life, and destructive fallback has been in place since
version 1 — meaning **every schema change to date has silently destroyed all captured traffic,
sessions and reports on existing installs.**

This is the gating decision for most of the schema packets below: adding foreign keys and indices
(PKT-04, PKT-05) are themselves schema changes that would trigger exactly this wipe.

#### User Instructions

Keep the destructive migration schema in place for this pass – we'll start using proper migrations
once we have a stable schema.

### F-05 — Missing foreign keys (High)

| Child | Column | Should reference | Current state |
|---|---|---|---|
| `AppXPermission` | `packageName` | `App.packageName` | no FK (`entity/AppXPermission.kt:9-15`) |
| `AppXTracker` | `packageName`, `trackerId` | `App.packageName`, `Tracker.id` | no FK (`entity/AppXTracker.kt:9-14`) |
| `Report` | `appPackageName` | `App.packageName` | no FK (`entity/Report.kt`, bare `@Entity`) |
| `SubReport` | `reportId` | `Report.reportId` | no FK (`entity/SubReport.kt:26`) |

The `Session → Connection → Request → Response` chain is the one part of the schema done correctly:
real `@ForeignKey(onDelete = CASCADE)` with covering indices (`entity/Connection.kt:8-19`,
`entity/Request.kt:7-19`, `entity/Response.kt:7-19`).

`AppXTracker`'s missing FK is not latent — `TrackerDao.deleteAllTrackers()` (`dao/TrackerDao.kt:17-18`)
actively deletes all parent rows with no cascade (see F-01).

#### User Instructions

Fix.

### F-06 — Missing indices (High)

- **`Report.appPackageName`** — the entire basis of the `AppWithReports` / `AppWithReportsAndSubReports`
  relations (`entity/Report.kt:57-63,83-90`, used by `dao/ReportDao.kt:43-52`), with no index at all.
- **`SubReport.packageName`** — filtered by `dao/SubReportDao.kt:42,54` and sorted by `:36`.
- **`SubReport.module`** — filtered alone by `dao/SubReportDao.kt:48`; as the *trailing* column of the
  composite PK, the PK index cannot serve a module-only lookup.

#### User Instructions

Fix.

### F-07 — Redundant indices (High, cheap to fix)

SQLite already maintains an implicit index for a single-column primary key and for the leading
column(s) of a composite key. These five explicit `@ColumnInfo(index = true)` declarations duplicate
existing structures, costing write throughput and storage for nothing:

`entity/App.kt:11-13` (`packageName`, is the PK) · `entity/Permission.kt:10-12` (`permissionName`, is
the PK) · `entity/AppXPermission.kt:11-12` (`packageName`, leading composite-PK column) ·
`entity/AppXTracker.kt:11-12` (`packageName`, same) · `entity/SubReport.kt:28-29` (`reportId`, same) ·
`entity/Report.kt` (`@ColumnInfo(index = true)` on the `reportId` PK).

The *non-leading* junction indices are justified and should stay: `AppXPermission.permissionName`
(`:13-14`, serves `PermissionWithApps`) and `AppXTracker.trackerId` (`:13-14`, serves `TrackerWithApps`).

#### User Instructions

Fix.

### F-08 — `AppXTracker`'s join column is named `id` (Low)

```kotlin
// entity/AppXTracker.kt:9-14
@Entity(primaryKeys = ["packageName", "id"])
    @ColumnInfo(index = true, name = "id")
    val trackerId: Int
```

The Kotlin field is `trackerId` but the stored column is `id`, colliding by name with the surrogate
PK of `Tracker`, `Session`, `Connection`, `Request` and `Response`. Any schema dump or raw-SQL
debugging session reads as if the junction table were self-referential. `AppXPermission` uses the
honest name (`permissionName`) for the equivalent column.

#### User Instructions

Fix by renaming the stored column.

### F-09 — No retention policy (Medium)

`Session`, `Connection`, `Request` and `Response` grow strictly monotonically for the life of an
install. Every transport-layer connection and every HTTP transaction is a permanent row. A repo-wide
search for `DELETE FROM` / `@Delete` / prune / retention / cleanup / vacuum finds:

- `dao/ConnectionDao.kt:18` (`delete(id)`) — called only on **connection setup failure**
  (`RoomDatabaseConnector.kt:68-75` ← `TransportLayerConnection.kt:156-160` ← `TcpConnection.kt:76,85`,
  `UdpConnection.kt:66,75`). Not retention.
- `dao/ConnectionDao.kt:21` (`deleteForApp`), `dao/SessionDao.kt:23,26,29-30`, `dao/RequestDao.kt:20-21`,
  `dao/ResponseDao.kt:20-21` — **all dead**, zero callers.
- `dao/TrackerDao.kt:17-18` — the only DELETE actually exercised, and it targets the catalogue table,
  not traffic data.

There is no `WorkManager` job or any other scheduled pruning. Today the only thing that ever bounds
these tables is the destructive migration from F-04 — i.e. total data loss standing in for a
retention policy.

#### User Instructions

This was a deliberate decision as the app was originally designed to be a simple traffic monitor.
However, the scope has shifted to include a more comprehensive analytics consumer, so we need to think
about suitable, **user-configurable/selectable** retention and rolling aggregation policies.

### F-10 / F-11 — Report growth and the unbounded relation `Flow` (Medium)

`Evaluator.createReport()` always inserts a fresh `Report` (`app/evaluator/Evaluator.kt:121-153`,
insert at `:130-134`) plus one `SubReport` per module (`:139-150`). Because `Report.reportId` is
`autoGenerate` and always passed as `0`, the DAO's `OnConflictStrategy.REPLACE` never triggers — there
is no supersession path anywhere. Every re-scan of every app appends rows forever, while the UI only
ever reads the newest via `AppWithReports.getLatestReport()` (`entity/Report.kt:66-68`, a Kotlin-side
`maxByOrNull`).

This compounds into F-11: `dao/ReportDao.kt:51` `getAllAppsWithReportsAndSubReports()` is
`SELECT * FROM App` joined via `@Relation` to **every** report and **every** sub-report, with no date
bound, no `LIMIT`, and no "latest only" filter. It is consumed as a hot reactive `Flow` in
`ScoreViewModel.kt:56`, `combine`d and `map`ped on every emission (`:59-110`) — so the entire
historical report graph is re-materialised on every write to any of those tables.

#### User Instructions

Make this user-configurable, allowing users to choose between "latest only" and "all time" report 
retention.

### F-12 — Over-fetching (Medium)

- `dao/ResponseDao.kt:32` — `SELECT * FROM Response WHERE requestId = :requestId LIMIT 1`, while its
  sole call site reads exactly one column: `DatabaseViewModel.kt:107`
  (`...getForRequest(requestId)?.statusCode`). The fetched row carries `headers` and `content` blobs.
- `dao/ConnectionDao.kt:30,33` — `SELECT *`; the analytics consumer (`DatabaseViewModel.kt:32-90`)
  uses 5 of 14 columns.
- `dao/RequestDao.kt:32` — `SELECT *` including `headers`/`content` for list rendering
  (`DatabaseViewModel.kt:103-104`).

#### User Instructions

We are going to substantially rework the DatabaseView soon, so keep this as-is for now.

### F-13 / F-14 — N+1 and heavy lookups (Medium)

- `ScanWorker.performFullScan()` (`app/service/ScanWorker.kt:130-179`) calls `insertApps(...)` once
  per installed app inside `forEachIndexed`, despite `AppDao.insertApps` already taking `vararg App`
  (`dao/AppDao.kt:11-12`). On a 200-app device that is 200+ round trips instead of one.
- `ScoreViewModel.scoreAllApps()` (`:173-176`) calls `allApps.first()` purely to obtain a list of
  package names — forcing full materialisation of the F-11 relation graph for what should be a
  single-column query.

#### User Instructions

Re-wire `ScanWorker.performFullScan()` to bulk-insert after completing the scan and fix
`ScoreViewModel.scoreAllApps()`.

### F-15 — Score type drift (Low)

`Report.mainScore: Double` (`entity/Report.kt`) vs `SubReport.score: Float` (`entity/SubReport.kt:32`)
vs `ModuleResult.score: Float` (`app/evaluator/ModuleResult.kt:14`), with `weight: Double` on both
sides (`entity/SubReport.kt:35`, `app/evaluator/module/Module.kt:56`). They are summed together in
`Evaluator.kt:104-108`. Kotlin auto-widens so results are correct today; the inconsistency is a
precision-bug waiting to be introduced.

#### User Instructions

Align the different scores to prevent type drift.

### F-16 — `CURRENT_TIMESTAMP` default on a `Long` column (Low)

```kotlin
// entity/Report.kt and entity/SubReport.kt:33-34
@ColumnInfo(defaultValue = "CURRENT_TIMESTAMP")
val timestamp: Long      // SubReport: Long?
```

SQLite's `CURRENT_TIMESTAMP` yields text (`'YYYY-MM-DD HH:MM:SS'`, UTC), not epoch millis — which is
what every other timestamp in the schema stores and what every Kotlin insert site supplies
(`Evaluator.kt:132,145`). The default is currently unreachable, so nothing breaks; it is a landmine
for any future raw-SQL insert, seed script or migration. Note also `SubReport.timestamp` is nullable
while `Report.timestamp` is not, for conceptually identical data.

#### User Instructions

Remove the default and align `SubReport.timestamp` with `Report.timestamp`.

### F-17 — `App.flags` populated inconsistently (Low)

`ScanWorker.kt:111,160` sets the real value (`pkgInfo.applicationInfo?.flags ?: 0`). Two other live
insert paths never pass it at all, leaving the `= 0` default:
`LibraryScannerViewModel.kt:127-133` and `PermissionScannerViewModel.kt:122-128`. Two paths write the
same entity and disagree on whether the column is data or a placeholder. The field is also an
undocumented bitfield with no KDoc.

#### User Instructions

The field is meant to hold `pkgInfo.applicationInfo?.flags`.

### F-18 — High-volume primary keys are `Int` (Low)

`Connection.id`, `Request.id`, `Response.id` and `Session.id` are `Int` autogenerate
(`entity/Connection.kt:21-22`, `entity/Request.kt:21-22`, `entity/Response.kt:21-22`). For a
continuously-writing traffic monitor with no pruning (F-09), the ~2.1B ceiling is a real, if distant,
limit — and `Report.reportId` is already `Long`, so the schema is internally inconsistent about it.

#### User Instructions

Switch to `Long` for all primary keys.

### F-19 — ~25 unused DAO methods (Low)

See Appendix A for the full inventory.

#### User Instructions

Leave for now, we can clean up later.

### F-20 — Ambiguous sentinels and defaults (Low)

- `Connection.remoteHost: String = ""` (`entity/Connection.kt:30`) — "unresolved" and "no reverse-DNS
  name" are indistinguishable, and `DatabaseViewModel.kt:83` branches on `isNotEmpty()`. (The default
  itself is dead: `RoomDatabaseConnector.kt:55` always supplies a value.)
- `App.isInstalled: Boolean = true` — never set at any construction site; only ever mutated
  out-of-band by raw SQL (`dao/AppDao.kt:14-15` ← `HeimdallBroadcastReceiver.kt:86`).
- `SubReport.additionalDetails: String = ""` (`:36`) — empty string rather than nullable for a
  free-form/JSON field; downstream parsing of `""` throws rather than reading as "absent".
- `Session.endTime: Long = -1` — a reasonable sentinel, listed for completeness.

#### User Instructions

- `Connection.remoteHost: String = ""`: make it nullable and distingush between "unresolved" and 
  "no reverse-DNS name".
- `App.isInstalled: Boolean = true`: update to false when apps are uninstalled and for any apps not
  found by the full-sweep permission and library scans.
- `SubReport.additionalDetails: String = ""`: make it nullable and remove the default.
- `Session.endTime: Long = -1`: leave as-is.

### F-21 — Serialised lists, no `TypeConverter`s (Low)

`Tracker.categories: String` holds a comma-joined list (`entity/Tracker.kt:13`, built at
`ExodusUpdater.kt:45`) — not relationally queryable; category filters would need `LIKE '%…%'`. There
is no `TypeConverter` class anywhere in the module, so all categorical data (`Connection.protocol`,
`Response.statusMsg`, `Tracker.categories`) is raw `String` with no compile-time safety.

#### User Instructions

Add entities and `TypeConverter` classes for the listed categorical data.

### F-22 — `Session.startTime` unindexed (Low)

`dao/SessionDao.kt:41-42` does `ORDER BY startTime DESC LIMIT 1` on an unindexed column. Session
counts are small and the call is not hot (`TrafficScannerViewModel.kt:112`, once per VPN start/stop),
so this is a completeness note rather than a real cost today.

#### User Instructions

Add an index for completeness.

---

## 2. Packets

### PKT-00 — Record the migration strategy (decided)

- **Priority:** High (do first — establishes the rule every other schema packet relies on) · **Depends
  on:** —
- **Resolves:** F-04
- **Type:** Decision record. No production code changes.
- **Decision (per user instruction):** keep `fallbackToDestructiveMigration` for this pass. Real
  `Migration`s + `exportSchema = true` are deferred until the schema is judged stable — revisit once
  PKT-01/02/04/05/06/08/13/14 have landed.
- **Standing rule for every schema-changing packet below:** bump `version` in `HeimdallDatabase.kt`
  whenever an entity's columns change, even though the fallback is destructive. Room only knows to
  reconcile (here: wipe and recreate) on a version mismatch — without the bump, an existing install
  hits a runtime schema mismatch instead of a clean, intentional wipe. Each schema packet below notes
  this as "bump `version` (PKT-00)" rather than repeating the rationale.
- **Files:** `docs/ARCHITECTURE.md` (record the decision and the revisit trigger).
- **Tests:** none.
- **Commit:** `docs: record Room migration strategy for core:database`

### PKT-01 — Give `Tracker` a stable key, fix refresh orphaning, re-derive `Connection.isTracker`

- **Priority:** Critical · **Depends on:** PKT-00 (bump `version`)
- **Resolves:** F-01 (and the `AppXTracker` half of F-05)
- **Approach, part 1 (the orphaning bug):** replace the surrogate `Tracker.id` with the Exodus-provided
  identifier as the primary key (or add a unique index on it and key `AppXTracker` off that), switch
  `ExodusUpdater` from wipe-and-reload to an upsert (`OnConflictStrategy.REPLACE` against the natural
  key), and add `@ForeignKey(onDelete = CASCADE)` from `AppXTracker.trackerId`. With a stable key,
  existing associations survive a catalogue refresh; with the FK, a tracker genuinely removed upstream
  cleanly takes its associations with it instead of leaving them mis-pointed.
- **Approach, part 2 (cascading re-derivation) — open architectural question, read before starting:**
  the user instruction asks for `Connection.isTracker` to be re-derived when the tracker catalogue
  changes. As it stands, `Connection.isTracker` is **not** derived from the `Tracker`/`AppXTracker`
  tables at all — it comes from `ComponentManager`'s in-memory `trackerTrie`
  (`core/vpn/.../components/ComponentManager.kt:51,268`), built once at VPN startup from the bundled
  Steven Black hosts file (`R.raw.adhosts`, `:101`), and is keyed by **hostname**, not by app or by the
  Exodus catalogue (which is keyed by app-bundled tracker *libraries*, unrelated to hostnames). These
  are two independent tracker-detection mechanisms today. Making "re-derive `Connection.isTracker` on
  catalogue change" meaningful requires first deciding how they should relate — e.g. folding Exodus
  hostnames (if the API exposes any) into the same trie, or accepting that this instruction currently
  has no catalogue to react to and is better read as "make the hosts-file trie itself refreshable and
  re-derive on *that* change." Flag this back before implementing rather than guessing at the
  connection between two currently-unrelated systems.
- **Approach, part 2b (once the above is resolved):** add a bulk re-labelling path — a new
  `ConnectionDao` query to update `isTracker` for connections matching a hostname set (avoid a
  per-row round trip; recall F-09/PKT-07 means this table has no bound today) — triggered after
  whichever refresh event part 2 settles on.
- **Files:** `entity/Tracker.kt`, `entity/AppXTracker.kt`, `dao/TrackerDao.kt`, `dao/ConnectionDao.kt`,
  `core/scanner/.../ExodusUpdater.kt`, `core/scanner/.../LibraryScanner.kt`,
  `core/vpn/.../components/ComponentManager.kt`.
- **Tests:** unit test — seed trackers, record `AppXTracker` rows for an app, run a catalogue refresh
  with reordered/changed input, assert the app still resolves to the same trackers by name; once part
  2 is designed, a test asserting existing `Connection` rows are relabelled after the triggering event.
- **Commit:** `fix(database): key trackers by stable id so refreshes don't orphan app associations`

### PKT-02 — Remove `Request`/`Response.isTracker`; `Connection.isTracker` is the sole source of truth

- **Priority:** Critical · **Depends on:** PKT-00 (bump `version` — this drops columns)
- **Resolves:** F-02
- **Approach:** delete the `isTracker` field from both `Request` and `Response` entities. Nothing
  constructs them with it today (confirmed: `RoomDatabaseConnector.kt:94-111,137-154` never pass it),
  so removal is a pure schema/read-side change, no write-side code to touch.
  The one real consumer is `core/export/.../csv/CsvExport.kt:18,24` (`exportRequestsToCSV`), which
  currently writes `request.isTracker` as a CSV column. Since `Request` has no direct reference to its
  connection's `isTracker`, replace the plain `requestDao.getAllPaginated(...)` call with a small joined
  query (`SELECT r.*, c.isTracker AS connectionIsTracker FROM Request r JOIN Connection c ON
  r.connectionId = c.id LIMIT :limit OFFSET :offset`, returned as a lightweight DTO) so the export
  keeps an `isTracker` column — now sourced correctly — without a per-row lookup. Note there is no
  equivalent CSV export for `Response` today, so no second consumer to update there.
- **Files:** `entity/Request.kt`, `entity/Response.kt`, `dao/RequestDao.kt` (new joined query + DTO),
  `core/export/.../csv/CsvExport.kt`.
- **Tests:** `CsvExport` test asserting the exported `isTracker` column matches the connection's, not a
  hardcoded `false`; build should surface every other reference to the removed fields.
- **Commit:** `fix(database): drop dead Request/Response.isTracker, source CSV export from Connection`

### PKT-03 — Fix `updateBytesOut`

- **Priority:** Critical (trivial) · **Depends on:** —
- **Resolves:** F-03
- **Approach:** `SET bytesOut = bytesOut + :delta`. One line.
- **Files:** `core/database/.../dao/ConnectionDao.kt`.
- **Tests:** small DAO test inserting a connection, applying both counters, asserting independence.
  (Worth adding even though the methods are currently uncalled — this is exactly the bug a test
  catches for free.)
- **Commit:** `fix(database): accumulate bytesOut from bytesOut, not bytesIn`

### PKT-04 — Add the missing foreign keys

- **Priority:** High · **Depends on:** PKT-00 (bump `version`); PKT-01 for the tracker FK specifically
- **Resolves:** F-05
- **Approach:** add `@ForeignKey(onDelete = CASCADE)` for `AppXPermission.packageName` → `App`,
  `AppXTracker.packageName` → `App`, `Report.appPackageName` → `App`, and `SubReport.reportId` →
  `Report`, each with a covering index (coordinate with PKT-05 so indices aren't added twice).
  Decide explicitly whether `Connection.initiatorPkg` should stay FK-free — it is a deliberate
  historical record that must outlive app uninstalls, and should be commented as such rather than
  left looking like an oversight.
- **Files:** `entity/AppXPermission.kt`, `entity/AppXTracker.kt`, `entity/Report.kt`,
  `entity/SubReport.kt`, plus the migration from PKT-00.
- **Tests:** DAO tests asserting cascade behaviour (delete an `App`, assert its junction/report rows
  vanish); verify no existing insert path now violates a constraint.
- **Commit:** `feat(database): enforce app/report relationships with foreign keys`

### PKT-05 — Index hygiene

- **Priority:** High · **Depends on:** PKT-00 (bump `version`)
- **Resolves:** F-06, F-07, F-22
- **Approach:** add indices on `Report.appPackageName`, `SubReport.packageName`, `SubReport.module`,
  and `Session.startTime` (F-22's "add for completeness" now included, not optional); remove the five
  redundant PK/leading-column indices listed in F-07. Keep `AppXPermission.permissionName` and
  `AppXTracker.trackerId`.
- **Files:** `entity/App.kt`, `entity/Permission.kt`, `entity/AppXPermission.kt`,
  `entity/AppXTracker.kt`, `entity/Report.kt`, `entity/SubReport.kt`, `entity/Session.kt`.
- **Tests:** build + existing suites; optionally assert query plans via `EXPLAIN QUERY PLAN` in a DAO
  test for the `AppWithReports` relation.
- **Commit:** `perf(database): index relation join columns, drop redundant PK indices`

### PKT-06 — Rename `AppXTracker.id` → `trackerId`

- **Priority:** Low · **Depends on:** PKT-00 (bump `version`), PKT-01 (same table), PKT-13 (same
  column's type also changes there — do all three together rather than bumping the version three times)
- **Resolves:** F-08
- **Approach:** drop the `name = "id"` override so the column matches the field. Fold into PKT-01's
  migration since that packet already rewrites the table.
- **Files:** `entity/AppXTracker.kt`, plus any raw SQL referencing the column, plus the migration.
- **Tests:** build + tracker-association tests from PKT-01.
- **Commit:** `refactor(database): name AppXTracker's join column trackerId`

### PKT-07 — User-configurable retention + rolling aggregation for the traffic tables

- **Priority:** Medium · **Depends on:** PKT-00 (bump `version` for the new aggregate entity)
- **Resolves:** F-09
- **Scope note:** per the user instruction, this is no longer "add a pruning job" — the product intent
  has shifted from a simple traffic monitor to a "comprehensive analytics consumer", so raw deletion
  alone would throw away the trend data that a comprehensive analytics view would want to show over
  time. This packet is meaningfully larger than the others in this document and likely deserves its
  own short design pass (or an ADR) before implementation rather than being executed straight from
  this bullet list. What follows is the shape of it, not a final design.
- **Approach — building blocks:**
  1. **New aggregate entity**, e.g. `SessionSummary` (or per-day rollup): stores what a "comprehensive
     analytics" view needs after raw rows are gone — connection count, unique host count, tracker
     count/ratio, total bytes in/out, session duration — keyed by session (or by day, if cross-session
     rollup is wanted). Populate it *before* deleting the raw rows it summarises.
  2. **User-configurable retention policy** — a new `preferences.proto` field (e.g. an enum: keep
     forever / keep N days / keep N sessions) plus a settings UI control, following the existing
     `BooleanPreference`/pattern in `app/ui/scanner/traffic/TrafficScannerPreferences.kt`.
  3. **A periodic `WorkManager` job** (mirroring `ScanWorker`'s existing pattern) that: finds sessions
     older than the configured cutoff, writes their `SessionSummary` row(s), then deletes the
     `Session` row — the existing `CASCADE` chain (`Connection → Request → Response`) removes
     everything beneath it in one delete. The dead `SessionDao.deleteAll`/`delete(id)` methods can be
     revived here instead of written from scratch.
  4. Point any "historical trend" UI at `SessionSummary` and any "recent detail" UI at the raw tables,
     so both survive pruning in the form appropriate to each.
- **Files:** new `entity/SessionSummary.kt` + `dao/SessionSummaryDao.kt`, `dao/SessionDao.kt`, a new
  worker under `app/service/`, `preferences.proto`, `PreferencesDataSource.kt`,
  `app/ui/scanner/traffic/TrafficScannerPreferences.kt`.
- **Tests:** worker test for cutoff arithmetic and cascade-then-summarise ordering; DAO test that a
  `SessionSummary` row's aggregates match a hand-computed sum over the raw rows it replaces.
- **Commit:** `feat(database): add configurable traffic retention with rolling aggregation`

### PKT-08 — User-configurable report retention (latest-only vs. all-time) + SQL-level latest lookup

- **Priority:** Medium · **Depends on:** — (no schema change; behavioural + query change only)
- **Resolves:** F-10, F-11
- **Approach:** two parts. (1) Add a report-retention preference with two values, `LATEST_ONLY` and
  `ALL_TIME` (mirroring the pattern in PKT-07's preference, though this one doesn't need the
  aggregation machinery since a `Report`/`SubReport` row is already a compact summary, not raw
  traffic). In `Evaluator.createReport()`, when `LATEST_ONLY` is selected, delete the package's prior
  `Report` (and, until PKT-04's FK lands, its `SubReport`s explicitly) before inserting the new one;
  under `ALL_TIME`, keep appending as today. (2) Regardless of the mode chosen, add a query returning
  only the latest report per app (window function or correlated subquery) and point the live
  `ScoreViewModel` dashboard at it instead of `getAllAppsWithReportsAndSubReports()` — even in
  `ALL_TIME` mode, the live dashboard wants "current status per app", not full history; full history
  would back a separate, not-yet-built "score history" view.
- **Files:** `dao/ReportDao.kt`, `dao/SubReportDao.kt`, `app/evaluator/Evaluator.kt`,
  `app/ui/evaluator/ScoreViewModel.kt`, `preferences.proto`, `PreferencesDataSource.kt`, a settings row
  for the new preference.
- **Tests:** evaluator test asserting `LATEST_ONLY` keeps exactly one `Report` per app across repeated
  re-scores, and `ALL_TIME` keeps appending; DAO test that the latest-report query returns exactly one
  row per app and picks the newest timestamp regardless of mode.
- **Commit:** `feat(database): make report history retention user-configurable`

### PKT-09 — Projection queries — **deferred**

- **Status:** deferred per user instruction: `DatabaseView` is due for a substantial rework soon, and
  these queries live in exactly the code that rework would touch. Left as-is for this pass; revisit
  F-12 once that rework lands, since the over-fetch may be reshaped or resolved as a side effect of it
  anyway.
- **Resolves (when picked back up):** F-12

### PKT-10 — Fix the N+1 insert, the heavy package-name lookup, and reconcile uninstalled apps

- **Priority:** Medium · **Depends on:** —
- **Resolves:** F-13, F-14, and the `App.isInstalled` half of F-20
- **Approach:** in `ScanWorker.performFullScan()` (`app/service/ScanWorker.kt:130-179`), collect `App`
  rows into a list during the `forEachIndexed` loop and issue one `insertApps(*apps)` call after the
  loop completes, instead of once per app (the `vararg` API already exists — the loop still needs to
  run per-app for permission/library scanning, only the raw `App` upsert is deferred and batched).
  While reworking this loop: the method already computes `existingApps` (from the DB) and iterates
  `packages` (from `PackageManager`) — take the set difference (`existingApps.keys` minus the
  package names seen in this sweep) and mark those as `App.isInstalled = false` via
  `AppDao.updateIsInstalled`, so an app that disappears without the uninstall broadcast being caught
  (`HeimdallBroadcastReceiver.kt:86`) still gets reconciled on the next full scan. Separately, add a
  `suspend fun getAllPackageNames(): List<String>` to `AppDao` and use it in
  `ScoreViewModel.scoreAllApps()` instead of `allApps.first()`.
- **Files:** `app/service/ScanWorker.kt`, `dao/AppDao.kt`, `app/ui/evaluator/ScoreViewModel.kt`.
- **Tests:** existing scan tests; assert scan results unchanged with batched insert; new test asserting
  an app missing from a full-sweep result set is marked `isInstalled = false`.
- **Commit:** `perf(scanner): batch app inserts, avoid loading the report graph for a name list, reconcile uninstalled apps`

### PKT-11 — Type and default consistency

- **Priority:** Low · **Depends on:** PKT-00 (bump `version` — the timestamp/nullability change is a
  schema change; the `flags`/`remoteHost` fixes are not)
- **Resolves:** F-15, F-16, F-17, F-20 (the `remoteHost` half — see PKT-10 for the `isInstalled` half)
- **Approach:**
  - F-15: unify score types on `Double` across `SubReport.score`, `ModuleResult.score`, and anywhere
    else `Float` is used for a score that's summed/averaged with `Report.mainScore`/`weight`.
  - F-16: remove the `CURRENT_TIMESTAMP` column defaults on `Report.timestamp`/`SubReport.timestamp`
    (every insert site already supplies an explicit value) and make `SubReport.timestamp` non-null to
    match `Report.timestamp`.
  - F-17: confirmed exact fix — `LibraryScannerViewModel.kt:127-133` and
    `PermissionScannerViewModel.kt:122-128` both construct `App(...)` without `flags`; add
    `flags = it.applicationInfo?.flags ?: 0`, matching the pattern already used in `ScanWorker.kt:111,160`.
  - F-20 (`remoteHost` only): make `Connection.remoteHost` nullable, so "not yet resolved" (`null`)
    is distinguishable from "resolved, no reverse-DNS name" (empty string) —
    `DatabaseViewModel.kt:83`'s `isNotEmpty()` filter will need the equivalent null-check update.
- **Files:** `entity/SubReport.kt`, `entity/Report.kt`, `entity/Connection.kt`,
  `app/evaluator/ModuleResult.kt`, `app/evaluator/module/Module.kt`,
  `app/ui/scanner/library/LibraryScannerViewModel.kt`,
  `app/ui/scanner/permission/PermissionScannerViewModel.kt`, `app/ui/database/DatabaseViewModel.kt`.
- **Tests:** evaluator scoring tests (assert unchanged scores after the `Float`→`Double` change); scan
  test asserting `App.flags` is now populated from both scanner entry points.
- **Commit:** `refactor(database): unify score types, remove misleading column defaults, populate App.flags consistently`

### PKT-12 — Remove or document unused DAO methods — **deferred**

- **Status:** deferred per user instruction ("leave for now, we can clean up later"). No action this
  pass.
- **Resolves (when picked back up):** F-19. Note PKT-07 will already revive several of the
  `Session`/`Connection` delete methods this packet would otherwise flag — re-run the unused-method
  scan after PKT-07 lands rather than working from Appendix A as-is.

### PKT-13 — Widen all `Int` primary keys to `Long`

- **Priority:** Low · **Depends on:** PKT-00 (bump `version`); coordinate with PKT-01 and PKT-06
  (both touch `Tracker.id`/`AppXTracker.trackerId` in the same window)
- **Resolves:** F-18
- **Approach:** per the user instruction, this is now "all primary keys", not just the high-volume
  traffic ones. `Int` → `Long` for: `Connection.id`, `Request.id`, `Response.id`, `Session.id`,
  and `Tracker.id` — the last one cascades into `AppXTracker.trackerId`, which references it. (
  `Report.reportId` is already `Long`; `App`/`Permission` use natural string keys, out of scope.)
  Touches every signature that passes these ids (`DatabaseConnector`, `RoomDatabaseConnector`, the
  connection classes, view models, `TrackerDao`/`AppXTrackerDao`), so it is mechanical but wide. Do
  this together with PKT-01/PKT-06 for `Tracker`/`AppXTracker` specifically, since all three touch the
  same two entities in the same migration window.
- **Files:** the five entities, all DAOs referencing those ids, `core/vpn/.../components/*`,
  `core/scanner/.../ExodusUpdater.kt`, `core/scanner/.../LibraryScanner.kt`,
  `app/ui/database/DatabaseViewModel.kt`, `app/ui/scanner/traffic/TrafficScannerViewModel.kt`.
- **Tests:** full `core:vpn` suite (it exercises the id plumbing end to end); PKT-01's tracker tests.
- **Commit:** `refactor(database): widen all primary keys to Long`

### PKT-14 — Proper modelling for categorical/enumerable data

- **Priority:** Low · **Depends on:** PKT-00 (bump `version` — new entity + column type changes)
- **Resolves:** F-21
- **Approach:** per the user instruction — "add entities and `TypeConverter` classes for the listed
  categorical data" (`Connection.protocol`, `Response.statusMsg`, `Tracker.categories`). Split by
  actual fit:
  - `Tracker.categories` — genuinely categorical (Exodus returns a fixed, known category list) and
    currently a comma-joined string (`ExodusUpdater.kt:45`). Model properly: a `Category` entity plus
    a `TrackerXCategory` junction table, following the exact pattern already used for
    `Tracker`↔`AppXTracker`. This is the one that most benefits from "entities" (plural).
  - `Connection.protocol` — small closed set (`TCP`/`UDP`), a clean fit for a Kotlin `enum` plus a
    Room `TypeConverter`.
  - `Response.statusMsg` — **flagging a mismatch rather than implementing as instructed**: this is the
    HTTP reason phrase (e.g. `"OK"`, `"Not Found"`), which servers can populate with arbitrary
    non-standard text — it is not a fixed category, it's free text correlated with `statusCode`.
    Converting it to an enum/`TypeConverter` would either lose data (unrecognised phrases) or need an
    open-ended catch-all case that defeats the purpose of enumerating it. Recommend leaving it as
    `String` and treating `statusCode` (already `Int`) as the actual categorical signal; confirm before
    implementing this part.
- **Files:** new `entity/Category.kt`, new `entity/TrackerXCategory.kt`, new `dao/CategoryDao.kt`,
  `core/scanner/.../ExodusUpdater.kt`, `entity/Tracker.kt`, `entity/Connection.kt`, a new
  `TypeConverters` class (none exists in the module today), `core/database/.../HeimdallDatabase.kt`
  (register the converter).
- **Tests:** `ExodusUpdater` test asserting categories round-trip through the new tables; DAO test for
  `Connection.protocol` enum (de)serialisation.
- **Commit:** `feat(database): model tracker categories and connection protocol as proper types`

---

## Appendix A — Unused DAO methods

Verified as having no callers in `app`, `core:vpn` or `core:scanner`.

**Correction from the original pass:** `RequestDao.getAllPaginated` is *not* unused — the original
search didn't cover `core:export`, and `core/export/.../csv/CsvExport.kt:21` calls it directly for CSV
export. Removed from the list below; see PKT-02, which changes this call site anyway.

| DAO | Unused methods |
|---|---|
| `AppXPermissionDao` | `getAppWithPermissions()` (list variant), `getPermissionWithApps`, `getPermissionsWithApps` |
| `AppXTrackerDao` | `getAppsWithTrackers`, `getTrackerWithApps`, `getTrackersWithApps` |
| `ConnectionDao` | `update`, `deleteForApp`, `updateBytesOut`*, `updateBytesIn`*, `getAll` |
| `ReportDao` | `getAll`, `getAllObservable`, `getAllAppsWithReports` |
| `RequestDao` | `update`, `delete`, `getAll`, `getAllObservable` |
| `ResponseDao` | `update`, `delete`, `getAll`, `getAllPaginated`, `getAllObservable` |
| `SessionDao` | `update`, `delete(session)`, `delete(id)`, `deleteAll`, `getAll`, `getAllPaginated`, `getAllObservable` |
| `SubReportDao` | `getAll`, `getSubReportsByPackageName`, `getSubReportsByModule`, `getSubReportsByReportId`, `getAllObservable` |

\* `updateBytesOut`/`updateBytesIn` are presumably intended for byte accounting that was never wired
up — fix PKT-03 before enabling them.

`SubReportDao.getSubReportsByPackageNameAndModule` technically has callers, but only from
`loadSubReportFromDB` in `TrackerScore.kt` and `StaticPermissionsScore.kt`, which are themselves never
called — dead code reachable only through dead code.

Per the "User Instructions" on F-19, this appendix is informational only for this pass — PKT-12 is
deferred, not scheduled.

## Appendix B — Open items

The two open decisions from the original pass are now settled via the "User Instructions" added to
each finding (migration strategy → F-04 / PKT-00; retention → F-09 / PKT-07 and F-10–F-11 / PKT-08).
What remains open, surfaced while adjusting the packets to match those instructions:

1. **PKT-01's cascading re-derivation** — `Connection.isTracker` and the `Tracker`/`AppXTracker`
   catalogue are, today, two unrelated detection mechanisms (hostname trie vs. app-library signatures).
   The instruction to re-derive one from the other's refresh needs a decision on how they should
   relate before it can be implemented as more than a re-run of the existing hostname trie. See
   PKT-01, part 2.
2. **PKT-07's exact retention levers** — which unit(s) to expose (days / session count / both),
   default value, and rollup granularity (per-session vs. per-day) for `SessionSummary`.
3. **PKT-14's `Response.statusMsg`** — flagged as a poor fit for enum/`TypeConverter` modelling (it's
   free text, not a fixed category); confirm whether to leave it as `String` before implementing.
