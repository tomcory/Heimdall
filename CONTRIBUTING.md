# Contributing to Heimdall

Thanks for your interest in contributing! This document covers how to get a development build running, how the codebase is organized, and what to keep in mind when opening a pull request.

## Development setup

1. Clone the repository:
   ```bash
   git clone https://github.com/tomcory/heimdall.git
   ```
2. Open the project with Android Studio.
3. Build and run:
   ```bash
   ./gradlew assembleDebug          # Build debug APK
   ./gradlew test                   # Run unit tests
   ./gradlew connectedAndroidTest   # Run instrumentation tests (requires device/emulator)
   ```

No API keys, extra signing configs, or submodules are required to build.

**Requirements**: Android SDK 24+ (min), 36 (target/compile), JDK 17. CI runs `./gradlew build` on JDK 17/macOS for every push and PR to `main` (`.github/workflows/android.yml`).

## Codebase orientation

Heimdall is a multi-module Android project — `app/` plus several `core/*` library modules (database, scanner, vpn, proxy, util, export, datastore, datastore-proto). See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full breakdown of modules, the MVVM/Hilt architecture, the VPN/MitM packet pipeline, and the database schema. The VPN/MitM engine specifically has its own deep-dive at [`core/vpn/README.md`](core/vpn/README.md).

## Adding a new privacy-score module

Scoring is pluggable: `Evaluator` (`app/src/main/java/de/tomcory/heimdall/evaluator/Evaluator.kt`) iterates over `Module` implementations and computes a weighted average from their results. To add a new scoring axis, implement the abstract `Module` class (`app/src/main/java/de/tomcory/heimdall/evaluator/module/Module.kt`):

```kotlin
abstract suspend fun calculateOrLoad(app: App, context: Context, forceRecalculate: Boolean): Result<ModuleResult>
abstract fun BuildUICard(report: ReportWithSubReports?)   // Composable
abstract fun exportToJsonObject(subReport: SubReport?): JsonObject
```

Look at `StaticPermissionsScore`, `TrackerScore`, or `PrivacyPolicyScore` for reference implementations.

## Pull requests

- Keep PRs focused — one feature or fix per PR is easier to review than a bundle of unrelated changes.
- Make sure `./gradlew build` passes locally before opening a PR; CI will run the same check.
- If your change affects behavior described in the README or `docs/ARCHITECTURE.md`, update those docs in the same PR.
- For bug reports or feature requests that aren't ready as a PR, open an [issue](https://github.com/tomcory/Heimdall/issues) instead.
