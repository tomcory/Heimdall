# Heimdall UI Redesign — Design Document

## Overview

A full redesign of the Heimdall Android UI. The goal is to replace a sparse, utilitarian interface with one that is modern, adaptive, technically-flavoured, and information-rich — without sacrificing the clarity that a privacy/network analysis tool requires.

**Implementation order:** Scaffold first (theme → navigation → splash), then tab-by-tab: Score → Scanner → Database.

---

## 1. Visual Design Language

### 1.1 Aesthetic Direction

Modern and adaptive (full dark/light mode support), with material depth through layered surfaces. The aesthetic reads as a technical instrument — purposeful density, not decoration. Think modern network monitor or terminal emulator, not consumer lifestyle app.

### 1.2 Color System

**Base palette — monochromatic:**
- Near-black surfaces in dark mode, near-white in light mode
- A single accent color for interactive elements (buttons, highlights, links)
- Minimal use of color outside of the semantic risk system

**Semantic risk colors — used consistently throughout all three tabs:**

| Risk Level | Color | Usage |
|---|---|---|
| High | Red (`#BA1A1A` / light-mode equivalent) | Section headers, ring segments, tracker badges, row tints |
| Medium | Amber (current orange secondary) | Section headers, ring segments, warning chips |
| Low | Green (current green tertiary) | Section headers, ring segments, safe indicators |
| Neutral / Unknown | `onSurfaceVariant` | Unscanned apps, missing data |

Color carries meaning throughout the app. If something is colored, it indicates risk level — nothing else. Decorative color use is avoided.

### 1.3 Typography

Two-font system:

| Font | Use cases |
|---|---|
| System font (Roboto / device default) | All UI chrome: labels, headings, body text, navigation, descriptions |
| Monospace (JetBrains Mono or Roboto Mono) | All data: hostnames, IP addresses, package names, HTTP paths, byte counts, timestamps, score values |

The monospace font signals "instrument" and distinguishes raw data from UI scaffolding at a glance.

Apply the full Material 3 type scale intentionally: clear distinction between `displaySmall`, `titleLarge`, `bodyMedium`, `labelSmall`. Tighter tracking on headings. Tabular figures (`tnum`) on all numeric data.

### 1.4 Surfaces and Elevation

Use Material 3 surface tiers (`surface`, `surfaceContainer`, `surfaceContainerHigh`) to create visual depth:
- Background: `surface` (darkest in dark mode)
- Cards and list items: `surfaceContainer`
- Elevated sheets and dialogs: `surfaceContainerHigh`
- No hard outlines on cards — use surface elevation difference instead

### 1.5 Animation System

Three tiers, applied as a unified system:

**Tier 1 — Functional (all state changes):**
Every state change that would otherwise feel jarring is animated: list expand/collapse, button state changes (VPN start/stop), tab content swaps, filter application. Default: `tween(200ms, EaseInOut)`.

**Tier 2 — Data-driven (live elements):**
Live data elements animate to reflect system state. Connection counts tick up with each new entry. The risk ring fills on load. Byte counters animate to new values. Chart lines draw in as data arrives. These animations make the app feel alive when the VPN is active.

**Tier 3 — Expressive springs (key moments):**
Reserved for three high-impact transitions:
1. Risk ring filling on Score tab load
2. App row expanding into a detail card
3. VPN activation — the Scanner tab transforms from idle to live dashboard

Use `spring(dampingRatio = 0.7, stiffness = 300)` for these. Do not overuse; the impact comes from selectivity.

---

## 2. Navigation Shell

### 2.1 Bottom Navigation Bar

Material 3 `NavigationBar` with the following refinements:
- Darker surface color than the default — use `surfaceContainer` not `surface`
- Pill indicator on the selected item (the standard M3 `NavigationBarItem` indicator), not a full-width container highlight
- Icon set reviewed for distinctiveness — all three icons must be immediately differentiable at a glance
- Labels always visible (not icon-only — accessibility requirement)

**Adaptive layout groundwork:**
- Extract navigation destinations into a shared `NavigationConfig` structure
- `MainScreen` detects window size class and renders `NavigationBar` (compact) or `NavigationRail` (medium/expanded)
- No functional tablet UI in v1, but the switch point is wired so it can be filled in later

### 2.2 Three Tabs

| Tab | Route | Purpose |
|---|---|---|
| Scanner | `scanner` | Live monitoring dashboard + scan controls |
| Score | `score` | Device privacy posture + per-app risk analysis |
| Database | `database` | Traffic analytics + raw connection inspector |

---

## 3. Splash Screen

Replace the current custom splash composable with the Android 12+ Splash Screen API (`androidx.core:core-splashscreen`).

- The system handles logo display and the launch animation
- No custom progress bar or percentage on the splash — remove the blocking overlay entirely
- On the main screen, data that is still loading shows **skeleton placeholders** (animated shimmer using `Brush.linearGradient`) in the appropriate positions within each tab
- Scan progress feedback moves to the Scanner tab's idle state (see §4.3), not a blocking overlay

---

## 4. Scanner Tab

### 4.1 Two States

The tab has two distinct states with a smooth animated transition between them (Tier 3 spring + crossfade):

| State | Condition | Bottom section content |
|---|---|---|
| **Idle** | VPN inactive, no scan running | Last session summary + contextual nudges |
| **Live** | VPN active | Real-time connection chart + grouped connection feed |

### 4.2 Persistent Control Strip (always visible, top section)

Three compact status rows, one per scanner:

```
[ VPN ]         Active · 00:14:32          [■ Stop ]
[ Permissions ] Last scanned: 2h ago       [↺ Scan ]
[ Libraries ]   Last scanned: 3 days ago   [↺ Scan ]
```

- Each row shows scanner name, current state/last-updated time (monospace), and an inline action button
- VPN row shows elapsed session timer when active (monospace, ticking — Tier 2 animation)
- Tapping the VPN row's action button starts or stops the capture
- VPN mode selector (Off / VPN / Proxy) appears as a compact segmented control *within* the VPN row when inactive; collapses when active

### 4.3 Idle State (bottom section)

**Last session summary card:**
- Session duration, total connections, unique remote hosts, tracker connection count
- All numeric values in monospace
- Subtle `surfaceContainer` card with no border

**Contextual nudges:**
- If permissions last scanned > 24h ago: "Permissions scan is stale — rescan?" with inline action
- If library scan last scanned > 7 days ago: same pattern
- If no VPN session ever recorded: "Start the VPN to begin monitoring"
- At most two nudges shown at once, ordered by staleness

### 4.4 Live State (bottom section)

**Real-time connection chart (hero element):**
- Line chart showing connection count per second over a rolling 60-second window
- Rendered using Vico (`CartesianChartHost`)
- Chart draws in as data arrives — Tier 2 animation
- Tracker connections plotted as a second line in the High risk color (red), total connections in the accent color
- Chart height: ~160dp; does not scroll with the list below

**Grouped connection feed (below chart):**
- Live list of apps currently making connections
- Each group: app icon + app name as section header
- Under each header: hostname rows (monospace), protocol badge, bytes out/in (monospace), tracker badge (red `●` if `isTracker = true`)
- New entries animate in from the top (Tier 1 fade + slide)
- Tracker-flagged hostnames get a subtle red tint on the row background
- Feed is scrollable independently of the chart

---

## 5. Score Tab

### 5.1 Overall Structure

Three-level progressive disclosure:

```
[ Device risk summary — always visible ]
[ Sectioned app list ]
  Section: High Risk
    [ Compact row ]        ← default
    [ Expanded card ]      ← tapped
  Section: Medium Risk
    ...
  Section: Low Risk
    ...
  Section: Unknown
    ...
```

### 5.2 Device Risk Summary (top, non-scrolling)

**Risk ring (hero element):**
- A segmented arc ring (not a continuous gradient) divided into High / Medium / Low / Unknown segments, sized proportionally to the number of apps in each category
- Fills on tab load — Tier 3 spring animation
- Center text: total app count in large monospace type, "apps analysed" label below in `labelSmall`

**Stat chips (below ring, horizontal row):**

| Chip | Value | Tap action |
|---|---|---|
| Trackers | Total unique trackers detected across all apps | Filters list to apps with tracker count > 0 |
| Dangerous permissions | Total dangerous permissions granted across all apps | Filters list to apps with dangerous permissions > 0 |
| Last scanned | Timestamp of most recent scan (monospace) | Triggers a full rescan |

- Active filter state: chip gets accent-color outline and a dismiss `×` icon
- Only one filter active at a time
- Filter applies with Tier 1 animated list recomposition

### 5.3 App List — Compact Row (default)

Sectioned by risk level: **High Risk** → **Medium Risk** → **Low Risk** → **Unknown**. Section headers use the corresponding semantic risk color.

Each compact row contains:
- App icon (40dp)
- App label (`bodyMedium`, system font)
- Score indicator: a small filled circle in the semantic risk color, plus the numeric score in monospace (`labelMedium`)
- Chevron `›` indicating expandability

No package name in the list — it belongs in the detail view.

### 5.4 App List — Expanded Card (tapped)

Tapping a compact row expands it in-place into a card (Tier 3 spring animation). The card shows:

**Module score chips (horizontal row):**
- Permissions: score value (monospace) + risk color dot
- Trackers: score value (monospace) + risk color dot + tracker count
- Privacy Policy: score value (monospace) + risk color dot

**Quick action buttons (bottom of card):**
- `Rescan` — triggers re-evaluation for this app only
- `Export` — exports this app's report
- `View full report` — navigates to the full detail screen

Tapping elsewhere on the card (or the chevron again) collapses it with the reverse animation.

### 5.5 Full Detail Screen (AppScoreScreen)

Revamped to match the new design system but retains its full content. Key changes:
- Replace the current arc chart with the same segmented ring used in the summary
- Module cards use `surfaceContainer` elevation, monospace for all numeric values
- Action menu (rescan, uninstall, export, feedback) moves to a top-bar overflow menu
- Typography and color system aligned with the rest of the redesign

---

## 6. Database Tab

### 6.1 Overall Structure

Two-section layout, both always visible:

```
[ Analytics section — fixed height, non-scrolling ]
[ Filter bar ]
[ Raw connection log — scrollable ]
```

### 6.2 Analytics Section

Three charts in a horizontal pager or fixed grid:

| Chart | Type | Content |
|---|---|---|
| Connection timeline | Line chart (Vico) | Total connections per minute over last session |
| Top apps | Horizontal bar chart | Top 5 apps by connection count |
| Top tracker domains | Horizontal bar chart | Top 5 tracker hostnames by hit count, in risk red |

Charts use the semantic color system. Tracker-specific data always in the High risk color.

### 6.3 Filter Bar

A compact horizontal chip row below the analytics section:
- `All` · `Trackers only` · filter by app (app picker) · filter by protocol (TCP / UDP)
- Active filters shown as filled chips with dismiss `×`
- Filters compose (e.g. "Trackers only" + specific app)

### 6.4 Raw Connection Log

Scrollable list of `Connection` rows:
- App icon + app label
- Remote hostname (monospace) + protocol badge
- Bytes out / in (monospace)
- Tracker badge (red `●` if `isTracker`)
- Timestamp (monospace, relative: "2m ago")

Tapping a connection row expands an inline detail view showing:
- Full remote host + port (monospace)
- All associated `Request` rows (method + path, monospace)
- Each request expandable to show headers and response status

If no MitM data is available (VPN-only mode), request/response rows are absent and a note explains why.

---

## 7. Implementation Plan

### Phase 1 — Scaffold (prerequisite for all tabs)

1. Migrate to Android 12+ Splash Screen API; remove `SplashScreen.kt` composable and `showSplashScreen` overlay logic from `MainActivity`
2. Add skeleton loading composables (shimmer brush utility)
3. Establish new `Color.kt`: monochromatic base + semantic risk tokens (`riskHigh`, `riskMedium`, `riskLow`, `riskUnknown`)
4. Update `Theme.kt` to apply new color scheme in light and dark modes
5. Add JetBrains Mono (or Roboto Mono) to `res/font/`; update `Type.kt` with two-font system
6. Define animation constants (`AnimationSpec` values for all three tiers) in a shared `Animation.kt`
7. Refactor `MainScreen.kt` to detect window size class and conditionally render `NavigationBar` vs `NavigationRail`
8. Restyle `BottomNavigationBar.kt`: surface color, pill indicator, updated icon set

### Phase 2 — Score Tab

In order: device risk summary → sectioned list with compact rows → expand-in-place card → full detail screen revamp.

### Phase 3 — Scanner Tab

In order: persistent control strip → idle state (last session summary + nudges) → live state (chart + grouped feed).

### Phase 4 — Database Tab

In order: analytics charts → filter bar → raw connection log → inline request/response detail.
