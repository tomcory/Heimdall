# Automation: capture control, export and host blocking over adb

Heimdall can be driven from a host machine without touching its UI: start and stop a capture, ask
what it is doing, block hosts for a session, and export what was captured. This is what scripted
workflows build on, in Asgard the app driver **Loki**, which starts, stops and exports a capture
around each of its runs. The other components read what Loki puts into its run folders.

Everything here was run on an emulator with Android 13 (API 33). Later Android versions are
untested; see [Prerequisites](#prerequisites).

## Prerequisites

| What | How | Notes |
|---|---|---|
| VPN consent | once in the UI (start the Traffic Scanner and accept the dialog), or `adb shell appops set de.tomcory.heimdall ACTIVATE_VPN allow` | without it a start answers `reason=vpn_consent_missing` |
| CA certificate in the system store | see the README, "Man-in-the-Middle VPN"; the CA can be generated over adb, see [architecture.md](architecture.md#generating-the-ca-via-adb) | only needed to decrypt TLS |
| Heimdall installed and not disabled | `adb install` | the commands work on an app that was never launched or was force-stopped (`-f 0x20`) |

Starting the capture from a broadcast means starting a foreground service while the app is in the
background. Android 13 allows this for a broadcast sent from the shell. If a later version refuses,
the command answers `status=error reason=background_start_not_allowed`; exempting Heimdall from
battery optimisation (`adb shell cmd deviceidle whitelist +de.tomcory.heimdall`) is the documented
way around that restriction and has not been needed so far.

## Commands

All commands are broadcasts to one receiver, which only the shell and the system may call (it is
guarded by `android.permission.DUMP`):

```bash
H="am broadcast -f 0x20 -n de.tomcory.heimdall/.service.CaptureCommandReceiver"
adb shell "$H -a de.tomcory.heimdall.action.START_CAPTURE [extras]"
adb shell "$H -a de.tomcory.heimdall.action.STOP_CAPTURE"
adb shell "$H -a de.tomcory.heimdall.action.CAPTURE_STATUS"
adb shell "$H -a de.tomcory.heimdall.action.EXPORT_CAPTURE [extras]"
```

`am broadcast` prints the answer as `Broadcast completed: result=<code>, data="<answer>"`. The
answer is a list of `key=value` pairs separated by spaces, starting with `status`; no value
contains a space. `result=-1` means the command did what it was asked or there was nothing to do,
`result=0` that it did not.

### START_CAPTURE

| Extra | Meaning |
|---|---|
| `--es tag <label>` | Stored with the session and written into its exports. Letters, digits, `.`, `_`, `:`, `-`; at most 1023 characters |
| `--es apps <pkg,pkg>` | Only these packages are routed through the VPN for this session, whatever the stored monitoring scope says. Every package must be installed |
| `--es block_hosts <host,host>` | Hosts blocked for this session, in addition to the stored block list; see [Host blocking](#host-blocking) |
| `--ez mitm true\|false` | Whether this session decrypts TLS; without it the preference decides |
| `--es quic_policy block\|passthrough` | QUIC policy for this session; without it the preference decides |

The extras apply to the started session only and change no preference.

| Answer | When |
|---|---|
| `status=started session=<id> mitm=<bool> apps=<n> blocked_hosts=<n> [tag=<label>]` | the capture is up; `blocked_hosts` counts the stored list and the session's own |
| `status=starting session=<id>` | not up after 8 seconds; ask `CAPTURE_STATUS` |
| `status=running session=<id> …` (result 0) | a capture is already running; it is left alone |
| `status=error reason=<reason>` (result 0) | `invalid_tag`, `invalid_apps`, `invalid_block_hosts`, `invalid_quic_policy`, `app_not_installed apps=<pkg,…>`, `vpn_consent_missing`, `background_start_not_allowed`, `start_failed` |

### STOP_CAPTURE

| Answer | When |
|---|---|
| `status=stopped session=<id> connections=<n> requests=<n> [tag=<label>]` | the capture is down; the counts are those of the session |
| `status=stopping session=<id>` | not down after 8 seconds |
| `status=idle [last_session=<id>]` | nothing was running |

### CAPTURE_STATUS

`status=idle [last_session=<id>]`, `status=starting …`, `status=stopping …`, or
`status=running session=<id> mitm=<bool> apps=<n> blocked_hosts=<n> since=<epoch ms> [tag=<label>]`.

The state is that of the running app process. After Heimdall's process has been killed it is
`idle`, and `last_session` is gone.

### EXPORT_CAPTURE

| Extra | Meaning |
|---|---|
| `--es session latest\|all\|<id>` | Which session; `latest` (the session started last) by default |
| `--es apps <pkg,pkg>` | Only the traffic of these packages. Does not apply to the database copy |
| `--es formats <list>` | Any of `messages`, `connections`, `sqlite`; `messages,connections` by default |

| Answer | When |
|---|---|
| `status=exported dir=<path> session=<id\|all> [messages=<n>] [connections=<n>]` | the export is complete |
| `status=running dir=<path>` | not complete after 8 seconds; it is once `<path>/manifest.json` exists |
| `status=error reason=<reason>` (result 0) | `invalid_session`, `invalid_apps`, `invalid_formats`, `no_session`, `unknown_session`, `export_failed` |

Every export gets a folder of its own, `<session or "all">-<yyyyMMdd-HHmmss>`, below
`/sdcard/Android/data/de.tomcory.heimdall/files/export/`, which `adb pull` can read. A capture can
be exported while it runs; the export then holds what had been recorded until that moment, and
the manifest says so.

The same export is available in the app: the **Export** button on the Insights tab (the Database
screen) opens a dialog for the sessions and files, and offers to share the result.

## Export files

| File | Content |
|---|---|
| `messages.jsonl` | One JSON object per line: an HTTP request with its response |
| `connections.jsonl` | One JSON object per line: a connection, whether or not its traffic was decrypted |
| `heimdall.sqlite` | A copy of the whole database (all sessions, all apps) |
| `manifest.json` | Written last: backend, Heimdall version, session, tag, session start and end, whether the capture was still running, and per file its size and record count |

Only HTTP/1.1 that Heimdall could read becomes a message: plain HTTP, and TLS that was decrypted.
Everything else appears in `connections.jsonl` only.

### A message

```json
{
  "id": "3-5",
  "time": {"start": 1791804961000, "end": 1791804961120},
  "app": {"package": "com.example.app", "uid": 10180},
  "http_request": {
    "method": "POST", "scheme": "https", "host": "api.example.com", "port": 443,
    "path": "/v1/signup?ref=a",
    "headers": [{"key": "Host", "value": "api.example.com"}, {"key": "Content-Type", "value": "application/json"}],
    "body": "eyJlbWFpbCI6ImphbmVAZXhhbXBsZS5vcmcifQ==",
    "body_encoding": "base64", "body_truncated": false, "content_length": 28
  },
  "http_response": {
    "status": 200, "message": "OK", "headers": [],
    "body": "", "body_encoding": "base64", "body_truncated": false, "content_length": 0
  },
  "connection": {"id": 48, "remote_ip": "93.184.216.34", "remote_port": 443, "local_port": 40000,
                 "security": "TLS", "sni": "api.example.com", "alpn": "http/1.1", "is_tracker": false},
  "capture": {"backend": "heimdall", "version": "0.1", "session": 3, "tag": "baseline-1"},
  "blocked": false
}
```

- `id` is the session id and the request's row id.
- `http_request` has the form in which the other Asgard components read an HTTP message (`method`,
  `path`, `headers` as `key`/`value` pairs, `body`).
- `body` is always Base64 (standard alphabet, padded) of the bytes as they were sent, and
  `body_encoding` always `base64`; an empty body is an empty string. Nothing is decoded on the way:
  the charset of a text body is in its `Content-Type`, and a body sent compressed
  (`Content-Encoding: gzip`, `br`, …) is still compressed. A reader decodes Base64, then the
  content encoding, then the charset.
- `body_truncated` is true if the body was longer than the configured limit ("Largest HTTP body to
  keep"); `content_length` is the length of the whole body in bytes,
  so more than `body` holds in that case.
- `http_response` is `null` if no response was recorded, and `time.end` with it.
- `scheme` is `https` for a decrypted TLS connection, otherwise `http`.
- Times are epoch milliseconds of the device's wall clock. `time.start` is when the first bytes of
  the request arrived from the app, before its body if it has one. `time.end` is when the response
  was complete (for a response whose body runs until the connection closes: when its headers
  were).

### A connection

```json
{
  "id": "3-c48", "time": {"start": 1791804960900},
  "app": {"package": "com.example.app", "uid": 10180},
  "protocol": "TCP", "ip_version": 4, "security": "TLS",
  "host": "api.example.com", "sni": "api.example.com", "alpn": "http/1.1", "ech_offered": false,
  "remote_ip": "93.184.216.34", "remote_port": 443, "local_port": 40000,
  "bytes_out": 512, "bytes_in": 2048, "is_tracker": false,
  "blocked": false, "block_reason": null, "passthrough_reason": null,
  "capture": {"backend": "heimdall", "version": "0.1", "session": 3, "tag": "baseline-1"}
}
```

`block_reason` is `host_rule` (the host is on the block list) or `quic_policy` (HTTP/3 blocked so
that the app falls back to TLS). `passthrough_reason` says why a TLS connection was not decrypted
although MitM was on. DNS lookups (port 53) have no connection record. `time.start` is when the
app's first packet of the connection arrived (the TCP SYN or the first datagram), so it precedes
the handshakes and every request on the connection.

## Host blocking

Hosts on the block list are not reachable for the apps in the capture. The list is the stored one
(Traffic Scanner preferences, "Blocked hosts", separated by commas) plus the `block_hosts` of the
session. It is fixed when the capture starts.

**Matching.** An entry matches its host and every subdomain: `tracker.net` blocks
`cdn.tracker.net` but not `nottracker.net`. Case, a trailing dot and a leading `*.` are ignored.
An IP address matches that address only.

**What happens to a blocked connection.**

| Heimdall learns the name from | Then |
|---|---|
| the DNS cache, when the connection is opened, or the address itself is listed | no socket to the host is opened. TCP: the app's connect is refused at once. UDP: the datagrams are dropped, the first three answered with ICMP port unreachable |
| the TLS ClientHello (server name) | the connection is closed and reset; the ClientHello is not forwarded |
| the QUIC Initial (server name) | the flow's first datagrams are held until the name is read, then dropped as above |

Every blocked connection is recorded with `blocked` and `block_reason = host_rule`, so an export
shows what was blocked.

**Limits.**

- No payload reaches a blocked host, but when only the server name reveals it, the TCP handshake
  with the host has already taken place.
- A plain-HTTP connection to a bare IP address, whose name is only in its `Host` header, is closed
  after its first request has been sent.
- Names are not blocked at DNS level: the lookup itself still succeeds.
- A server name hidden by Encrypted Client Hello cannot be matched; such a connection is only
  blocked through the DNS cache or its address.
- While a block list is set, the first datagrams of every QUIC flow are held until its server name
  is read, which delays QUIC handshakes slightly.
- An app that finds a host unreachable may retry, fall back to another host or fail in other ways.
  The block says nothing about how the app copes.

## Example: one tagged capture of one app

```bash
H="am broadcast -f 0x20 -n de.tomcory.heimdall/.service.CaptureCommandReceiver"
adb shell "$H -a de.tomcory.heimdall.action.START_CAPTURE \
  --es tag baseline-1 --es apps com.example.app --ez mitm true --es block_hosts ads.example.net"
# … drive the app …
adb shell "$H -a de.tomcory.heimdall.action.STOP_CAPTURE"
dir=$(adb shell "$H -a de.tomcory.heimdall.action.EXPORT_CAPTURE" | grep -o 'dir=[^ "]*' | cut -d= -f2)
adb pull "$dir" ./capture-baseline-1
```

With Loki, a section of its configuration makes every run one tagged session, scoped to the app
under test and exported into the run folder:

```yaml
capture:
  backend: heimdall
  mitm: true
  block_hosts: [ads.example.net]
```

Loki sends the commands above, reads every answer (a refusal ends the run with Heimdall's reason),
waits where Heimdall answers `starting`, `stopping` or `running`, pulls the export and checks every
record against its schema in Ratatoskr. `loki capture start|stop|status|export` does the same
without a run. Both are described in `Loki/docs/capture.md`.

A caller of its own, such as a script or one of Loki's hooks, has to read the answers itself: a
command run with `am broadcast` succeeds when the broadcast could be sent, also if Heimdall
answered `status=error`.

## Mapping records to Loki's actions

Loki logs what it did with the host's clock, Heimdall stamps traffic with the device's. Loki
measures the difference at the start and at the end of a run (`run.json → clock`), which is all
that is needed to place both on one time line:

```text
device_ms = epoch_ms(event.ts) − clock.host_minus_device_wall_s · 1000
```

An action's window starts at its `started` time, not at the event's own `ts`, and lasts until the
next action starts. A message belongs to the window that holds its `time.start`, a connection to
the one that holds its `time.start`. The rule in full, with its error bounds and what it cannot
tell (cause, as opposed to time), is in Loki's README under "Mapping traffic to actions".

The device's wall clock can be set while a capture runs (network time, a restored emulator
snapshot). Heimdall's times then jump with it. Loki's `clock.drift_s` shows that it happened.
