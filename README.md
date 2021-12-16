# Heimdall
## _The Android HTTPS monitoring toolkit_

Heimdall is an HTTP traffic monitoring tool which uses the Android VPN API to intercept the transport-level traffic of installed apps.

Intercepted traffic is stored in a local SQLite Database. You can export the SQLite database file with the Device File Explorer bundled with Android Studio. The database file is located at `/data/data/de.tomcory.heimdall/databases/`. Use a SQLite database browser of your choice to open and browse the exported database