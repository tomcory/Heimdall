# Heimdall
## _The Android HTTPS monitoring toolkit_

Heimdall is an HTTP traffic monitoring tool which uses the Android VPN API to intercept the transport-level traffic of installed apps.

Intercepted traffic is stored in a local SQLite Database. You can export the SQLite database file with the Device File Explorer bundled with Android Studio. The database file is located at `/data/data/de.tomcory.heimdall/databases/`. Use a SQLite database browser of your choice to open and browse the exported database

## License

Copyright 2021 Thomas Cory

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.