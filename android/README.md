# GenADB Android companion (scaffold)

The phone side of New-GenADB. A foreground service runs the Go connectivity core (`../core`, packaged as `libgenadb.so`) as `genadb device …`. It folds the agent's JSON events into UI state.

| Module | What | Builds without Android SDK? |
|---|---|---|
| `agent-protocol` | Pure-Kotlin bridge: `DeviceAgentConfig.toArgs()`, `AgentEvent.parse`, `AgentState.reduce` | yes: `gradle :agent-protocol:test` |
| `app` | Android app: `AgentService` (foreground, specialUse), `MainActivity` (Compose status screen), EMM managed config (`app_restrictions.xml`) | needs `ANDROID_HOME` |

`app:preBuild` cross-compiles the Go core:
- `arm64-v8a`: `GOOS=android GOARCH=arm64`
- `x86_64`: `linux/amd64`, used for emulators

The output goes to `src/main/jniLibs/<abi>/libgenadb.so`. `useLegacyPackaging` keeps the binary extracted, so the service can exec it from `nativeLibraryDir`.

## Behaviour wired in
- **Solo mode:**
  - The service passes `--adbd auto`, so the agent discovers the dynamic Wireless-debugging port by mDNS while holding a `MulticastLock`.
  - It passes `--lan-listen 0.0.0.0:47100` for the direct LAN path.
  - The pairing code is shown in the notification and on screen.
- **Corporate mode:**
  - It starts automatically when EMM pushes `enroll_token`, `policy_json` and `relay_url` as managed configuration.
  - `UserManager.DISALLOW_DEBUGGING_FEATURES` is mapped to `--debug-policy disallowed`. The agent then refuses to tunnel.
- **Agent restarts:** if the agent dies (for example from OEM battery management), it restarts with exponential backoff.

## Not yet verified
This module was written without an Android SDK, so it has never been compiled or run on a device. Still to do:
- Compile against the SDK.
- Check the notification and foreground-service-type policy on Android 14+.
- Exempt the app from MIUI/OEM battery optimisation.
- Pass the `adbd` endpoint discovered by NsdManager to the agent where multicast is filtered.
- Write the pairing UX for `adb pair` through the tunnel.
