# Omega Local Console (personal testing only)

Sideload-only Android WebView wrapper for the ESP32 dashboard at `http://192.168.4.1`.
Not for clients. Not for Play Store.

## Use

1. Connect your phone to the device Wi-Fi AP.
2. Open **Omega Local**.
3. It loads `http://192.168.4.1` (change IP in the top bar if needed).

## Build / install

### Android Studio (easiest)

1. Open folder `android-console/` in Android Studio.
2. Wait for Gradle sync.
3. Plug in phone (USB debugging on) **or** use an emulator on the same LAN.
4. Run the `app` configuration (Debug).

### Command line (if SDK + wrapper available)

```bash
cd android-console
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Notes

- Cleartext HTTP is allowed on purpose for local ESP32 testing.
- Login cookies stay in the WebView session.
- Back button goes back in the WebView history.
- Home reloads your saved device URL.
