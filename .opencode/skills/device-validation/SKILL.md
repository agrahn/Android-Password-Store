---
name: device-validation
description: Build, install, and validate release builds on a physical Android device via ADB. Use when the user asks to test on device, validate a release, or debug runtime issues on their phone.
---

## When to use

- User asks to "test on my phone", "validate the release", "install and test"
- User wants to debug runtime issues that only appear in release builds
- User wants to upgrade the F-Droid/production version with a locally built release

## Prerequisites

- Physical device connected via USB with ADB enabled
- `pass` CLI configured with the signing key at `personal/fdroid/android-password-store`

## Step 1: Verify Device Connection

```bash
adb devices
```

Confirm the device appears with status `device` (not `unauthorized`).

## Step 2: Set Up Signing

The release keystore is encrypted. Extract it from `pass`:

```bash
# Extract keystore.jks (base64-encoded after the marker line)
pass personal/fdroid/android-password-store | sed -n '/^--- keystore.jks ---$/,$ p' | tail -n +2 | base64 -d > keystore.jks

# Create keystore.properties from pass metadata
cat > keystore.properties <<EOF
keyAlias=release
keyPassword=$(pass personal/fdroid/android-password-store | head -1)
storeFile=keystore.jks
storePassword=$(pass personal/fdroid/android-password-store | head -1)
EOF
```

The pass entry format:
- Line 1: encryption key / key password (same value)
- `keyAlias:` field
- `keyPassword:` field
- `cert SHA-256:` field
- `applicationId:` field
- `--- keystore.jks ---` marker followed by base64-encoded JKS

**Important:** The `scripts/signing-setup.sh` uses openssl with a CI-only key and will NOT work locally. Always extract from `pass` directly.

## Step 3: Check Installed Version

```bash
# Check if the app is already installed (F-Droid or previous build)
adb shell dumpsys package app.passwordstore.pando85 | grep -E "versionName|versionCode|signatures"
```

The release build uses applicationId `app.passwordstore.pando85` (no suffix). The debug build uses `app.passwordstore.pando85.debug`.

## Step 4: Build and Install

### For validation (non-minified, with logs):

```bash
DISABLE_MINIFY=1 ./gradlew app:installRelease
```

This produces a release-signed APK with the same applicationId as F-Droid but WITHOUT R8 minification, so `logcat` output is preserved. Use this for debugging.

### For production-equivalent testing (minified):

```bash
./gradlew app:installRelease
```

This is identical to what F-Droid/CI produces. Logs will be stripped by R8.

### Uninstall debug build first (if present):

```bash
adb uninstall app.passwordstore.pando85.debug
```

## Step 5: Capture Logs

```bash
# Clear previous logs
adb logcat -c

# Launch the app
adb shell monkey -p app.passwordstore.pando85 -c android.intent.category.LAUNCHER 1

# Wait for app to start, then capture
sleep 2
PID=$(adb shell pidof app.passwordstore.pando85)

# Capture all logs from the app PID to a file (background)
adb logcat --pid=$PID -v time > /tmp/opencode/aps-logs.txt 2>&1 &
```

**Key insight:** If the app restarts (crash, process death), the PID changes and log capture stops. Re-fetch the PID if logs appear empty.

### Broader capture (if PID-filtered logs are empty):

```bash
adb logcat -v time -s "BiometricAuthenticator:*" "PasswordStore:*" "APS:*" "AndroidRuntime:*" "ActivityTaskManager:*" "*:E" > /tmp/opencode/aps-tagged-logs.txt 2>&1 &
```

### Grep for app-specific entries:

```bash
adb logcat -d -v time | grep -i "passwordstore\|pando85" | tail -100
```

## Step 6: User Testing Loop

1. Tell the user to enable debug mode in app settings (if available)
2. Ask the user to reproduce the reported issues
3. Wait for user confirmation ("done")
4. Kill the background logcat process: `kill %1`
5. Read and analyze the log file

## Step 7: Analyze Logs

Look for:
- `E/AndroidRuntime` — uncaught exceptions / crashes
- `BiometricAuthenticator` — auth flow errors (error codes, messages)
- `KeyStore` / `AndroidKeyStore` — key invalidation after upgrade
- `Fragment` / `Activity` — navigation failures
- `SecurityException` — permission or signature issues

## Step 8: Fix and Iterate

1. Create a fix branch: `git checkout -b fix/<issue-description>`
2. Make code changes
3. Rebuild and reinstall: `DISABLE_MINIFY=1 ./gradlew app:installRelease`
4. Repeat from Step 5

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| `signing-setup.sh` fails with "bad decrypt" | CI-only encryption key | Extract keystore from `pass` directly (Step 2) |
| Logs are empty / no app entries | R8 stripped log calls | Use `DISABLE_MINIFY=1` build |
| PID is empty when capturing | App not running yet | Launch app first with `monkey` command |
| Logs stop mid-session | App crashed/restarted | Re-fetch PID and restart capture |
| Install fails with signature mismatch | Different signing key than installed version | Uninstall first: `adb uninstall app.passwordstore.pando85` |
| Auth fails after upgrade | AndroidKeystore keys invalidated by signing cert change | Expected if signing key differs; app should fall back to passphrase |
| `installFreeDebug` task not found | No product flavors in this fork | Use `app:installDebug` or `app:installRelease` |

## Key Files

| File | Role |
|------|------|
| `keystore.jks` | Release signing key (extracted from pass, gitignored) |
| `keystore.properties` | Signing config for Gradle (gitignored) |
| `secrets/keystore.cipher` | CI-encrypted keystore (not usable locally) |
| `scripts/signing-setup.sh` | CI-only signing setup (requires CI encryption key) |
| `scripts/signing-cleanup.sh` | Removes keystore.jks and keystore.properties |
| `build-logic/.../signing/AppSigning.kt` | Reads keystore.properties for build signing |
| `build-logic/.../ApplicationPlugin.kt` | DISABLE_MINIFY env var disables R8 |

## Cleanup

After validation is complete:

```bash
./scripts/signing-cleanup.sh
```

This removes `keystore.jks` and `keystore.properties` from the working tree.

## Architecture Notes

- **ApplicationId:** `app.passwordstore.pando85` (release), `app.passwordstore.pando85.debug` (debug)
- **Signing:** All build types use the release key when `keystore.properties` exists
- **Minification:** R8 with `-dontobfuscate` — class names preserved, but log calls may be stripped
- **Logging library:** `logcat` (square/logcat) — calls are stripped by R8 in minified builds
- **Auth flow:** `LaunchActivity` → `BiometricAuthenticator` → `PasswordStore` / `DecryptActivity`
- **Password selection:** `PasswordFragment` → `SearchableRepositoryAdapter` click → `PasswordStore.decryptPassword()` → `DecryptActivity`
