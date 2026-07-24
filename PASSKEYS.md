# Passkey Implementation Notes

This document records interoperability and Android Credential Manager invariants that must remain
true when changing the passkey implementation.

## Compatibility Boundary

Passkey credential files are shared with
[passless](https://github.com/pando85/passless). Treat their encrypted CBOR representation as an
external format:

- Do not rename, remove, reinterpret, or add required CBOR fields without coordinating the format
  with passless and adding cross-implementation test vectors.
- Do not migrate or rewrite credential files merely to provide Android UI metadata.
- Existing credentials may omit newer optional binding fields. Readers must continue applying the
  documented defaults.
- Signature-counter updates are the only normal assertion-time credential rewrite.

The Android provider currently reads account labels from an existing encrypted credential when the
file-system metadata has empty names. This happens in memory, and the `SensitivePasskeyCredential`
is immediately closed so its private-key bytes are wiped. It does not alter the CBOR or ciphertext.

## OpenPGP Files

Passkey `.gpg` files are binary OpenPGP by default. ASCII armor is optional and must not be assumed.

- Never call `decodeToString()` on ciphertext. A UTF-8 round trip corrupts binary packet headers.
- APIs that inspect OpenPGP messages must receive the original `InputStream` or bytes.
- Tests must cover binary ciphertext produced with the production encryption options, not only
  ASCII-armored fixtures.

## Caller Verification

Native Android applications and privileged browsers use different trust paths.

### Digital Asset Links Relation Policy

Each `AssetLinkCapability` maps to exactly one DAL relation. Passkey ceremonies require the
`PASSKEY_CEREMONY` capability, which maps to `delegate_permission/common.handle_all_urls`. The
`get_login_creds` relation alone **cannot** authorize a passkey create or get request.

| Capability               | Required relation                                      |
|--------------------------|--------------------------------------------------------|
| `PASSKEY_CEREMONY`       | `delegate_permission/common.handle_all_urls`           |
| `LOGIN_CREDENTIAL_ACCESS`| `delegate_permission/common.get_login_creds`           |

The `authorizesAndroidApp()` function requires an explicit `AssetLinkCapability` parameter. Do not
reintroduce a generic matcher that silently treats both relations as interchangeable.

Example `assetlinks.json` for passkey authorization:

```json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.app",
    "sha256_cert_fingerprints": [
      "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
    ]
  }
}]
```

### General Rules

- Android app targets contain the plural array `sha256_cert_fingerprints`.
- Browser origins must be obtained through `CallingAppInfo.getOrigin()` with valid AndroidX
  privileged-allowlist JSON. Passing an empty string is invalid.
- Browser package names and release certificate SHA-256 pins are both security-sensitive. Never add
  guessed or placeholder pins. Verify pins from an official APK or publisher source.
- Canonicalize a framework-verified web origin before putting it in `clientDataJSON`. For example,
  `https://github.com/` and `https://github.com:443` become `https://github.com`.
- Request JSON `origin` values are untrusted and must never override framework verification.

## Discoverable Credentials

A usernameless WebAuthn request has an empty `allowCredentials` array. The provider must return all
discoverable credentials matching the RP ID and include the selected credential's `userHandle` in
the assertion response.

Android's `PublicKeyCredentialEntry.username` is also its grouping/deduplication identity:

- Use the account username as `username`; use the human display name only as the subtitle.
- Two accounts with the same display name must remain separate entries.
- Disable auto-selection when more than one candidate matches.
- Give every entry a unique `PendingIntent` identity. Intent extras do not participate in
  `PendingIntent` equality, so the credential ID is also encoded in the intent data URI.
- File-only metadata intentionally has blank account labels. Load labels from the encrypted
  credential in memory rather than changing the shared CBOR format.

## Regression Tests

The dedicated passkey CI job runs tests for these boundaries:

- Digital Asset Links JSON parsing and package/certificate matching
- AndroidX browser privileged-allowlist generation and verified certificate pins
- canonical web origins and RP ID validation
- binary OpenPGP recipient inspection
- empty-allow-list discoverable credential enumeration
- assertion `userHandle` encoding
- identity hydration from encrypted/file-only metadata
- account grouping, multi-account auto-selection, and unique pending-intent identities

Run the same suite locally with:

```bash
./gradlew :passkeys:core:test \
  :passkeys:provider:testDebugUnitTest \
  :crypto:pgpainless:test \
  :app:testDebugUnitTest
```

## Device Verification

Unit tests cannot fully model OEM Credential Manager UI. Before releasing changes to provider
entries or caller verification, test on a physical Android device with debug logging enabled:

1. An explicit assertion with a non-empty `allowCredentials` list.
2. A usernameless assertion with an empty `allowCredentials` list.
3. Two accounts for the same RP, including accounts sharing a display name.
4. At least one pinned Chrome build and one pinned Firefox build.
5. A credential created by the previous release and a credential produced by passless.

Capture package-scoped logs with `adb logcat --uid=<app uid> -v threadtime`. Logs must not include
credential IDs, challenges, user handles, private keys, or decrypted CBOR.

## USB Debugging With The F-Droid-Signed App

Android only permits an APK to update an installed app when both APKs use the same application ID
and signing certificate. For this repository, the F-Droid-compatible signing material is stored in
`pass` at:

```text
personal/fdroid/android-password-store
```

The first line is the keystore password. The entry also contains `keyAlias: release`, followed by a
base64-encoded keystore after the `--- keystore.jks ---` marker. Never print this entry in issue
reports, CI logs, or shared terminal transcripts.

From the repository root, materialize the ignored signing files locally:

```bash
install -m 600 /dev/null keystore.jks
pass show personal/fdroid/android-password-store \
  | sed -n '/^--- keystore.jks ---$/,$p' \
  | tail -n +2 \
  | base64 -d > keystore.jks

store_password="$(pass show personal/fdroid/android-password-store | sed -n '1p')"
install -m 600 /dev/null keystore.properties
{
  printf 'storeFile=keystore.jks\n'
  printf 'storePassword=%s\n' "$store_password"
  printf 'keyAlias=release\n'
  printf 'keyPassword=%s\n' "$store_password"
} > keystore.properties
unset store_password
```

Verify that the extracted key is the expected F-Droid-compatible certificate before building:

```bash
keytool -list -keystore keystore.jks
```

Its SHA-256 certificate fingerprint must be:

```text
D7:57:11:D7:DA:9C:8E:EC:A9:D0:4E:51:C4:EB:5D:4D:7E:3D:B7:4B:C1:8E:A5:0E:26:2C:0A:74:9E:3C:50:F8
```

Build the normal minified signed release and collect the consistently named APK:

```bash
./gradlew :app:assembleRelease :app:collectReleaseApks
```

Confirm the phone is authorized, verify the APK certificate, and update the installed app without
clearing its data:

```bash
adb devices -l
"$ANDROID_HOME/build-tools/36.0.0/apksigner" verify --print-certs \
  app/build/outputs/apk/release/app-release.apk
adb install -r app/build/outputs/apk/release/app-release.apk
```

For release builds, enable **Settings → Miscellaneous → Enable debug logging** and restart the app.
Find the app UID and capture only this app's logs:

```bash
app_uid="$(adb shell dumpsys package app.passwordstore.pando85 \
  | sed -n 's/.*appId=\([0-9]*\).*/\1/p' \
  | sed -n '1p')"
adb logcat -c
adb logcat --uid="$app_uid" -v threadtime > aps-logcat.txt
```

Reproduce one operation at a time, stop capture with `Ctrl-C`, and inspect errors without publishing
the full log blindly:

```bash
rg -i 'fatal|exception|error|fail|passkey|credential|webauthn' aps-logcat.txt
```

When debugging is complete, remove materialized secrets and the local log:

```bash
rm -f keystore.jks keystore.properties aps-logcat.txt
```

`keystore.jks` and `keystore.properties` are gitignored, but they should still be deleted promptly.
