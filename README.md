# Password Store

Password Store is a [`pass`](https://www.passwordstore.org/)-compatible **password** manager, **passkey** credential provider and **autofill** service for Android.

As a credential provider, it can respond to passkey creation and authentication requests from browsers and native apps. Supported **passkey types** are **EdDSA (Ed25519)**, **ES256**, and **RS256**. Passkey functionality is available on devices with Android 14 and above.

Forked from the archived [Password Store](https://github.com/android-password-store/Android-Password-Store) project.

[![GitHub workflow](https://github.com/agrahn/Android-Password-Store/workflows/Deploy%20snapshot%20builds/badge.svg)](https://github.com/agrahn/Android-Password-Store/actions)

## Download

[<img src="https://github.com/machiav3lli/oandbackupx/blob/034b226cea5c1b30eb4f6a6f313e4dadcbb0ece4/badge_github.png"
    alt="Get it on GitHub"
    height="60">](https://github.com/agrahn/Android-Password-Store/releases)
[<img src="https://fdroid.gitlab.io/artwork/badge/get-it-on.svg"
    alt="Get it on F-Droid"
    height="60">](https://f-droid.org/en/packages/app.passwordstore.agrahn)

Latest [snapshot build (APK)](https://github.com/agrahn/Android-Password-Store/releases/tag/latest) of this fork

Verification info:

- Package ID: `app.passwordstore.agrahn`
- SHA-256 hash of signing certificate (GitHub relases): `CA:3A:D7:C5:F9:90:BF:82:57:7C:EC:3B:9F:F9:E5:DB:C1:7E:05:2F:AB:C3:C7:58:8A:48:92:C4:15:67:12:90`

## Documentation

The original documentation can be found [here](https://docs.passwordstore.app) and [there](https://github.com/android-password-store/Android-Password-Store/wiki/).

To activate passkey (Android 14+) and autofill support, go to Settings → Autofill & Passkeys and choose Password Store as your preferred service. For Chrome and Chromium-based browsers, you might additionally need to enable "Autofill using another service" within the browser's own settings.

Utilising the standard `pass` file structure, passkey data is stored on the first line, followed by optional extra content, as line-oriented plain text secured by PGP encryption. Details on passkey encoding and storage are given in file [`PasskeyStorage.md`](PasskeyStorage.md).

## How-To: Transfer a PGP key to Password Store securely

### From GPG keyring
````bash
gpg --armor --gen-random 1 24 # generate a strong random password; use it in the next step
gpg --armor --export-secret-keys <ID of key used for pass> | gpg --armor --symmetric --output myKeyForPass.sec.asc
````
File `myKeyForPass.sec.asc` can be directly imported into Password Store via Settings → PGP Settings → Key Manager → <kbd>+</kbd>; enter the password from the first step when asked for the backup code.

### From OpenKeychain
1. In the main app window, select the key that you use for `pass`/Password Store from the "My Keys" list.
2. In the window that appears, tap the three-dot menu in the top right corner and select "Backup key".
3. Write down the backup code, then save the backup file to your phone.
4. Import this backup file into Password Store by navigating to Settings → PGP Settings → Key Manager → <kbd>+</kbd>, and enter the backup code when prompted.

## Contributing

Issues and pull requests are welcome, but avoid bulky, hard to digest multi-feature contributions, especially AI-generated ones. Refer to the [Changelog](CHANGELOG.md) for the latest fixes and additions.

## Donations

If you wish to sponsor the original author, financial contributions can be made through the following platforms

- [GitHub Sponsors](https://github.com/sponsors/android-password-store)
- [OpenCollective](https://opencollective.com/android-password-store)
