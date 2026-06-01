# Password Store

[![GitHub workflow](https://github.com/agrahn/Android-Password-Store/workflows/Deploy%20snapshot%20builds/badge.svg)](https://github.com/agrahn/Android-Password-Store/actions)

## Download

- Latest [snapshot build (APK)](https://github.com/agrahn/Android-Password-Store/releases/tag/latest) of this fork
- [GitHub Releases](https://github.com/agrahn/Android-Password-Store/releases)
- [<img src="https://f-droid.org/assets/fdroid-logo-text_S0MUfk_FsnAYL7n2MQye-34IoSNm6QM6xYjDnMqkufo=.svg" height="32px"/>](https://f-droid.org/en/packages/app.passwordstore.agrahn)

## Documentation

The original documentation can be found [here](https://docs.passwordstore.app) and [there](https://github.com/android-password-store/Android-Password-Store/wiki/).

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

This fork of the original repository just tries to keep pace with automatic dependency updates made by [Renovate](https://github.com/apps/renovate). New features will most likely not be implemented, only fixes. See [ChangeLog](https://github.com/agrahn/Android-Password-Store/blob/develop/CHANGELOG.md).

## Donations

If you wish to sponsor the original author, financial contributions can be made through the following platforms

- [GitHub Sponsors](https://github.com/sponsors/android-password-store)
- [OpenCollective](https://opencollective.com/android-password-store)
