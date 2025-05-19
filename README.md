# Password Store

[![GitHub workflow](https://github.com/agrahn/Android-Password-Store/workflows/Deploy%20snapshot%20builds/badge.svg)](https://github.com/agrahn/Android-Password-Store/actions)

## Download

- [GitHub Releases](https://github.com/agrahn/Android-Password-Store/releases)

- Latest [snapshot build (APK)](https://github.com/agrahn/Android-Password-Store/releases/tag/latest) of this fork

## Documentation

The original documentation can be found [here](https://docs.passwordstore.app) and [there](https://github.com/android-password-store/Android-Password-Store/wiki/).

## How-To: Transfer a PGP key to Password Store securely

### From GPG keyring
````bash
gpg --armor --gen-random 1 24 # generate a strong random password; use it in the next step
gpg --armor --export-secret-keys <ID of key used for pass> | gpg --armor --symmetric --output myKeyForPass.sec.asc
````
File `myKeyForPass.sec.asc` can be directly imported into Password Store; enter the password from above when asked for the backup code.

### From OpenKeychain
1. Only the PGP key used for `pass`/Password Store should remain in "My Keys." If needed, create a backup ("Full backup") of your entire keyring and make a note of the backup key. Then, remove all other keys from OpenKeychain.
2. Make another full backup (again, note the backup key) of the remaining PGP key—the one used by `pass`/Password Store.
3. Import this backup file into Password Store and enter the backup key when requested.
4. Restore the previous keyring state in OpenKeychain from the first backup.

## Contributing

This fork of the original repository just tries to keep pace with automatic dependency updates made by [Renovate](https://github.com/apps/renovate). New features will most likely not be implemented, only fixes. See [ChangeLog](https://github.com/agrahn/Android-Password-Store/blob/develop/CHANGELOG.md).

## Donations

If you wish to sponsor the original author, financial contributions can be made through the following platforms

- [GitHub Sponsors](https://github.com/sponsors/android-password-store)
- [OpenCollective](https://opencollective.com/android-password-store)
