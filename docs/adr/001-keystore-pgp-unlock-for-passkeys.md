# ADR-001: Keystore-backed PGP Passphrase Unlock for Passkeys

**Status:** Accepted
**Date:** 2026-07-25
**Issue:** #88

## Context

Passkeys only work with unprotected (no-passphrase) PGP secret keys. `DefaultPgpUnlockContext.unlockKey()` always returns `null`, so PGPainless cannot decrypt passphrase-protected keys. Users with passphrase-protected PGP keys see a generic "Selected passkey is unavailable" error.

The main app already has a mature passphrase caching infrastructure for password decryption:
- **In-memory cache** (`BasePGPActivity.cachedPassphrases`): AES-encrypted with `KeyType.TEMPORARY`, cleared on screen-off
- **Persistent cache** (`SharedPreferences`): AES-encrypted with `KeyType.PERSISTENT_WITH_AUTHENTICATION` (biometric) or `KeyType.PERSISTENT` + `KeyType.PERSISTENT_WITH_PIN`
- **Interactive dialog**: manual passphrase entry as fallback

The passkey flow has two distinct decryption needs:
1. **Picker** (in `PasskeyCredentialProviderService`): needs usernames from encrypted credential files to build the credential list
2. **Signing** (in `AppPasskeyProviderActivity`): needs the private key for assertion signing

The picker runs BEFORE biometric authentication (which happens after credential selection for WebAuthn UV). This creates a chicken-and-egg problem: usernames require decryption, but the passphrase is behind biometric auth.

## Decision

### 1. Persistent metadata index (solves the picker problem)

Store credential display metadata (`userName`, `userDisplayName`) in a persistent index that survives process death. The picker reads from this index without decryption.

- Populated at credential creation time (plaintext is available)
- Rebuilt via biometric-gated decryption when cold/missing
- Contains NO secrets — only display strings and identifiers

### 2. Biometric-gated passphrase unlock (solves the signing problem)

When the metadata index is cold (no usernames for the requested rpId), prompt biometric authentication to:
1. Unlock the passphrase from the persistent Keystore-backed cache
2. Decrypt candidate credentials to extract usernames
3. Populate the persistent metadata index
4. Cache the passphrase in memory for the subsequent signing step

### 3. Process-level passphrase cache (bridges picker → signing)

A singleton in-memory passphrase cache accessible from both `PasskeyCredentialProviderService` (picker) and `AppPasskeyProviderActivity` (signing). Mirrors `BasePGPActivity.cachedPassphrases` pattern.

- AES-encrypted with `KeyType.TEMPORARY` (process lifetime, cleared on screen-off)
- Populated after successful biometric auth
- If cold at signing time (process death between picker and signing), re-prompt biometric

### 4. UV flag semantics

Biometric authentication always gates passkey access. The UV flag is always `true` because:
- Picker biometric (index build) satisfies UV for the session
- Signing biometric (re-prompt after process death) satisfies UV
- No passphrase-protected key can be accessed without biometric

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    PasskeyCredentialProviderService              │
│                         (picker flow)                            │
│                                                                  │
│  1. listMetadata(rpId) → index has usernames?                   │
│     YES → build picker entries directly                         │
│     NO  → biometric prompt → unlock passphrase →                │
│           decrypt candidates → populate index → build entries    │
│           → cache passphrase in PasskeyPassphraseCache           │
└──────────────────────────────────┬──────────────────────────────┘
                                   │ PendingIntent
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AppPasskeyProviderActivity                     │
│                        (signing flow)                            │
│                                                                  │
│  2. Biometric auth (UV)                                         │
│  3. PasskeyPassphraseCache has passphrase?                      │
│     YES → KeystorePgpUnlockContext returns it → decrypt → sign  │
│     NO  → unlock from persistent cache via biometric cipher →   │
│           cache it → decrypt → sign                             │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### New: `PasskeyPassphraseCache` (app module, singleton)

Process-level in-memory cache for PGP passphrases used by the passkey flow.

```kotlin
@Singleton
class PasskeyPassphraseCache @Inject constructor() {
    // keyId → AES-encrypted passphrase (KeyType.TEMPORARY)
    private val cache = ConcurrentHashMap<String, CharArray>()

    fun put(keyId: String, passphrase: CharArray)
    fun get(keyId: String): CharArray?  // AES-decrypts before returning
    fun clear()
}
```

### New: `KeystorePgpUnlockContext` (app module)

Implements `PgpUnlockContext`. Reads from `PasskeyPassphraseCache`, falls back to persistent Keystore-backed cache.

```kotlin
class KeystorePgpUnlockContext(
    private val passphraseCache: PasskeyPassphraseCache,
    private val persistentPassphrases: SharedPreferences,
) : PgpUnlockContext {
    override suspend fun unlockKey(keyId: String): CharArray? {
        // 1. Try in-memory cache
        passphraseCache.get(keyId)?.let { return it }
        // 2. Try persistent cache (requires prior biometric unlock)
        //    Decrypt from SharedPreferences using PERSISTENT_WITH_AUTHENTICATION
        // 3. Return null (caller must trigger biometric)
    }
}
```

### New: `PasskeyMetadataIndex` (app module)

Persistent metadata store for credential display info. Backed by `SharedPreferences` or a JSON file.

```kotlin
@Singleton
class PasskeyMetadataIndex @Inject constructor(
    @ApplicationContext context: Context,
) {
    // credentialId (base64url) → {userName, userDisplayName, rpId}
    fun get(credentialId: ByteArray): MetadataEntry?
    fun put(credentialId: ByteArray, entry: MetadataEntry)
    fun getByRpId(rpId: String): List<MetadataEntry>
    fun remove(credentialId: ByteArray)
    fun clear()
}
```

### Modified: `PasskeyCredentialProviderService`

Add biometric-gated index building when metadata is cold.

### Modified: `AppPasskeyProviderActivity`

Use `PasskeyPassphraseCache` for signing; re-prompt biometric if cache is cold.

### Modified: `PasskeysModule` (DI)

Replace `DefaultPgpUnlockContext` with `KeystorePgpUnlockContext`.

## Implementation Plan

### Phase 1: Core infrastructure

1. **`PasskeyPassphraseCache`** — `app/src/main/java/app/passwordstore/passkeys/PasskeyPassphraseCache.kt`
   - Singleton, `ConcurrentHashMap<String, CharArray>`
   - AES encrypt/decrypt with `KeyType.TEMPORARY`
   - `put()`, `get()`, `clear()`
   - Register screen-off receiver to clear (or rely on TEMPORARY key invalidation)

2. **`KeystorePgpUnlockContext`** — `app/src/main/java/app/passwordstore/passkeys/KeystorePgpUnlockContext.kt`
   - Implements `PgpUnlockContext`
   - Reads from `PasskeyPassphraseCache` first
   - Falls back to persistent `SharedPreferences` (same store as `BasePGPActivity`)
   - Returns `null` if neither has the passphrase (signals caller to prompt biometric)

3. **`PasskeyMetadataIndex`** — `app/src/main/java/app/passwordstore/passkeys/PasskeyMetadataIndex.kt`
   - Persistent JSON file in `filesDir/passkey-metadata-index.json`
   - Stores `{credentialId → {userName, userDisplayName, rpId, createdAt}}`
   - Thread-safe reads/writes
   - Populated at creation time and during biometric-gated rebuild

### Phase 2: Picker flow integration

4. **Modify `PasskeyCredentialProviderService.onBeginGetCredentialRequest()`**
   - After `listMetadata(rpId)` returns entries with blank usernames:
     - Check `PasskeyMetadataIndex` for cached usernames
     - If found: enrich metadata from index, skip decryption
     - If not found: trigger biometric → unlock passphrase → decrypt → populate index
   - Biometric in a `CredentialProviderService` requires special handling (no Activity context)
     - Use `PendingIntent`-based biometric or delegate to a transparent Activity
     - Alternative: return entries with rpId as username, let signing flow handle biometric

5. **Modify `PasskeyProviderUtils.loadStoredIdentity()`**
   - Check `PasskeyMetadataIndex` before falling through to `loadForSigning()`
   - If index has the entry, return enriched metadata without decryption

### Phase 3: Signing flow integration

6. **Modify `AppPasskeyProviderActivity.handleGetCredential()`**
   - After biometric auth succeeds, populate `PasskeyPassphraseCache` from persistent store
   - `KeystorePgpUnlockContext` will then find the passphrase in memory
   - If persistent store is empty (first use with passphrase key), prompt for passphrase entry
     - Cache in both `PasskeyPassphraseCache` and persistent store

7. **Modify `PasskeysModule.providePgpUnlockContext()`**
   - Replace `DefaultPgpUnlockContext()` with `KeystorePgpUnlockContext(passphraseCache, persistentPassphrases)`

### Phase 4: Creation flow integration

8. **Modify credential creation** (`AppPasskeyProviderActivity.handleCreateCredential()`)
   - After successful `saveCredential()`, populate `PasskeyMetadataIndex` with the new credential's metadata
   - This ensures the index is warm from the start

### Phase 5: Cache lifecycle

9. **Passphrase persistence on first use**
   - When a user enters their PGP passphrase for the first time in the passkey flow:
     - Encrypt with `KeyType.PERSISTENT_WITH_AUTHENTICATION`
     - Store in `persistentPassphrases` SharedPreferences (same store as passwords)
   - Subsequent uses: biometric unlocks the persistent cache → populates in-memory cache

10. **Index invalidation**
    - Clear `PasskeyMetadataIndex` entry on `deleteCredential()`
    - Rebuild on `invalidate()` (git sync, clear credential state)
    - Index is a cache, not source of truth — always recoverable via biometric-gated rebuild

### Phase 6: Tests

11. **Unit tests**
    - `PasskeyPassphraseCache`: put/get/clear, AES round-trip
    - `KeystorePgpUnlockContext`: cache hit, persistent fallback, null when empty
    - `PasskeyMetadataIndex`: CRUD, rpId queries, persistence across instances
    - `loadStoredIdentity` with index hit (no decryption)

12. **Integration considerations**
    - Biometric in `CredentialProviderService` (no Activity) — may need instrumentation tests
    - Process death between picker and signing — passphrase cache cold path

## Alternatives Considered

### A. Persistent metadata index only (no biometric at picker)
Populate index at creation time, never decrypt at picker. Problem: existing credentials (created before this feature) have no index entries. Migration requires decryption.

### B. Biometric before picker (always)
Always prompt biometric before showing the picker. Rejected: worse UX, unnecessary when index is warm.

### C. Store usernames in filesystem path
Encode username in the file path (e.g., `fido2/rpId/username/credentialId.gpg`). Rejected: changes storage format, breaks passless compatibility.

### D. Two separate biometric prompts (one for picker, one for UV)
Rejected: worse UX. Single biometric serves both purposes within a session.

## Consequences

- Users with passphrase-protected PGP keys can use passkeys
- First picker request for a new rpId triggers biometric (subsequent requests use the index)
- The persistent metadata index leaks which RPs have passkeys (usernames are stored in plaintext). This is acceptable: the same info is visible in the filesystem paths (`fido2/<rpId>/...`)
- Process death between picker and signing requires re-authentication (acceptable security tradeoff)
- The passkey flow shares the same persistent passphrase store as the password flow — unlocking one unlocks both
