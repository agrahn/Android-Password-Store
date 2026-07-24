/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

/**
 * # WebAuthn Caller Verification — Trust Model
 *
 * This package implements the security boundary that verifies which Android application is
 * requesting a WebAuthn credential operation and whether it is authorized for the requested Relying
 * Party (RP).
 *
 * ## Native Application Trust Model
 *
 * Native Android applications are authorized through **Digital Asset Links** (DAL). For each
 * assertion or registration request from a native app:
 *
 * 1. The calling package name and signing certificate SHA-256 digest are extracted from the
 *    framework-provided `CallingAppInfo`.
 * 2. The provider fetches `https://<rpId>/.well-known/assetlinks.json` over HTTPS.
 * 3. The response is parsed and checked for a statement with:
 *     - `relation`: `delegate_permission/common.handle_all_urls` (required for passkey ceremonies)
 *     - `target.namespace`: `android_app`
 *     - `target.package_name`: matching the calling package
 *     - `target.sha256_cert_fingerprints`: containing the calling app's signing certificate digest
 *
 * The `get_login_creds` relation alone cannot authorize passkey ceremonies. Each
 * `AssetLinkCapability` maps to exactly one DAL relation, and the cache key includes the capability
 * to prevent cross-capability authorization.
 * 4. The Android app origin is derived as `android:apk-key-hash:<base64url_sha256>`.
 *
 * **No fabricated `https://` origin is ever used for native callers.**
 *
 * ### Certificate Rotation
 *
 * Android supports signing certificate rotation via the `signingInfo` API. The verifier extracts
 * all signing certificates from `apkContentsSigners` (current signing certificates). If the RP's
 * asset links file includes any of the current certificates, the caller is authorized. This means
 * that after a certificate rotation, the RP must update their asset links to include the new
 * certificate digest, OR the old certificate must still be in the signing lineage.
 *
 * ### Asset Link Caching
 *
 * Successful asset link verifications are cached for 5 minutes, keyed by (RP ID, package name,
 * certificate digests, capability). The cache is capability-specific: a `LOGIN_CREDENTIAL_ACCESS`
 * result cannot authorize a `PASSKEY_CEREMONY` request. The cache is in-memory only and does not
 * survive process death. This limits the window where a revoked asset link statement might still be
 * accepted.
 *
 * ### Offline / Fail-Closed Behavior
 *
 * If the asset links fetch fails for any reason (network timeout, TLS error, DNS failure, HTTP
 * error, parse error), the verification **fails closed** — the request is rejected. There is no
 * offline fallback or cached-forever behavior. The only exception is the short-lived (5-minute)
 * in-memory cache for previously verified callers.
 *
 * ## Privileged Browser Trust Model
 *
 * Browsers may represent web origins on behalf of web pages. A browser is trusted only when ALL of
 * the following are true:
 *
 * 1. **Package name** is on the explicit allowlist (see `BrowserAllowlist`).
 * 2. **Signing certificate** SHA-256 digest matches a pinned value in the allowlist entry.
 * 3. **Verified origin** is provided by the Android framework via `CallingAppInfo.getOrigin()`.
 *    This origin is populated by the framework for privileged browsers and cannot be spoofed by the
 *    browser app itself.
 * 4. **RP ID matches origin**: The requested RP ID is the exact host or a registrable suffix of the
 *    verified origin's host (e.g., origin `https://login.example.com` permits RP ID `example.com`).
 *
 * The allowlist is data-driven (`BrowserAllowlist.DEFAULT_ALLOWLIST`), not hardcoded logic. Adding
 * or removing browsers requires updating the allowlist entries with both package name and
 * certificate pin.
 *
 * ### Browser Certificate Pins
 *
 * Each `TrustedBrowserEntry` contains one or more SHA-256 certificate digests. These must be
 * updated when a browser rotates its signing certificate. The framework's
 * `CallingAppInfo.getOrigin()` mechanism ensures that even if a browser is compromised, it cannot
 * claim arbitrary origins without the correct signing certificate.
 *
 * ### Certificate Rotation for Browsers
 *
 * When a browser rotates its signing certificate, the allowlist must be updated to include the new
 * certificate digest. Until the allowlist is updated, the browser with the new certificate will be
 * rejected. This is a deliberate security trade-off: it is better to temporarily break passkey
 * support for a browser than to accept an unverified certificate.
 *
 * ## Request JSON Origin — Never Trusted
 *
 * The `origin` field in `WebAuthnGetRequest` JSON is **never used** for security decisions. It is
 * retained only for deserialization compatibility but is marked `@Deprecated`. The actual origin
 * used in assertions and attestations always comes from the `VerifiedWebAuthnContext`.
 *
 * ## Client Data Binding — Two Signing Modes
 *
 * The `ClientDataBinding` sealed interface makes it impossible to accidentally reconstruct client
 * data for a privileged browser. Two modes exist:
 *
 * ### FrameworkHash (Privileged Browser)
 *
 * For privileged browser callers, the Android Credential Manager framework provides a
 * `clientDataHash` that represents the exact client data approved by the browser. The provider
 * signs `authenticatorData || clientDataHash` without reconstructing client data. This ensures that
 * security-relevant browser context such as `crossOrigin`, `topOrigin`, token binding, or future
 * WebAuthn fields are preserved exactly as the browser intended.
 *
 * The framework `clientDataHash` must be exactly 32 bytes (SHA-256). If missing or the wrong
 * length, the request fails closed before any private-key operation.
 *
 * ### ProviderConstructed (Native App)
 *
 * For native Android callers, the provider constructs canonical client data JSON using the verified
 * Android origin (`android:apk-key-hash:<base64url-cert-sha256>`), hashes it, and signs the result.
 * The same bytes are returned in the response.
 *
 * The request JSON `origin` is never used for either mode.
 *
 * ## RP ID Validation
 *
 * Before any caller verification, the RP ID is validated:
 * - Must be a valid hostname (no schemes, ports, paths, queries, fragments)
 * - Must not start/end with dots or contain consecutive dots
 * - Labels must be 1-63 characters, alphanumeric plus hyphens (no leading/trailing hyphens)
 * - Maximum total length: 253 characters
 *
 * After caller verification, the RP ID is checked against the verified origin:
 * - For web origins: RP ID must equal the origin host or be a registrable suffix
 * - For Android origins: RP ID validation passes if asset links matched (checked earlier)
 *
 * ## Algorithm Validation
 *
 * Create requests must include ES256 (`alg = -7`) in `pubKeyCredParams`. Requests without ES256
 * support are rejected before any biometric prompt or key generation.
 *
 * ## Error Handling
 *
 * - Requesting apps receive generic error messages ("Caller verification failed")
 * - Detailed diagnostics are logged locally via `CallerVerificationDiagnostic`
 * - Diagnostics include: caller package, caller type, RP ID, verification stage, error code
 * - Diagnostics never include: challenges, private keys, full credential IDs, or cert details
 */
