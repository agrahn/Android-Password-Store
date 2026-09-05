/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.credman

import android.annotation.SuppressLint
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.credentials.provider.CallingAppInfo
import app.passwordstore.util.extensions.b64Encode
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getError
import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.mapError
import com.github.michaelbull.result.runCatching
import java.net.URI
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

private val mdSha256 = MessageDigest.getInstance("SHA-256")

private val json: Json = Json {
  ignoreUnknownKeys = true
  coerceInputValues = true
}

// assetlinks, cached for the lifetime of the app process
private val assetLinks = mutableMapOf<String, String>()

val CALLER_UNKNOWN = "caller unknown"
val CALLER_NON_PRIVILEGED = "caller non privileged"
val CALLER_WRONG_SIGNATURE = "caller wrong signature"
val CALLER_REQUEST_UNSUPPORTED = "caller passkey unsupported"
val CALLER_INVALID_ALLOWLIST = "caller invalid allowlist"
val CALLER_RELYING_PARTY_NOT_IDENTIFIED = "caller relying party not identified"
val CALLER_MISSING_ASSET_LINKS = "caller missing asset links"

/**
 * top-level verifier of a passkey requesting app's authenticity
 *
 * privileged (browser) apps are verified against google's and bitwarden's community-maintained
 * allow lists
 *
 * non-privileged (native) apps are verified using RP-provided asset links
 *
 * on success, the returned Result object contains the web origin of the call if the calling app is
 * a privileged app, or the signing key hash of the calling app formatted as an URI if it is a
 * native app
 *
 * on failure, the returned Result contains an Exception object, whose message text should be
 * examined for the reason
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
fun CallingAppInfo.verifyCaller(rpId: String): Result<String, Throwable> = runCatching {
  /* privileged (browser) app verification against google's official
   * and bitwarden's community-maintained allow lists */
  var verifyCallerResult = getPrivilegedAppOrigin()

  if (!verifyCallerResult.isOk) {
    var error =
      requireNotNull(verifyCallerResult.getError()) {
        "getPrivilegedAppOrigin().getError() returned null"
      }

    if (error.message == CALLER_NON_PRIVILEGED) {
      /* non-privileged (native) app verification using RP-provided asset links */
      verifyCallerResult = verifyNativeApp(rpId)

      if (!verifyCallerResult.isOk) {
        error =
          requireNotNull(verifyCallerResult.getError()) {
            "verifyNativeApp().getError() returned null"
          }
        throw Exception(error.message)
      }
    } else throw Exception(error.message)
  }

  requireNotNull(verifyCallerResult.get()) { "verifyCallerResult.get() returned null" }
}

/**
 * verifies a non-privileged caller app's authenticity; returns a Result object with the signing key
 * hash in the case of success, an exception object otherwise
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
fun CallingAppInfo.verifyNativeApp(rpId: String): Result<String, Throwable> = runCatching {
  var verified = false
  var packageKnown = false

  val appFingerprints = extractSha256CertFingerprints()

  val assetLinksJson =
    fetchAssetLinks(rpId).getOrElse { error ->
      throw Exception(CALLER_UNKNOWN, error)
    }

  val assetLinks = json.decodeFromString<List<AssetLinkEntry>>(assetLinksJson)

  for (entry in assetLinks) {
    val target = entry.target ?: continue
    val relation = entry.relation ?: continue

    if (
      relation.contains("delegate_permission/common.handle_all_urls") &&
        target.namespace == "android_app" &&
        target.packageName == packageName &&
        !target.sha256CertFingerprints.isNullOrEmpty()
    ) {
      var packageKnown = true

      for (localFingerprint in appFingerprints) {
        verified =
          target.sha256CertFingerprints.any { remote ->
            remote.equals(localFingerprint, ignoreCase = true)
          }
        if (verified) break
      }
    }
    if (verified) break
  }

  if (verified) getAppOrigin()
  else throw Exception(if (packageKnown) CALLER_WRONG_SIGNATURE else CALLER_UNKNOWN)
}

/**
 * returns a Result object containing either the web origin of the passkey requesting app if it is
 * present in the list of privileged apps, or an Exception object otherwise (not listed as
 * privileged, wrong signature, broken allow list JSON)
 */
fun CallingAppInfo.getPrivilegedAppOrigin(): Result<String, Throwable> = runCatching {
  val allowed = Allowlist.get()

  if (!allowed.contains("\"$packageName\"")) throw Exception(CALLER_NON_PRIVILEGED)

  getOrigin(allowed) ?: throw Exception(CALLER_REQUEST_UNSUPPORTED)
}
  .mapError { error ->
    when (error) {
      is IllegalStateException -> {
        Exception(CALLER_WRONG_SIGNATURE, error)
      }
      is IllegalArgumentException -> {
        // mal-formatted allow list JSON; should not happen, actually
        Exception(CALLER_INVALID_ALLOWLIST, error)
      }
      else -> error
    }
  }

/**
 * returns the signing key hash of the calling application formatted as an origin URI for an
 * unprivileged application.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
fun CallingAppInfo.getAppOrigin(): String {
  val certHash = mdSha256.digest(signingInfoCompat.apkContentsSigners.first().toByteArray())
  return "android:apk-key-hash:${certHash.b64Encode().concatToString()}"
}

/** extracts, hashes, and formats all SHA-256 certificate fingerprints of the calling app */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
private fun CallingAppInfo.extractSha256CertFingerprints(): List<String> {
  return signingInfoCompat.apkContentsSigners.map { signature ->
    val sha256Bytes = mdSha256.digest(signature.toByteArray())

    sha256Bytes.joinToString(":") { byte ->
      String.format("%02X", byte) // byte as uppercase, 2-figure hex
    }
  }
}

/** returns cached or downloaded asset links for a given RP ID */
@SuppressLint("RawDispatchersUse")
private fun fetchAssetLinks(rpId: String): Result<String, Throwable> = runCatching {
  assetLinks.get(rpId)
    ?: run {
      runBlocking(Dispatchers.IO) {
          val host = "https://$rpId"
          URI("$host/.well-known/assetlinks.json").toURL().readText()
        }
        .also {
          assetLinks.put(rpId, it)
        }
    }
}

@Serializable
private data class AssetLinkEntry(
  val relation: List<String>? = null,
  val target: AssetLinkTarget? = null,
) {
  @Serializable
  data class AssetLinkTarget(
    val namespace: String? = null,
    @SerialName("package_name") val packageName: String? = null,
    @SerialName("sha256_cert_fingerprints") val sha256CertFingerprints: List<String>? = null,
  )
}
