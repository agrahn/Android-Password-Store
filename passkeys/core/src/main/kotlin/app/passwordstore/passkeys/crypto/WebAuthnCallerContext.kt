/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.crypto

private val PRIVILEGED_BROWSER_CLIENT_DATA_JSON_PLACEHOLDER: ByteArray = "{}".toByteArray()

public enum class CallerType {
  NATIVE_APP,
  PRIVILEGED_BROWSER,
}

public sealed interface ClientDataBinding {

  /**
   * Binding for privileged browser ceremonies.
   *
   * Android Credential Manager supplies the authoritative clientDataHash for privileged callers.
   * Providers must sign that hash directly and return a placeholder clientDataJSON rather than a
   * locally reconstructed browser payload. The constructor keeps the legacy response JSON argument
   * for source compatibility with the app-layer verifier, but that value is intentionally ignored.
   */
  public class FrameworkHash(
    public val hash: ByteArray,
    @Suppress("UNUSED_PARAMETER") responseClientDataJson: ByteArray,
  ) : ClientDataBinding {

    public val responseClientDataJson: ByteArray
      get() = PRIVILEGED_BROWSER_CLIENT_DATA_JSON_PLACEHOLDER.copyOf()

    override fun equals(other: Any?): Boolean {
      if (this === other) return true
      if (other !is FrameworkHash) return false
      return hash.contentEquals(other.hash)
    }

    override fun hashCode(): Int = hash.contentHashCode()

    override fun toString(): String =
      "FrameworkHash(hash=<${hash.size} bytes>, responseClientDataJson=<placeholder>)"
  }

  public data object ProviderConstructed : ClientDataBinding
}

public data class VerifiedWebAuthnContext(
  val callingPackage: String,
  val origin: String,
  val callerType: CallerType,
  val signingCertificateDigests: Set<String>,
  val clientDataBinding: ClientDataBinding,
) {

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is VerifiedWebAuthnContext) return false
    if (callingPackage != other.callingPackage) return false
    if (origin != other.origin) return false
    if (callerType != other.callerType) return false
    if (signingCertificateDigests != other.signingCertificateDigests) return false
    if (clientDataBinding != other.clientDataBinding) return false
    return true
  }

  override fun hashCode(): Int {
    var result = callingPackage.hashCode()
    result = 31 * result + origin.hashCode()
    result = 31 * result + callerType.hashCode()
    result = 31 * result + signingCertificateDigests.hashCode()
    result = 31 * result + clientDataBinding.hashCode()
    return result
  }

  override fun toString(): String =
    "VerifiedWebAuthnContext(callingPackage=$callingPackage, origin=$origin, " +
      "callerType=$callerType, clientDataBinding=$clientDataBinding, " +
      "signingCertificateDigests=$signingCertificateDigests)"
}

public enum class AssetLinkCapability(public val requiredRelation: String) {
  PASSKEY_CEREMONY("delegate_permission/common.handle_all_urls"),
  LOGIN_CREDENTIAL_ACCESS("delegate_permission/common.get_login_creds"),
}

public sealed class CallerVerificationError {
  public data class MissingCallingAppInfo(val stage: String) : CallerVerificationError()

  public data class MissingPackageName(val stage: String) : CallerVerificationError()

  public data class MissingSigningCertificate(val stage: String) : CallerVerificationError()

  public data class InvalidRpId(val rpId: String, val reason: String) : CallerVerificationError()

  public data class OriginRpIdMismatch(val origin: String, val rpId: String) :
    CallerVerificationError()

  public data class AssetLinkVerificationFailed(val rpId: String, val reason: String) :
    CallerVerificationError()

  public data class RequiredAssetLinkRelationMissing(
    val rpId: String,
    val packageName: String,
    val requiredRelation: String,
  ) : CallerVerificationError()

  public data class UntrustedBrowser(val packageName: String, val reason: String) :
    CallerVerificationError()

  public data class BrowserCertificateMismatch(val packageName: String) : CallerVerificationError()

  public data class UnsupportedAlgorithm(val requestedAlgorithms: List<Long>) :
    CallerVerificationError()

  public data class MalformedRequest(val field: String, val reason: String) :
    CallerVerificationError()

  public data class MissingClientDataHash(val stage: String) : CallerVerificationError()

  public data class InvalidClientDataHashLength(val expected: Int, val actual: Int) :
    CallerVerificationError()

  public data class BindingModeMismatch(val expected: String, val actual: String) :
    CallerVerificationError()

  public fun errorCode(): String =
    when (this) {
      is MissingCallingAppInfo -> "CALLER_INFO_MISSING"
      is MissingPackageName -> "PACKAGE_NAME_MISSING"
      is MissingSigningCertificate -> "SIGNING_CERT_MISSING"
      is InvalidRpId -> "INVALID_RP_ID"
      is OriginRpIdMismatch -> "ORIGIN_RP_MISMATCH"
      is AssetLinkVerificationFailed -> "ASSET_LINK_FAILED"
      is RequiredAssetLinkRelationMissing -> "ASSET_LINK_RELATION_MISSING"
      is UntrustedBrowser -> "UNTRUSTED_BROWSER"
      is BrowserCertificateMismatch -> "BROWSER_CERT_MISMATCH"
      is UnsupportedAlgorithm -> "UNSUPPORTED_ALGORITHM"
      is MalformedRequest -> "MALFORMED_REQUEST"
      is MissingClientDataHash -> "MISSING_CLIENT_DATA_HASH"
      is InvalidClientDataHashLength -> "INVALID_CLIENT_DATA_HASH_LENGTH"
      is BindingModeMismatch -> "BINDING_MODE_MISMATCH"
    }
}

public data class CallerVerificationDiagnostic(
  val callerPackage: String?,
  val callerType: CallerType?,
  val requestedRpId: String?,
  val stage: String,
  val errorCode: String,
  val message: String,
) {
  override fun toString(): String =
    "Diagnostic(stage=$stage, code=$errorCode, package=$callerPackage, " +
      "type=$callerType, rpId=$requestedRpId, msg=$message)"
}
