/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import app.passwordstore.passkeys.security.PasskeyInputLimits
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
internal data class AssetLinkStatement(
  @SerialName("relation") val relation: List<String>? = null,
  @SerialName("target") val target: AssetLinkTarget? = null,
)

@Serializable
internal data class AssetLinkTarget(
  @SerialName("namespace") val namespace: String? = null,
  @SerialName("site") val site: String? = null,
  @SerialName("package_name") val packageName: String? = null,
  @SerialName("sha256_cert_fingerprints") val sha256CertFingerprints: List<String>? = null,
)

internal class DigitalAssetLinksClient(
  private val connectTimeoutMs: Int = 5_000,
  private val readTimeoutMs: Int = 5_000,
  private val inputLimits: PasskeyInputLimits = PasskeyInputLimits.DEFAULT,
) {

  private val json = Json { ignoreUnknownKeys = true }

  fun fetchAssetLinks(rpId: String): Result<List<AssetLinkStatement>, AssetLinkFetchError> {
    val url = URL("https://$rpId/.well-known/assetlinks.json")
    val connection =
      try {
        url.openConnection() as HttpsURLConnection
      } catch (e: Exception) {
        return Err(AssetLinkFetchError.TlsError(e.message ?: "Unknown TLS error"))
      }
    return try {
      connection.connectTimeout = connectTimeoutMs
      connection.readTimeout = readTimeoutMs
      connection.requestMethod = "GET"
      connection.setRequestProperty("Accept", "application/json")
      connection.instanceFollowRedirects = false
      connection.connect()

      val responseCode = connection.responseCode
      if (responseCode != HttpURLConnection.HTTP_OK) {
        return Err(AssetLinkFetchError.HttpError(responseCode, "HTTP $responseCode from $rpId"))
      }

      val contentLength = connection.contentLengthLong
      if (contentLength > inputLimits.maxAssetLinksBytes) {
        return Err(
          AssetLinkFetchError.ResponseTooLarge(
            "Content-Length $contentLength exceeds maximum ${inputLimits.maxAssetLinksBytes}"
          )
        )
      }

      val body = readBoundedResponseBody(connection, inputLimits.maxAssetLinksBytes)

      val statements =
        try {
          json.decodeFromString<List<AssetLinkStatement>>(body)
        } catch (e: Exception) {
          return Err(AssetLinkFetchError.ParseError(e.message ?: "Failed to parse asset links"))
        }

      if (statements.size > inputLimits.maxAssetLinkStatements) {
        return Err(AssetLinkFetchError.TooManyStatements(inputLimits.maxAssetLinkStatements))
      }

      for (statement in statements) {
        val relationCount = statement.relation?.size ?: 0
        if (relationCount > inputLimits.maxRelationsPerStatement) {
          return Err(AssetLinkFetchError.TooManyRelations(inputLimits.maxRelationsPerStatement))
        }
        val fingerprintCount = statement.target?.sha256CertFingerprints?.size ?: 0
        if (fingerprintCount > inputLimits.maxFingerprintsPerStatement) {
          return Err(
            AssetLinkFetchError.TooManyFingerprints(inputLimits.maxFingerprintsPerStatement)
          )
        }
        val pkgName = statement.target?.packageName
        if (pkgName != null && pkgName.length > MAX_PACKAGE_NAME_LENGTH) {
          return Err(AssetLinkFetchError.ParseError("Package name exceeds maximum length"))
        }
        val fingerprints = statement.target?.sha256CertFingerprints
        if (fingerprints != null) {
          for (fp in fingerprints) {
            if (fp.length > MAX_FINGERPRINT_LENGTH) {
              return Err(AssetLinkFetchError.ParseError("Fingerprint exceeds maximum length"))
            }
          }
        }
      }

      Ok(statements)
    } catch (e: javax.net.ssl.SSLException) {
      Err(AssetLinkFetchError.TlsError(e.message ?: "TLS error"))
    } catch (e: java.net.SocketTimeoutException) {
      Err(AssetLinkFetchError.Timeout("Connection timed out fetching asset links from $rpId"))
    } catch (e: java.net.UnknownHostException) {
      Err(AssetLinkFetchError.DnsError("Could not resolve $rpId"))
    } catch (e: AssetLinkFetchError) {
      Err(e)
    } catch (e: Exception) {
      Err(AssetLinkFetchError.NetworkError(e.message ?: "Unknown network error"))
    } finally {
      connection.disconnect()
    }
  }

  private fun readBoundedResponseBody(
    connection: HttpsURLConnection,
    maxBytes: Long,
  ): String {
    val output = ByteArrayOutputStream()
    val buf = ByteArray(8192)
    var totalRead = 0L
    connection.inputStream.use { inputStream ->
      while (true) {
        val n = inputStream.read(buf)
        if (n == -1) break
        totalRead += n
        if (totalRead > maxBytes) {
          throw AssetLinkFetchError.ResponseTooLarge(
            "Response body exceeds maximum $maxBytes bytes"
          )
        }
        output.write(buf, 0, n)
      }
    }
    return output.toString(Charsets.UTF_8.name())
  }

  private companion object {
    private const val MAX_PACKAGE_NAME_LENGTH = 256
    private const val MAX_FINGERPRINT_LENGTH = 128
  }
}

internal sealed class AssetLinkFetchError(val reason: String) : RuntimeException(reason) {
  class Timeout(reason: String) : AssetLinkFetchError(reason)

  class TlsError(reason: String) : AssetLinkFetchError(reason)

  class HttpError(val statusCode: Int, reason: String) : AssetLinkFetchError(reason)

  class ParseError(reason: String) : AssetLinkFetchError(reason)

  class DnsError(reason: String) : AssetLinkFetchError(reason)

  class NetworkError(reason: String) : AssetLinkFetchError(reason)

  class ResponseTooLarge(reason: String) : AssetLinkFetchError(reason)

  class TooManyStatements(val maximum: Int) :
    AssetLinkFetchError("Statement count exceeds maximum $maximum")

  class TooManyRelations(val maximum: Int) :
    AssetLinkFetchError("Relation count exceeds maximum $maximum")

  class TooManyFingerprints(val maximum: Int) :
    AssetLinkFetchError("Fingerprint count exceeds maximum $maximum")
}
