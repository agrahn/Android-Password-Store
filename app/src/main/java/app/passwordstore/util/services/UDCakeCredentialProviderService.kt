/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.services

import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import app.passwordstore.BuildConfig
import app.passwordstore.util.credman.CredmanUtils
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.runCatching
import logcat.logcat

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class UDCakeCredentialProviderService : CredentialProviderService() {

  override fun onBeginCreateCredentialRequest(
    request: BeginCreateCredentialRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
  ) {
    val response: BeginCreateCredentialResponse? =
      CredmanUtils.processCreateCredentialRequest(request)
    logcat {
      "++++++++++++++++++++ onBegin CREATE CredentialRequest ++++++++++++++++++++"
    }
    if (response != null) {
      runCatching {
          callback.onResult(response)
        }
        .onErr { e ->
          logcat { e.toString() }
        }
    } else {
      callback.onError(CreateCredentialUnknownException())
    }
  }

  override fun onBeginGetCredentialRequest(
    request: BeginGetCredentialRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
  ) {
    logcat { "++++++++++++++++++++ onBegin GET CredentialRequest ++++++++++++++++++++" }
    // try {
    //
    // callback.onResult(OpenPasskeyAuthServiceUtils.processGetCredentialRequest(this.application,
    // this, request))
    // } catch (_: GetCredentialException) {
    //    callback.onError(GetCredentialUnknownException())
    // }
  }

  override fun onClearCredentialStateRequest(
    request: ProviderClearCredentialStateRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<Void?, ClearCredentialException>,
  ) {
    logcat { "Not implemented: onClearCredentialStateRequest" }
  }

  companion object {
    // These intent actions are specified for corresponding activities
    // that are to be invoked through the PendingIntent(s)
    const val GET_PASSKEY_INTENT_ACTION = "${BuildConfig.APPLICATION_ID}.action.GET_PASSKEY"
    const val CREATE_PASSKEY_INTENT_ACTION = "${BuildConfig.APPLICATION_ID}.action.CREATE_PASSKEY"
    const val CREDENTIAL_DATA_EXTRA = "${BuildConfig.APPLICATION_ID}.CREDENTIAL_DATA"
    const val UNLOCK_APP_INTENT_ACTION = "${BuildConfig.APPLICATION_ID}.action.UNLOCK_APP"
    const val CREDENTIAL_ID = "credentialId"
    const val ACCOUNT_ID = "accountId"
    const val DEVICE_ACCOUNT = "DEVICE_ACCOUNT_ID"
  }
}
