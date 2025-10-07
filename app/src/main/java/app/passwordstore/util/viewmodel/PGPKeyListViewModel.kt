/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.viewmodel

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.passwordstore.crypto.KeyUtils
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.crypto.PGPIdentifier.UserId
import app.passwordstore.crypto.PGPKey
import app.passwordstore.crypto.PGPKeyManager
import com.github.michaelbull.result.map
import com.github.michaelbull.result.onSuccess
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toPersistentList
import kotlinx.coroutines.launch

@HiltViewModel
class PGPKeyListViewModel @Inject constructor(private val keyManager: PGPKeyManager) : ViewModel() {
  var keys: ImmutableList<Pair<KeyId?, UserId?>> by mutableStateOf(persistentListOf())

  init {
    updateKeySet()
  }

  fun updateKeySet() {
    viewModelScope.launch {
      keyManager
        .getAllKeys()
        .map { keys ->
          keys.mapNotNull { key -> KeyUtils.tryGetKeyId(key) to KeyUtils.tryGetUserId(key) }
        }
        .onSuccess {
          keys = persistentListOf<Pair<KeyId, UserId>>()
          keys = it.filter { it.first != null && it.second != null }.toPersistentList()
        }
    }
  }

  fun deleteKey(identifier: PGPIdentifier) {
    viewModelScope.launch {
      keyManager.removeKey(identifier)
      updateKeySet()
    }
  }

  fun addKey(key: PGPKey) {
    viewModelScope.launch {
      keyManager.addKey(key, replace = true)
      updateKeySet()
    }
  }
}
