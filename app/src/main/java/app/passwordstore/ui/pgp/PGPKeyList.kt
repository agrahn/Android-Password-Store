/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.pgp

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import app.passwordstore.R
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.ui.compose.theme.APSTheme
import app.passwordstore.ui.compose.theme.SpacingLarge
import app.passwordstore.ui.compose.theme.SpacingSmall
import app.passwordstore.util.extensions.conditional
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toPersistentList

@Composable
fun KeyList(
  identifiers: ImmutableList<PGPIdentifier>,
  hasSecretKey: (identifier: PGPIdentifier) -> Boolean,
  onChangePassphraseClick: (identifier: PGPIdentifier) -> Unit,
  onDeleteItemClick: (identifier: PGPIdentifier) -> Unit,
  onExportItemClick: (identifier: PGPIdentifier) -> Unit,
  onExportPublicClick: (identifier: PGPIdentifier) -> Unit,
  modifier: Modifier = Modifier,
  onKeySelected: ((identifier: PGPIdentifier) -> Unit)? = null,
) {
  if (identifiers.isEmpty()) {
    Column(
      modifier = modifier.fillMaxSize(),
      verticalArrangement = Arrangement.Center,
      horizontalAlignment = Alignment.CenterHorizontally,
    ) {
      Image(
        painter = painterResource(id = R.drawable.ic_launcher_foreground),
        contentDescription = "Password Store logo",
      )
      Text(stringResource(R.string.pgp_key_manager_no_keys_guidance))
    }
  } else {
    LazyColumn(modifier = modifier) {
      items(identifiers) { identifier ->
        KeyItem(
          identifier = identifier,
          hasSecretKey = hasSecretKey,
          onChangePassphraseClick = onChangePassphraseClick,
          onDeleteItemClick = onDeleteItemClick,
          onExportItemClick = onExportItemClick,
          onExportPublicClick = onExportPublicClick,
          onKeySelected = onKeySelected,
        )
      }
    }
  }
}

@Composable
private fun KeyItem(
  identifier: PGPIdentifier,
  hasSecretKey: (identifier: PGPIdentifier) -> Boolean,
  onChangePassphraseClick: (identifier: PGPIdentifier) -> Unit,
  onDeleteItemClick: (identifier: PGPIdentifier) -> Unit,
  onExportItemClick: (identifier: PGPIdentifier) -> Unit,
  onExportPublicClick: (identifier: PGPIdentifier) -> Unit,
  modifier: Modifier = Modifier,
  onKeySelected: ((identifier: PGPIdentifier) -> Unit)? = null,
) {
  var isDeleting by remember { mutableStateOf(false) }
  DeleteConfirmationDialog(
    isDeleting = isDeleting,
    onDismiss = { isDeleting = false },
    onConfirm = {
      onDeleteItemClick(identifier)
      isDeleting = false
    },
  )
  val label =
    when (identifier) {
      is PGPIdentifier.KeyId -> identifier.id.toString()
      is PGPIdentifier.UserId -> identifier.email
    }
  Row(
    modifier =
      modifier
        .padding(horizontal = SpacingLarge, vertical = SpacingSmall)
        .fillMaxWidth()
        .conditional(onKeySelected != null) { clickable { onKeySelected?.invoke(identifier) } },
    horizontalArrangement = Arrangement.SpaceBetween,
    verticalAlignment = Alignment.CenterVertically,
  ) {
    Text(
      text = label,
      modifier = Modifier.weight(1f),
      overflow = TextOverflow.Ellipsis,
      maxLines = 1,
    )
    if (onKeySelected == null) {
      Box() {
        var isMenuExpanded by remember { mutableStateOf(false) }

        IconButton(onClick = { isMenuExpanded = true }) {
          Icon(Icons.Default.MoreVert, contentDescription = "PGP key actions")
        }

        DropdownMenu(expanded = isMenuExpanded, onDismissRequest = { isMenuExpanded = false }) {
          if (hasSecretKey(identifier)) {
            DropdownMenuItem(
              text = { Text(stringResource(id = R.string.pref_pgp_key_manager_change_passphrase)) },
              onClick = {
                isMenuExpanded = false
                onChangePassphraseClick(identifier)
              },
            )
            DropdownMenuItem(
              text = { Text(stringResource(id = R.string.pref_pgp_key_manager_export)) },
              onClick = {
                isMenuExpanded = false
                onExportItemClick(identifier)
              },
            )
            Spacer(modifier = Modifier)
          }
          DropdownMenuItem(
            text = { Text(stringResource(id = R.string.pref_pgp_key_manager_export_public)) },
            onClick = {
              isMenuExpanded = false
              onExportPublicClick(identifier)
            },
          )
          HorizontalDivider(modifier = Modifier.padding(top = SpacingLarge))
          DropdownMenuItem(
            text = {
              Text(stringResource(id = R.string.delete))
              /* Icon(
                painter = painterResource(R.drawable.ic_delete_24dp),
                stringResource(id = R.string.delete),
              ) */
            },
            onClick = {
              isMenuExpanded = false
              isDeleting = true
            },
          )
        }
      }
    }
  }
}

@Suppress("NOTHING_TO_INLINE")
@Composable
private inline fun DeleteConfirmationDialog(
  isDeleting: Boolean,
  noinline onDismiss: () -> Unit,
  noinline onConfirm: () -> Unit,
) {
  if (isDeleting) {
    AlertDialog(
      onDismissRequest = onDismiss,
      title = {
        Row(verticalAlignment = Alignment.CenterVertically) {
          Icon(
            painter = painterResource(id = R.drawable.ic_warning_red_24dp),
            contentDescription = null,
            tint = Color.Unspecified,
          )
          Spacer(modifier = Modifier.width(SpacingLarge))
          Text(text = stringResource(R.string.pgp_key_manager_delete_confirmation_dialog_title))
        }
      },
      text = {
        Text(text = stringResource(R.string.pgp_key_manager_delete_confirmation_dialog_message))
      },
      confirmButton = {
        TextButton(onClick = onConfirm) { Text(text = stringResource(R.string.delete)) }
      },
      dismissButton = {
        TextButton(onClick = onDismiss) {
          Text(text = stringResource(R.string.dialog_do_not_delete))
        }
      },
    )
  }
}

@Preview
@Composable
private fun KeyListPreview() {
  APSTheme {
    Box(modifier = Modifier.background(MaterialTheme.colorScheme.background)) {
      KeyList(
        identifiers =
          listOfNotNull(
              PGPIdentifier.fromString("ultramicroscopicsilicovolcanoconiosis@example.com"),
              PGPIdentifier.fromString("0xB950AE2813841585"),
            )
            .toPersistentList(),
        hasSecretKey = { _ -> true },
        onChangePassphraseClick = {},
        onDeleteItemClick = {},
        onExportItemClick = {},
        onExportPublicClick = {},
      )
    }
  }
}

@Preview
@Composable
private fun EmptyKeyListPreview() {
  APSTheme {
    Box(modifier = Modifier.background(MaterialTheme.colorScheme.background)) {
      KeyList(
        identifiers = persistentListOf(),
        hasSecretKey = { _ -> true },
        onChangePassphraseClick = {},
        onDeleteItemClick = {},
        onExportItemClick = {},
        onExportPublicClick = {},
      )
    }
  }
}
