package app.passwordstore.util.services

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.service.quicksettings.TileService
import app.passwordstore.ui.passwords.PasswordStore

class QuickSearchTileService : TileService() {
  override fun onClick() {
    super.onClick()
    val intent =
      Intent(this, PasswordStore::class.java).apply {
        action = Intent.ACTION_SEARCH
        flags = Intent.FLAG_ACTIVITY_NEW_TASK
      }

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
      val pendingIntent =
        PendingIntent.getActivity(
          this,
          0,
          intent,
          PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
      startActivityAndCollapse(pendingIntent)
    } else {
      @SuppressLint("StartActivityAndCollapseDeprecated") @Suppress("DEPRECATION")
      startActivityAndCollapse(intent)
    }
  }
}
