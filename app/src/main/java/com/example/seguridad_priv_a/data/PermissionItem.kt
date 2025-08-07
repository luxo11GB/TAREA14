package com.example.seguridad_priv_a.data

import android.content.Intent

data class PermissionItem(
    val name: String,
    val description: String,
    val permission: String?,
    val activityClass: Class<*>?,
    val iconResource: Int = android.R.drawable.ic_menu_send,
    var status: PermissionStatus = PermissionStatus.NOT_REQUESTED
)

enum class PermissionStatus {
    NOT_REQUESTED,
    GRANTED,
    DENIED
}

object PermissionHelper {
    fun getStatusText(status: PermissionStatus): String {
        return when (status) {
            PermissionStatus.GRANTED -> "✅ Otorgado"
            PermissionStatus.DENIED -> "❌ Denegado"
            PermissionStatus.NOT_REQUESTED -> "⏸️ No solicitado"
        }
    }
}