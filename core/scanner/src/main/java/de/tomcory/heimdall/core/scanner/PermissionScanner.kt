package de.tomcory.heimdall.core.scanner

import android.content.pm.PackageInfo
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.AppXPermission
import de.tomcory.heimdall.core.database.entity.Permission
import timber.log.Timber
import javax.inject.Inject

class PermissionScanner @Inject constructor(
    private val database: HeimdallDatabase
) {

    /**
     * List of all dangerous permissions as of Android 13
     */
    private val dangerousPermissions = listOf(
        "android.permission.ACCEPT_HANDOVER",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_MEDIA_LOCATION",
        "android.permission.ACTIVITY_RECOGNITION",
        "com.android.voicemail.permission.ADD_VOICEMAIL",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.BLUETOOTH_ADVERTISE",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.BODY_SENSORS",
        "android.permission.BODY_SENSORS_BACKGROUND",
        "android.permission.CALL_PHONE",
        "android.permission.CAMERA",
        "android.permission.GET_ACCOUNTS",
        "android.permission.NEARBY_WIFI_DEVICES",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.READ_CALENDAR",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_MMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECORD_AUDIO",
        "android.permission.SEND_SMS",
        "android.permission.USE_SIP",
        "android.permission.UWB_RANGING",
        "android.permission.WRITE_CALENDAR",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.WRITE_CONTACTS",
        "android.permission.WRITE_EXTERNAL_STORAGE"
    )

    suspend fun scanApp(packageInfo: PackageInfo) {

        Timber.d("Scanning permissions of ${packageInfo.packageName}")

        val permissions = packageInfo.requestedPermissions?.toList()

        Timber.d("Permissions of ${packageInfo.packageName}: $permissions")

        // insert permissions into database
        permissions
            ?.map { permission -> Permission(permission, dangerousPermissions.contains(permission)) }
            ?.let { database.permissionDao().insert(*it.toTypedArray()) }

        // insert app-permission cross-reference into database
        permissions
            ?.map { permission -> AppXPermission(packageInfo.packageName, permission) }
            ?.let { database.appXPermissionDao().insert(*it.toTypedArray()) }
    }
}