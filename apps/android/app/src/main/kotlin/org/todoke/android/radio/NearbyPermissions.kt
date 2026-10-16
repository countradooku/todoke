// The permissions nearby radios need, each the narrowest the platform has
// (PROTOCOL §10.3): on Android 13 and later NEARBY_WIFI_DEVICES, declared
// neverForLocation; location only before Android 13, where Wi-Fi Direct and
// Aware have no other; UWB_RANGING for pointing. Each is explained once,
// before the system asks; without one, its feature is off and everything
// else works (transfers over the LAN and the relay).

package org.todoke.android.radio

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat

object NearbyPermissions {
    /** What direct Wi-Fi links ask for. */
    val wifi: Array<String> = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU -> arrayOf(Manifest.permission.NEARBY_WIFI_DEVICES)
        // Android 12 grants fine location only together with coarse.
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION)
        else -> arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
    }

    /** What pointing asks for (Android 12 and later). */
    const val UWB = "android.permission.UWB_RANGING"

    fun wifiGranted(context: Context): Boolean = granted(context, wifi.first())

    fun uwbGranted(context: Context): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && granted(context, UWB)

    private fun granted(context: Context, permission: String) =
        ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
}
