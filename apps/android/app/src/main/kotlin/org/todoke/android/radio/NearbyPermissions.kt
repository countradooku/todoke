// The permissions nearby radios need, each the narrowest the platform has
// (PROTOCOL §10.3): NEARBY_WIFI_DEVICES, declared neverForLocation (todoke
// never asks for location); UWB_RANGING for pointing. Each is explained once,
// before the system asks; without one, its feature is off and everything
// else works (transfers over the LAN and the relay).

package org.todoke.android.radio

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat

object NearbyPermissions {
    /** What direct Wi-Fi links ask for. */
    val wifi: Array<String> = arrayOf(Manifest.permission.NEARBY_WIFI_DEVICES)

    /** What pointing asks for. */
    const val UWB = Manifest.permission.UWB_RANGING

    fun wifiGranted(context: Context): Boolean = granted(context, wifi.first())

    fun uwbGranted(context: Context): Boolean = granted(context, UWB)

    private fun granted(context: Context, permission: String) =
        ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
}
