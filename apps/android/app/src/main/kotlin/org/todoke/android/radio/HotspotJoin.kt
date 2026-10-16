// Joining another device's hotspot (PROTOCOL §10.2 kind 3), Android 10 and
// later: a WifiNetworkSpecifier request for exactly the offer's network,
// without internet, so the network stays the app's and is never saved or
// suggested; the system asks the user once per request. Sockets are bound
// to it; it goes when the request is withdrawn.

package org.todoke.android.radio

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiManager
import android.net.wifi.WifiNetworkSpecifier
import android.os.Build
import android.os.Handler
import androidx.annotation.RequiresApi
import org.todoke.ffi.LinkRequest
import org.todoke.ffi.LinkSecurity

internal class HotspotJoin(private val context: Context, private val handler: Handler) {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val wifi = context.getSystemService(WifiManager::class.java)

    fun available(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && wifi?.isWifiEnabled == true

    /** What this device joins with (Wi-Fi Direct groups too: WPA2). */
    fun securities(): List<LinkSecurity> = buildList {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && wifi?.isWpa3SaeSupported == true) {
            add(LinkSecurity.WPA3)
            add(LinkSecurity.WPA3_TRANSITION)
        }
        add(LinkSecurity.WPA2)
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun specifier(request: LinkRequest): WifiNetworkSpecifier {
        val passphrase = String(request.secret, Charsets.US_ASCII)
        val sae = wifi?.isWpa3SaeSupported == true
        return WifiNetworkSpecifier.Builder().setSsid(request.ssid).apply {
            when (request.security) {
                LinkSecurity.WPA3 -> setWpa3Passphrase(passphrase)
                LinkSecurity.WPA3_TRANSITION -> if (sae) setWpa3Passphrase(passphrase) else setWpa2Passphrase(passphrase)
                LinkSecurity.WPA2 -> setWpa2Passphrase(passphrase)
                else -> throw failed("not a hotspot security")
            }
        }.build()
    }

    @SuppressLint("MissingPermission")
    fun join(request: LinkRequest): Held {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) throw failed("joining hotspots needs Android 10")
        val connectivity = connectivity ?: throw failed("no connectivity service")
        val networkRequest = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .setNetworkSpecifier(specifier(request))
            .build()
        val up = Waiter<Pair<Network, LinkProperties>>()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
                if (properties.linkAddresses.any { it.address.usableV4() }) up.done(network to properties)
            }

            override fun onUnavailable() = up.fail("the hotspot was not joined")
        }
        val within = request.withinMs.toLong().takeIf { it > 0 } ?: STEP_MS
        connectivity.requestNetwork(networkRequest, callback, handler, within.toInt().coerceAtLeast(1))
        val teardown = { connectivity.unregisterNetworkCallback(callback) }
        try {
            val (network, properties) = up.await(within, "joining the hotspot")
            val local = properties.linkAddresses.first { it.address.usableV4() }.address
            // The hotspot's own address: its DHCP server, else its router.
            val host = (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) properties.dhcpServerAddress else null)
                ?: properties.routes.firstOrNull { it.isDefaultRoute && it.gateway?.usableV4() == true }?.gateway
                ?: throw failed("the hotspot named no address")
            return Held(local.text(), host.text(), indexOf(properties.interfaceName), network, teardown = teardown)
        } catch (error: Throwable) {
            teardown()
            throw error
        }
    }
}
