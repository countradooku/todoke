// Hosting a hotspot (PROTOCOL §10.2 kind 3) as a LocalOnlyHotspot with
// exactly the offer's name and passphrase, from Android 16 QPR2 (the first
// release that lets an app choose them). Local-only: Android shares no
// internet over it and forwards nothing; its DHCP names this device as
// router and DNS server, which §10.2 allows a host that cannot avoid it.
// Earlier releases cannot choose the name and passphrase, so they host no
// hotspot. The hotspot stops when the reservation is closed.

package org.todoke.android.radio

import android.annotation.SuppressLint
import android.content.Context
import android.net.wifi.SoftApConfiguration
import android.net.wifi.WifiManager
import android.net.wifi.WifiSsid
import android.os.Build
import android.os.Handler
import java.net.NetworkInterface
import java.util.concurrent.Executor
import org.todoke.ffi.LinkRequest
import org.todoke.ffi.LinkSecurity

internal class HotspotHost(private val context: Context, private val handler: Handler) {
    private val wifi = context.getSystemService(WifiManager::class.java)

    fun available(): Boolean = Build.VERSION.SDK_INT_FULL >= Build.VERSION_CODES_FULL.BAKLAVA_1 && wifi != null

    // Lint cannot read SDK_INT_FULL checks: available() is Android 16 QPR2.
    @SuppressLint("MissingPermission", "NewApi")
    fun host(request: LinkRequest): Held {
        if (!available()) throw failed("hosting a hotspot needs Android 16 QPR2")
        return start(wifi ?: throw failed("no Wi-Fi"), request)
    }

    /** Only after available(): Android 16 QPR2. */
    @SuppressLint("MissingPermission", "NewApi")
    private fun start(wifi: WifiManager, request: LinkRequest): Held {
        val type = when (request.security) {
            LinkSecurity.WPA3 -> SoftApConfiguration.SECURITY_TYPE_WPA3_SAE
            LinkSecurity.WPA3_TRANSITION -> SoftApConfiguration.SECURITY_TYPE_WPA3_SAE_TRANSITION
            LinkSecurity.WPA2 -> SoftApConfiguration.SECURITY_TYPE_WPA2_PSK
            else -> throw failed("not a hotspot security")
        }
        val config = SoftApConfiguration.Builder()
            .setWifiSsid(WifiSsid.fromBytes(request.ssid.toByteArray(Charsets.US_ASCII)))
            .setPassphrase(String(request.secret, Charsets.US_ASCII), type)
            .build()
        // The interfaces addressed before are never taken for the hotspot's.
        val before = addressed()
        val started = Waiter<WifiManager.LocalOnlyHotspotReservation>()
        val callback = object : WifiManager.LocalOnlyHotspotCallback() {
            override fun onStarted(reservation: WifiManager.LocalOnlyHotspotReservation) = started.done(reservation)

            override fun onFailed(reason: Int) = started.fail("the hotspot did not start ($reason)")
        }
        // A release whose platform lacks the flagged method fails here.
        try {
            wifi.startLocalOnlyHotspotWithConfiguration(config, Executor(handler::post), callback)
        } catch (error: LinkageError) {
            throw failed("this release cannot host a hotspot")
        }
        val reservation = started.await(STEP_MS, "starting the hotspot")
        val teardown = { reservation.close() }
        try {
            // Exactly the offer's network, or none.
            val ssid = reservation.softApConfiguration.wifiSsid?.bytes
            if (ssid == null || !ssid.contentEquals(request.ssid.toByteArray(Charsets.US_ASCII))) {
                throw failed("the hotspot is not the offer's network")
            }
            val (name, local) = poll(STEP_MS, "the hotspot's address") { addressed().entries.firstOrNull { it.key !in before } }
            return Held(local, null, indexOf(name), null, teardown = teardown)
        } catch (error: Throwable) {
            teardown()
            throw error
        }
    }

    /** Each up interface with an IPv4 address, by name. */
    private fun addressed(): Map<String, String> = runCatching {
        NetworkInterface.getNetworkInterfaces().toList()
            .filter { it.isUp && !it.isLoopback }
            .mapNotNull { nic -> nic.inetAddresses.toList().firstOrNull { it.usableV4() }?.let { nic.name to it.text() } }
            .toMap()
    }.getOrDefault(emptyMap())
}
