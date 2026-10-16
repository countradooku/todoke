// Wi-Fi Direct groups (PROTOCOL §10.2 kind 2), Android 10 and later: a
// group with exactly the offer's name and passphrase (WPA2-PSK, never
// persistent, never WPS), hosted or joined through WifiP2pConfig.Builder.
// The group owner's system DHCP names it as router and DNS server; it
// forwards nothing (Android does not tether groups). A group client's
// address on the group is not the device's default network, so nothing
// else takes the group's route or DNS.

package org.todoke.android.radio

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.WifiManager
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pGroup
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
import android.os.Build
import android.os.Handler
import androidx.annotation.RequiresApi
import java.net.NetworkInterface
import org.todoke.ffi.LinkRequest
import org.todoke.ffi.LinkSecurity

internal class WifiDirect(private val context: Context, private val handler: Handler) {
    private val manager: WifiP2pManager? = context.getSystemService(WifiP2pManager::class.java)

    fun available(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
            manager != null &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_DIRECT) &&
            context.getSystemService(WifiManager::class.java)?.isWifiEnabled == true

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun config(request: LinkRequest, owner: Boolean): WifiP2pConfig {
        if (request.security != LinkSecurity.WPA2) throw failed("Wi-Fi Direct groups are WPA2")
        return WifiP2pConfig.Builder()
            .setNetworkName(request.ssid)
            .setPassphrase(String(request.secret, Charsets.US_ASCII))
            .enablePersistentMode(false)
            .apply { if (owner) setGroupOperatingBand(WifiP2pConfig.GROUP_OWNER_BAND_AUTO) }
            .build()
    }

    @SuppressLint("MissingPermission")
    fun host(request: LinkRequest): Held {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) throw failed("Wi-Fi Direct groups need Android 10")
        val manager = manager ?: throw failed("this device has no Wi-Fi Direct")
        val channel = manager.initialize(context, handler.looper, null) ?: throw failed("Wi-Fi Direct is off")
        val teardown = {
            manager.removeGroup(channel, null)
            channel.close()
        }
        try {
            act("creating the group") { manager.createGroup(channel, config(request, owner = true), it) }
            val group = poll(STEP_MS, "the group") {
                group(manager, channel)?.takeIf { it.isGroupOwner && it.networkName == request.ssid }
            }
            val name = group.`interface`
            val local = poll(STEP_MS, "the group's address") { address(name) }
            return Held(local, null, indexOf(name), null, teardown = teardown)
        } catch (error: Throwable) {
            teardown()
            throw error
        }
    }

    @SuppressLint("MissingPermission")
    fun join(request: LinkRequest): Held {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) throw failed("Wi-Fi Direct groups need Android 10")
        val manager = manager ?: throw failed("this device has no Wi-Fi Direct")
        val channel = manager.initialize(context, handler.looper, null) ?: throw failed("Wi-Fi Direct is off")
        val teardown = {
            manager.cancelConnect(channel, null)
            manager.removeGroup(channel, null)
            channel.close()
        }
        val within = request.withinMs.toLong().takeIf { it > 0 } ?: STEP_MS
        try {
            act("joining the group") { manager.connect(channel, config(request, owner = false), it) }
            val owner = poll(within, "joining the group") {
                info(manager, channel)?.takeIf { it.groupFormed && !it.isGroupOwner }?.groupOwnerAddress
            }
            val name = poll(STEP_MS, "the group") { group(manager, channel)?.`interface` }
            val local = poll(STEP_MS, "an address on the group") { address(name) }
            return Held(local, owner.text(), indexOf(name), null, teardown = teardown)
        } catch (error: Throwable) {
            teardown()
            throw error
        }
    }

    private fun act(what: String, call: (WifiP2pManager.ActionListener) -> Unit) {
        val waiter = Waiter<Unit>()
        call(
            object : WifiP2pManager.ActionListener {
                override fun onSuccess() = waiter.done(Unit)

                override fun onFailure(reason: Int) = waiter.fail("$what failed (${reason(reason)})")
            },
        )
        waiter.await(STEP_MS, what)
    }

    @SuppressLint("MissingPermission")
    private fun group(manager: WifiP2pManager, channel: WifiP2pManager.Channel): WifiP2pGroup? {
        val waiter = Waiter<WifiP2pGroup?>()
        manager.requestGroupInfo(channel) { waiter.done(it) }
        return waiter.await(STEP_MS, "the group's state")
    }

    private fun info(manager: WifiP2pManager, channel: WifiP2pManager.Channel): WifiP2pInfo? {
        val waiter = Waiter<WifiP2pInfo?>()
        manager.requestConnectionInfo(channel) { waiter.done(it) }
        return waiter.await(STEP_MS, "the group's state")
    }

    /** This device's IPv4 address on the group's interface, once it has one. */
    private fun address(name: String?): String? =
        name?.let { runCatching { NetworkInterface.getByName(it) }.getOrNull() }
            ?.inetAddresses?.toList()?.firstOrNull { it.usableV4() }?.text()

    private fun reason(code: Int) = when (code) {
        WifiP2pManager.BUSY -> "busy"
        WifiP2pManager.P2P_UNSUPPORTED -> "unsupported"
        WifiP2pManager.ERROR -> "error"
        else -> "code $code"
    }
}
