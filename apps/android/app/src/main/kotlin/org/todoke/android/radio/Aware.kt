// Wi-Fi Aware data paths (PROTOCOL §10.2 kind 1). The host publishes the
// service `todoke` with the offer's eight bytes of service information and
// accepts a data path from any subscriber holding the PMK; the joiner
// subscribes, and requests a data path to each matching publisher once,
// until one comes up. The data path is the app's network: never open
// (always the PMK, NCS-SK-128, or NCS-SK-256 where the hardware has it),
// and it goes when the request is withdrawn.
//
// The host's address on the data path exists only once the joiner sets it
// up, after the offer: the host names the Aware data interfaces instead, and
// the core accepts only link-local peers arriving on them.

package org.todoke.android.radio

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.aware.AttachCallback
import android.net.wifi.aware.Characteristics
import android.net.wifi.aware.DiscoverySessionCallback
import android.net.wifi.aware.PeerHandle
import android.net.wifi.aware.PublishConfig
import android.net.wifi.aware.PublishDiscoverySession
import android.net.wifi.aware.SubscribeConfig
import android.net.wifi.aware.SubscribeDiscoverySession
import android.net.wifi.aware.WifiAwareDataPathSecurityConfig
import android.net.wifi.aware.WifiAwareManager
import android.net.wifi.aware.WifiAwareNetworkInfo
import android.net.wifi.aware.WifiAwareNetworkSpecifier
import android.net.wifi.aware.WifiAwareSession
import android.os.Handler
import java.util.Collections
import org.todoke.ffi.LinkRequest
import org.todoke.ffi.LinkSecurity

internal class Aware(private val context: Context, private val handler: Handler) {
    private val manager: WifiAwareManager? by lazy {
        if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE)) {
            context.getSystemService(WifiAwareManager::class.java)
        } else {
            null
        }
    }
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)

    fun available(): Boolean = manager?.isAvailable == true

    /** Hosting needs a data interface to listen on. */
    fun canPublish(): Boolean = available() && interfaces().isNotEmpty()

    fun securities(): List<LinkSecurity> = buildList {
        if (sk256()) add(LinkSecurity.AWARE_SK256)
        add(LinkSecurity.AWARE_SK128)
    }

    private fun sk256(): Boolean =
        (manager?.characteristics?.supportedCipherSuites ?: 0) and
            Characteristics.WIFI_AWARE_CIPHER_SUITE_NCS_SK_256 != 0

    /** The Aware data interfaces' indexes (the data path comes up on one). */
    private fun interfaces(): List<Int> = (0 until MAX_INTERFACES).map { indexOf("aware_data$it") }.filter { it > 0 }
    private fun secure(builder: WifiAwareNetworkSpecifier.Builder, request: LinkRequest): WifiAwareNetworkSpecifier {
        if (request.secret.size != PMK_LEN) throw failed("not a data path key")
        when (request.security) {
            LinkSecurity.AWARE_SK128 -> builder.setPmk(request.secret.copyOf())
            LinkSecurity.AWARE_SK256 -> {
                if (!sk256()) throw failed("no NCS-SK-256 here")
                builder.setDataPathSecurityConfig(
                    WifiAwareDataPathSecurityConfig.Builder(Characteristics.WIFI_AWARE_CIPHER_SUITE_NCS_SK_256)
                        .setPmk(request.secret.copyOf())
                        .build(),
                )
            }
            else -> throw failed("not a Wi-Fi Aware security")
        }
        return builder.build()
    }

    @SuppressLint("MissingPermission")
    private fun attach(): WifiAwareSession {
        val manager = manager ?: throw failed("this device has no Wi-Fi Aware")
        val waiter = Waiter<WifiAwareSession>()
        manager.attach(
            object : AttachCallback() {
                override fun onAttached(session: WifiAwareSession) = waiter.done(session)

                override fun onAttachFailed() = waiter.fail("Wi-Fi Aware is unavailable")
            },
            handler,
        )
        return waiter.await(STEP_MS, "starting Wi-Fi Aware")
    }

    @SuppressLint("MissingPermission")
    fun host(request: LinkRequest): Held {
        val connectivity = connectivity ?: throw failed("no connectivity service")
        val scopes = interfaces().ifEmpty { throw failed("no Wi-Fi Aware data interface") }
        val session = attach()
        val published = Waiter<PublishDiscoverySession>()
        val config = PublishConfig.Builder()
            .setServiceName(SERVICE)
            .setServiceSpecificInfo(request.serviceInfo)
            .setPublishType(PublishConfig.PUBLISH_TYPE_UNSOLICITED)
            .build()
        session.publish(
            config,
            object : DiscoverySessionCallback() {
                override fun onPublishStarted(session: PublishDiscoverySession) = published.done(session)

                override fun onSessionConfigFailed() = published.fail("publishing failed")
            },
            handler,
        )
        var publish: PublishDiscoverySession? = null
        val callback = object : ConnectivityManager.NetworkCallback() {}
        val teardown = {
            runCatching { connectivity.unregisterNetworkCallback(callback) }
            publish?.close()
            session.close()
        }
        try {
            publish = published.await(STEP_MS, "publishing")
            // Any subscriber with the PMK: its data path comes up later,
            // when the joiner requests it.
            val specifier = secure(WifiAwareNetworkSpecifier.Builder(publish), request)
            connectivity.requestNetwork(aware(specifier), callback, handler)
            return Held("::", null, 0, null, scopes, teardown)
        } catch (error: Throwable) {
            teardown()
            throw error
        }
    }

    @SuppressLint("MissingPermission")
    fun join(request: LinkRequest): Held {
        val connectivity = connectivity ?: throw failed("no connectivity service")
        val within = request.withinMs.toLong().takeIf { it > 0 } ?: STEP_MS
        val deadline = System.currentTimeMillis() + within
        val session = attach()
        val up = Waiter<Pair<Network, String>>()
        // Data paths that could not come up; when every publisher tried has
        // failed, the join fails at once rather than at the deadline.
        val unavailable = java.util.concurrent.atomic.AtomicInteger()
        val callbacks = Collections.synchronizedList(mutableListOf<ConnectivityManager.NetworkCallback>())
        val tried = Collections.synchronizedSet(mutableSetOf<PeerHandle>())
        var subscribe: SubscribeDiscoverySession? = null
        val discovery = object : DiscoverySessionCallback() {
            override fun onSubscribeStarted(started: SubscribeDiscoverySession) {
                subscribe = started
            }

            override fun onSessionConfigFailed() = up.fail("subscribing failed")

            override fun onServiceDiscovered(peer: PeerHandle, info: ByteArray?, filter: MutableList<ByteArray>?) {
                val session = subscribe ?: return
                // Only the offer's publisher, and each at most once.
                if (info == null || !info.contentEquals(request.serviceInfo) || !tried.add(peer)) return
                val specifier = runCatching { secure(WifiAwareNetworkSpecifier.Builder(session, peer), request) }
                    .getOrElse { return up.fail(it.message ?: "no data path") }
                val callback = object : ConnectivityManager.NetworkCallback() {
                    private var properties: LinkProperties? = null
                    private var peerAddress: String? = null

                    override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                        val info = capabilities.transportInfo as? WifiAwareNetworkInfo ?: return
                        peerAddress = info.peerIpv6Addr?.text()
                        ready(network)
                    }

                    override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                        properties = linkProperties
                        ready(network)
                    }

                    override fun onUnavailable() {
                        if (unavailable.incrementAndGet() >= tried.size) up.fail("no Wi-Fi Aware data path came up")
                    }

                    private fun ready(network: Network) {
                        val host = peerAddress ?: return
                        if (properties?.linkAddresses?.any { it.address.linkLocalV6() } == true) up.done(network to host)
                    }
                }
                callbacks += callback
                val left = (deadline - System.currentTimeMillis()).coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
                connectivity.requestNetwork(aware(specifier), callback, handler, left)
            }
        }
        val teardown = {
            callbacks.toList().forEach { runCatching { connectivity.unregisterNetworkCallback(it) } }
            subscribe?.close()
            session.close()
        }
        try {
            val config = SubscribeConfig.Builder()
                .setServiceName(SERVICE)
                .setSubscribeType(SubscribeConfig.SUBSCRIBE_TYPE_PASSIVE)
                .build()
            session.subscribe(config, discovery, handler)
            val (network, host) = up.await(within, "the Wi-Fi Aware data path")
            val properties = connectivity.getLinkProperties(network) ?: throw failed("the data path went")
            val local = properties.linkAddresses.first { it.address.linkLocalV6() }.address
            return Held(local.text(), host, indexOf(properties.interfaceName), network, teardown = teardown)
        } catch (error: Throwable) {
            teardown()
            throw error
        }
    }
    private fun aware(specifier: WifiAwareNetworkSpecifier) = NetworkRequest.Builder()
        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI_AWARE)
        .setNetworkSpecifier(specifier)
        .build()

    private companion object {
        const val SERVICE = "todoke"
        const val PMK_LEN = 32
        const val MAX_INTERFACES = 4
    }
}
