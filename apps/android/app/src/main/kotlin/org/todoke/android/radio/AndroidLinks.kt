// The core's direct Wi-Fi links on Android (PROTOCOL §10.2): Wi-Fi Aware
// data paths, Wi-Fi Direct groups, and joining another device's hotspot,
// each with the platform's app-scoped, temporary mechanism. The core
// decides when (only for a transfer the user started or accepted), makes
// the credentials, and runs the session over the link; this only brings
// links up and down. The core calls it on its own threads, which block
// here while a link comes up; callbacks arrive on a radio thread of ours.
//
// Nothing here takes part while the needed permission is missing, Wi-Fi is
// off, or the app is in the background with no transfer running (links
// exist only for transfers: no radio work without one).

@file:OptIn(ExperimentalUnsignedTypes::class)

package org.todoke.android.radio

import android.content.Context
import android.net.Network
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import android.system.Os
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import org.todoke.ffi.LinkAbilities
import org.todoke.ffi.LinkError
import org.todoke.ffi.LinkKind
import org.todoke.ffi.LinkLease
import org.todoke.ffi.LinkRequest
import org.todoke.ffi.LinkSecurity
import org.todoke.ffi.WifiLinks

/** A link that is up, until released. */
internal class Held(
    val local: String,
    val host: String?,
    val index: Int,
    /** The link's own network, when sockets must be bound to it. */
    val network: Network?,
    /** For a Wi-Fi Aware publisher: the interfaces its data path may use. */
    val scopes: List<Int> = emptyList(),
    private val teardown: () -> Unit,
) {
    fun release() {
        runCatching { teardown() }
    }
}

class AndroidLinks(
    private val context: Context,
    /** Whether radio work is allowed now (foreground, or a transfer runs). */
    private val active: () -> Boolean,
) : WifiLinks {
    private val leases = ConcurrentHashMap<ULong, Held>()
    private val ids = AtomicLong(0)
    private val thread = HandlerThread("todoke-radio").apply { start() }
    private val handler = Handler(thread.looper)
    private val direct = WifiDirect(context, handler)
    private val aware = Aware(context, handler)
    private val hotspot = HotspotJoin(context, handler)
    private val hotspotHost = HotspotHost(context, handler)

    override fun abilities(): LinkAbilities {
        val none = LinkAbilities(emptyList(), emptyList(), emptyList())
        if (!active() || !NearbyPermissions.wifiGranted(context) || Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return none
        }
        val host = mutableListOf<LinkKind>()
        val join = mutableListOf<LinkKind>()
        val security = mutableListOf<LinkSecurity>()
        // In the order of preference (§10.2): Aware, Wi-Fi Direct, hotspot.
        if (aware.available()) {
            join += LinkKind.WIFI_AWARE
            if (aware.canPublish()) host += LinkKind.WIFI_AWARE
            security += aware.securities()
        }
        if (direct.available()) {
            host += LinkKind.WIFI_DIRECT
            join += LinkKind.WIFI_DIRECT
        }
        if (hotspotHost.available()) host += LinkKind.HOTSPOT
        if (hotspot.available()) join += LinkKind.HOTSPOT
        if (direct.available() || hotspot.available()) security += hotspot.securities()
        return LinkAbilities(host, join, security.distinct())
    }

    override fun host(request: LinkRequest): LinkLease = keep(
        request,
        when (request.kind) {
            LinkKind.WIFI_DIRECT -> direct::host
            LinkKind.WIFI_AWARE -> aware::host
            LinkKind.HOTSPOT -> hotspotHost::host
        },
    )

    override fun join(request: LinkRequest): LinkLease = keep(
        request,
        when (request.kind) {
            LinkKind.WIFI_DIRECT -> direct::join
            LinkKind.WIFI_AWARE -> aware::join
            LinkKind.HOTSPOT -> hotspot::join
        },
    )

    /** Brings the link up and keeps it under a fresh ID; the secret is
     * wiped from the request once the platform has it. */
    private fun keep(request: LinkRequest, up: (LinkRequest) -> Held): LinkLease {
        val held = try {
            if (!active()) throw failed("not now: no transfer runs")
            up(request)
        } catch (error: LinkError) {
            throw error
        } catch (error: SecurityException) {
            throw failed("the permission for nearby Wi-Fi devices is missing")
        } catch (error: Exception) {
            throw failed(error.message ?: error.javaClass.simpleName)
        } finally {
            request.secret.fill(0)
        }
        val id = ids.incrementAndGet().toULong()
        leases[id] = held
        return LinkLease(
            id = id,
            local = held.local,
            host = held.host,
            `interface` = held.index.toUInt(),
            bindSockets = held.network != null,
            scopes = held.scopes.map { it.toUInt() }.toUIntArray(),
        )
    }

    override fun bindSocket(lease: ULong, socket: Long) {
        val network = leases[lease]?.network ?: throw LinkError.Closed
        // A duplicate of the core's descriptor: the binding is the socket's,
        // so it holds for the core's copy; the duplicate is closed here.
        ParcelFileDescriptor.fromFd(socket.toInt()).use { network.bindSocket(it.fileDescriptor) }
    }

    override fun release(lease: ULong) {
        leases.remove(lease)?.release()
    }
}

internal fun failed(message: String) = LinkError.Failed(message)

/** An address as the core reads it: no IPv6 scope suffix. */
internal fun InetAddress.text(): String = hostAddress.orEmpty().substringBefore('%')

internal fun InetAddress.usableV4() = this is Inet4Address && !isLoopbackAddress

internal fun InetAddress.linkLocalV6() = this is Inet6Address && isLinkLocalAddress

/** The index of the interface `name`, or 0. */
internal fun indexOf(name: String?): Int =
    if (name == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
        0
    } else {
        runCatching { Os.if_nametoindex(name) }.getOrDefault(0)
    }
