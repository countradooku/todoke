// Ultra-wideband through androidx.core.uwb (the play build: the library
// depends on Google Play services). FiRa provisioned-STS unicast DS-TWR
// with the session ID and key the core made for each ranging; every
// address serves one ranging, so each comes from a fresh session scope.

package org.todoke.android.radio

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.uwb.RangingParameters
import androidx.core.uwb.RangingResult
import androidx.core.uwb.UwbAddress
import androidx.core.uwb.UwbClientSessionScope
import androidx.core.uwb.UwbComplexChannel
import androidx.core.uwb.UwbControleeSessionScope
import androidx.core.uwb.UwbControllerSessionScope
import androidx.core.uwb.UwbDevice
import androidx.core.uwb.UwbManager
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.mapNotNull
import org.todoke.ffi.RangingInfo
import org.todoke.ffi.UwbController

fun platformUwb(context: Context): Uwb? =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && context.packageManager.hasSystemFeature(PackageManager.FEATURE_UWB)) {
        PlayUwb(context)
    } else {
        null
    }

private class PlayUwb(context: Context) : Uwb {
    private val manager = UwbManager.createInstance(context)
    private val controllers = ConcurrentHashMap<UShort, UwbControllerSessionScope>()
    private val controlees = ConcurrentHashMap<UShort, UwbControleeSessionScope>()

    override suspend fun available(): Boolean = manager.isAvailable()

    override suspend fun controllers(count: Int): List<UwbController> = (0 until count).map {
        val scope = manager.controllerSessionScope()
        val address = short(scope.localAddress)
        controllers[address] = scope
        val channel = scope.uwbComplexChannel
        UwbController(address, channel.channel.toUByte(), channel.preambleIndex.toUByte())
    }

    override fun controller(target: RangingInfo): Flow<Bearing> {
        val scope = controllers.remove(target.controller) ?: return emptyFlow()
        val controlee = target.controlee ?: return emptyFlow()
        return range(scope, target, controlee)
    }

    override suspend fun controlee(): UShort {
        val scope = manager.controleeSessionScope()
        val address = short(scope.localAddress)
        controlees[address] = scope
        return address
    }

    override fun controlee(ranging: RangingInfo, address: UShort): Flow<Bearing> {
        val scope = controlees.remove(address) ?: return emptyFlow()
        return range(scope, ranging, ranging.controller)
    }

    override fun forget() {
        controllers.clear()
        controlees.clear()
    }

    private fun range(scope: UwbClientSessionScope, ranging: RangingInfo, peer: UShort): Flow<Bearing> {
        val parameters = RangingParameters(
            uwbConfigType = RangingParameters.CONFIG_PROVISIONED_UNICAST_DS_TWR,
            sessionId = ranging.sessionId.toInt(),
            subSessionId = 0,
            sessionKeyInfo = ranging.stsKey,
            subSessionKeyInfo = null,
            complexChannel = UwbComplexChannel(ranging.channel.toInt(), ranging.preamble.toInt()),
            peerDevices = listOf(UwbDevice(UwbAddress(bytes(peer)))),
            updateRateType = RangingParameters.RANGING_UPDATE_RATE_AUTOMATIC,
        )
        return scope.prepareSession(parameters).mapNotNull { result ->
            (result as? RangingResult.RangingResultPosition)?.position?.let { position ->
                Bearing(ranging.contact, position.distance?.value, position.azimuth?.value)
            }
        }
    }

    /** A short address as the core carries it: its two bytes, big-endian. */
    private fun short(address: UwbAddress): UShort {
        val bytes = address.address
        return ((bytes[0].toInt() and 0xff shl 8) or (bytes[1].toInt() and 0xff)).toUShort()
    }

    private fun bytes(address: UShort) = byteArrayOf((address.toInt() shr 8).toByte(), address.toInt().toByte())
}
