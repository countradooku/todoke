// Point to share (PROTOCOL §10.4), Android to Android with ultra-wideband.
// While a screen of the app shows and UWB is on and allowed, this device
// can be pointed at: contacts in sessions learn so, and a contact that
// points gets a fresh controlee session of ours for each ranging. Pointing
// prepares a few controller sessions (each address serves one ranging) and
// ranges with every nearby contact that accepts; the bearings it measures
// pick the contact the user points at. Ranging is a hint for the screen
// only: sending still needs the user's choice and the receiver's consent.

package org.todoke.android.radio

import android.content.Context
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.todoke.android.core.Backend
import org.todoke.ffi.CoreEvent
import org.todoke.ffi.RangingInfo
import org.todoke.ffi.UwbController

/** Where a contact is, as ranging last measured it. */
data class Bearing(val contact: String, val meters: Float?, val azimuth: Float?)

/** The platform's ultra-wideband (the play build; none in the F-Droid one). */
interface Uwb {
    suspend fun available(): Boolean

    /** `count` fresh controller sessions, kept until used or forgotten. */
    suspend fun controllers(count: Int): List<UwbController>

    /** Ranges as the controller with an accepted target, until cancelled. */
    fun controller(target: RangingInfo): Flow<Bearing>

    /** A fresh controlee session's address, kept until used or forgotten. */
    suspend fun controlee(): UShort

    /** Ranges as the controlee at `address`, until cancelled. */
    fun controlee(ranging: RangingInfo, address: UShort): Flow<Bearing>

    /** Drops the sessions prepared and not used. */
    fun forget()
}

class Pointing(
    private val backend: Backend,
    private val uwb: Uwb?,
    /** Whether a screen of the app shows. */
    private val foreground: StateFlow<Boolean>,
    /** Whether ranging is allowed (the permission). */
    private val allowed: () -> Boolean,
    private val scope: CoroutineScope,
) {
    constructor(context: Context, backend: Backend, uwb: Uwb?, radios: Radios, scope: CoroutineScope) :
        this(backend, uwb, radios.foreground, { NearbyPermissions.uwbGranted(context) }, scope)

    private val _bearings = MutableStateFlow<Map<String, Bearing>>(emptyMap())
    private val _pointing = MutableStateFlow(false)
    private val _ready = MutableStateFlow(false)
    private val running = ConcurrentHashMap<UInt, Job>()

    /** The contacts ranged now, by fingerprint. */
    val bearings: StateFlow<Map<String, Bearing>> get() = _bearings

    val pointing: StateFlow<Boolean> get() = _pointing

    /** Whether this device can point and be pointed at now. */
    val ready: StateFlow<Boolean> get() = _ready

    init {
        if (uwb != null) {
            scope.launch { foreground.collect { refresh() } }
            scope.launch {
                backend.events().collect { event ->
                    when (event) {
                        is CoreEvent.RangingRequested -> answer(event.ranging)
                        is CoreEvent.PointTarget -> range(event.ranging)
                        is CoreEvent.RangingStopped -> ended(event.contact, event.sessionId)
                        else -> {}
                    }
                }
            }
        }
    }

    /** Checks UWB again (after a permission was granted, say). */
    suspend fun refresh() {
        val uwb = uwb ?: return
        val ready = foreground.value && allowed() && runCatching { uwb.available() }.getOrDefault(false)
        _ready.value = ready
        runCatching { backend.setRangingReady(ready) }
        if (!ready) stop()
    }

    /** Points at up to `nearby` contacts (at most four rangings at once). */
    suspend fun start(nearby: Int) {
        val uwb = uwb ?: return
        if (!_ready.value) return
        stop()
        val controllers = uwb.controllers(nearby.coerceIn(1, MAX_TARGETS))
        backend.pointStart(controllers)
        _pointing.value = true
    }

    suspend fun stop() {
        if (_pointing.value) runCatching { backend.pointStop() }
        _pointing.value = false
        running.values.forEach { it.cancel() }
        running.clear()
        _bearings.value = emptyMap()
        uwb?.forget()
    }

    private suspend fun answer(ranging: RangingInfo) {
        val uwb = uwb
        val address = if (uwb != null && _ready.value) runCatching { uwb.controlee() }.getOrNull() else null
        if (uwb == null || address == null) {
            runCatching { backend.refuseRanging(ranging.contact, ranging.sessionId) }
            return
        }
        val accepted = runCatching { backend.acceptRanging(ranging.contact, ranging.sessionId, address) }
        if (accepted.isFailure) return
        running[ranging.sessionId] = scope.launch {
            runCatching { uwb.controlee(ranging, address).collect {} }
        }
    }

    private fun range(target: RangingInfo) {
        val uwb = uwb ?: return
        running[target.sessionId] = scope.launch {
            runCatching {
                uwb.controller(target).collect { bearing -> _bearings.update { it + (bearing.contact to bearing) } }
            }
        }
    }

    private fun ended(contact: String, sessionId: UInt) {
        running.remove(sessionId)?.cancel()
        _bearings.update { it - contact }
    }

    private companion object {
        const val MAX_TARGETS = 4
    }
}
