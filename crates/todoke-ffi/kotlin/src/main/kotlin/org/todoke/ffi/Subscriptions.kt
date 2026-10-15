// The core's events as a Flow: a subscription read on an I/O thread, in
// batches, ended (and freed) when collection stops or the core stops.

package org.todoke.ffi

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.yield

/**
 * The core's events from the moment collection starts. A
 * [CoreEvent.Missed] says events were lost: read the offers and transfers
 * again. The flow completes when the core stops.
 *
 * @throws TodokeError.State beyond 16 subscriptions at once.
 */
fun Guarded<Core>.events(batch: UInt = 64u): Flow<CoreEvent> = flow {
    // Only this collector reads the subscription: no other thread can free
    // it during a read.
    val events = call { it.subscribe() }
    try {
        while (true) {
            // Each read blocks up to 250 ms: between reads, give the thread
            // up (and stop if cancelled), even where flowOn fused with an
            // I/O collector.
            yield()
            val next = try {
                events.next(batch, 250u)
            } catch (_: TodokeError.State) {
                break
            }
            for (event in next) emit(event)
        }
    } finally {
        events.stop()
        events.close()
    }
}.flowOn(Dispatchers.IO)
