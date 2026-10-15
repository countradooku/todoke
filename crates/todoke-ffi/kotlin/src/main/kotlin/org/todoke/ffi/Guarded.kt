// A todoke object shared across threads or coroutines, closed only after
// every call on it has finished.
//
// The generated close() frees the Rust object at once; a call that has
// started on another thread may still be reading it (BoltFFI #664). Guarded
// counts the calls in progress and makes close() wait for them, and refuses
// calls after close. Suspending calls count until they finish, wherever
// they resume.

package org.todoke.ffi

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class Guarded<T : AutoCloseable>(private val value: T) : AutoCloseable {
    private val inFlight = AtomicInteger(0)
    private val closed = AtomicBoolean(false)

    private fun enter() {
        inFlight.incrementAndGet()
        if (closed.get()) {
            inFlight.decrementAndGet()
            throw IllegalStateException("closed")
        }
    }

    private fun leave() {
        inFlight.decrementAndGet()
    }

    /** Runs [block] with the object; it is not freed until [block] returns. */
    fun <R> call(block: (T) -> R): R {
        enter()
        try {
            return block(value)
        } finally {
            leave()
        }
    }

    /** As [call], for suspending calls: counted until they finish. */
    suspend fun <R> callSuspending(block: suspend (T) -> R): R {
        enter()
        try {
            return block(value)
        } finally {
            leave()
        }
    }

    /** Refuses new calls, waits for those in progress, then frees the object. */
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        // A call may last minutes (offering a large folder hashes it): wait
        // without spinning.
        while (inFlight.get() != 0) {
            Thread.sleep(1)
        }
        value.close()
    }
}
