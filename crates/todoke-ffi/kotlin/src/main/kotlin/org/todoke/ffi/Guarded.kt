// A todoke object shared across threads or coroutines, freed only after
// every call on it has finished.
//
// The generated close() frees the Rust object at once; a call that has
// started on another thread may still be reading it (BoltFFI #664). Guarded
// counts the calls in progress, refuses calls once closing, and frees the
// object after the last one: hold every shared Core, handle, and
// subscription through one, and never call the object's own close().

package org.todoke.ffi

import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.withContext

class Guarded<T : AutoCloseable>(private val value: T) : AutoCloseable {
    private val lock = ReentrantLock()
    private val idle = lock.newCondition()
    private var inFlight = 0
    private var closing = false
    private var freeing = false
    private var freed = false

    /** Calls of this object's in progress on the current thread. */
    private val inside = ThreadLocal.withInitial { 0 }

    /** The Guarded objects a coroutine is inside a call of. */
    private class Inside(val guards: Set<Guarded<*>>) : AbstractCoroutineContextElement(Key) {
        companion object Key : CoroutineContext.Key<Inside>
    }

    private fun enter() = lock.withLock {
        check(!closing) { "closed" }
        inFlight++
    }

    private fun leave() = lock.withLock {
        inFlight--
        if (inFlight == 0) idle.signalAll()
    }

    /** Runs [block] with the object; it is not freed until [block] returns. */
    fun <R> call(block: (T) -> R): R {
        enter()
        inside.set(inside.get() + 1)
        try {
            return block(value)
        } finally {
            inside.set(inside.get() - 1)
            leave()
        }
    }

    /** As [call], for suspending calls: counted until they finish. */
    suspend fun <R> callSuspending(block: suspend (T) -> R): R {
        enter()
        try {
            val outer = currentCoroutineContext()[Inside]?.guards.orEmpty()
            return withContext(Inside(outer + this)) { block(value) }
        } finally {
            leave()
        }
    }

    /**
     * Refuses new calls, waits for those in progress, then frees the object;
     * a second close() waits for the free too. It blocks (a call may last
     * minutes: offering a large folder hashes it), and an interrupt does not
     * cut the wait short (the interrupt stays set): never on the main
     * thread; use [closeSuspending] from coroutines.
     *
     * @throws IllegalStateException inside a call on this object, which
     *   would wait for itself.
     */
    override fun close() {
        check(inside.get() == 0) { "close() inside a call on this object would wait for itself" }
        var mine = false
        lock.withLock {
            closing = true
            while (!freed) {
                if (inFlight == 0 && !freeing) {
                    freeing = true
                    mine = true
                    break
                }
                idle.awaitUninterruptibly()
            }
        }
        if (mine) {
            try {
                value.close()
            } finally {
                lock.withLock {
                    freed = true
                    idle.signalAll()
                }
            }
        }
    }

    /**
     * [close] on an I/O thread, completed even if the caller is cancelled.
     *
     * @throws IllegalStateException inside a suspending call on this object.
     */
    suspend fun closeSuspending() {
        check(currentCoroutineContext()[Inside]?.guards?.contains(this) != true) {
            "close inside a call on this object would wait for itself"
        }
        withContext(Dispatchers.IO + NonCancellable) { close() }
    }
}
