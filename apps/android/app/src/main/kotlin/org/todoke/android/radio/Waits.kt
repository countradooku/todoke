// Waiting on the platform's callbacks from the core's blocking threads.

package org.todoke.android.radio

import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** The first value or failure a callback delivers. */
internal class Waiter<T> {
    private val future = CompletableFuture<T>()

    fun done(value: T) {
        future.complete(value)
    }

    fun fail(message: String) {
        future.completeExceptionally(failed(message))
    }

    /** The value, waiting at most `millis`. */
    fun await(millis: Long, what: String): T = try {
        future.get(millis.coerceAtLeast(1), TimeUnit.MILLISECONDS)
    } catch (error: TimeoutException) {
        throw failed("$what took too long")
    } catch (error: ExecutionException) {
        throw error.cause ?: error
    }
}

/** How long one platform step may take when the offer sets no deadline. */
internal const val STEP_MS = 30_000L

/** Polls `probe` until it answers, at most `millis`. */
internal fun <T : Any> poll(millis: Long, what: String, probe: () -> T?): T {
    val until = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(millis)
    while (System.nanoTime() < until) {
        probe()?.let { return it }
        Thread.sleep(200)
    }
    throw failed("$what took too long")
}
