// The screens' state, from the core only: every change comes from an answer
// or an event. Proximity and progress carry no event, so status, contacts,
// and transfers are fetched every two seconds (cheap requests), as on the
// desktop.

package org.todoke.android.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.todoke.android.core.Backend
import org.todoke.android.core.Picked
import org.todoke.ffi.Contact
import org.todoke.ffi.CoreEvent
import org.todoke.ffi.HistoryItem
import org.todoke.ffi.Offer
import org.todoke.ffi.Status
import org.todoke.ffi.Transfer

data class UiState(
    val status: Status? = null,
    val contacts: List<Contact> = emptyList(),
    val transfers: List<Transfer> = emptyList(),
    val offers: List<Offer> = emptyList(),
    val history: List<HistoryItem> = emptyList(),
    /** A short message for people (an answer the core refused, say). */
    val notice: String? = null,
)

class AppViewModel(val backend: Backend) : ViewModel() {
    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> get() = _state

    init {
        viewModelScope.launch {
            while (true) {
                refresh()
                delay(POLL_MS)
            }
        }
        viewModelScope.launch {
            backend.events().collect { event ->
                when (event) {
                    is CoreEvent.Missed, is CoreEvent.OfferReceived, is CoreEvent.Ended,
                    is CoreEvent.Completed, is CoreEvent.Delivered, is CoreEvent.Paired -> refresh()
                    else -> refreshTransfers()
                }
            }
        }
    }

    suspend fun refresh() {
        runCatching {
            val status = backend.status()
            val contacts = backend.contacts()
            val transfers = backend.transfers()
            val offers = backend.offers()
            _state.update { it.copy(status = status, contacts = contacts, transfers = transfers, offers = offers) }
        }
    }

    private suspend fun refreshTransfers() {
        runCatching { backend.transfers() }.onSuccess { transfers -> _state.update { it.copy(transfers = transfers) } }
    }

    fun loadHistory() = viewModelScope.launch {
        runCatching { backend.history() }.onSuccess { history -> _state.update { it.copy(history = history) } }
    }

    private fun act(block: suspend () -> Unit) = viewModelScope.launch {
        try {
            block()
        } catch (error: Exception) {
            _state.update { it.copy(notice = error.message ?: error.toString()) }
        }
        refresh()
    }

    fun dismissNotice() = _state.update { it.copy(notice = null) }

    fun send(contact: String, documents: List<Picked>) = act { backend.send(contact, documents) }

    fun accept(transfer: String, files: List<UInt>) = act { backend.accept(transfer, files) }

    fun decline(transfer: String) = act { backend.decline(transfer) }

    fun cancel(transfer: String) = act { backend.cancel(transfer) }

    fun setHidden(hidden: Boolean) = act { backend.setHidden(hidden) }

    fun clearHistory() = act {
        backend.clearHistory()
        _state.update { it.copy(history = emptyList()) }
    }

    class Factory(private val backend: Backend) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T = AppViewModel(backend) as T
    }

    private companion object {
        const val POLL_MS = 2_000L
    }
}
