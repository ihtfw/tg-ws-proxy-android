package org.flowseal.tgwsproxy.service

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.flowseal.tgwsproxy.proxy.Stats

/** What the proxy is doing, shared by the service, the notification and the screens. */
object ProxyState {

    sealed interface Status {
        data object Stopped : Status
        data object Starting : Status

        /**
         * @param listen the address the proxy listens on, "127.0.0.1:1443"
         * @param localLink the tg://proxy link for Telegram on this device
         * @param lanLink the link for other devices, when listening on all interfaces
         */
        data class Running(val listen: String, val localLink: String, val lanLink: String?) : Status

        /** Not running because of [message] (a busy port, invalid settings...). */
        data class Failed(val message: String) : Status
    }

    private val _status = MutableStateFlow<Status>(Status.Stopped)
    val status: StateFlow<Status> = _status.asStateFlow()

    /** Counters of the running proxy, null when it is not running. */
    @Volatile var stats: Stats? = null
        internal set

    internal fun set(status: Status) {
        _status.value = status
    }
}
