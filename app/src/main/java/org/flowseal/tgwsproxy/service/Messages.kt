package org.flowseal.tgwsproxy.service

import android.content.Context
import org.flowseal.tgwsproxy.R

/** The user-facing text for a settings problem. */
fun ConfigError.message(context: Context): String = when (kind) {
    ConfigError.Kind.BAD_HOST -> context.getString(R.string.validation_bad_host)
    ConfigError.Kind.BAD_PORT -> context.getString(R.string.validation_bad_port)
    ConfigError.Kind.SECRET_LENGTH -> context.getString(R.string.validation_bad_secret_len)
    ConfigError.Kind.SECRET_HEX -> context.getString(R.string.validation_bad_secret_hex)
    ConfigError.Kind.DC_FORMAT -> context.getString(R.string.validation_dc_format, entry)
    ConfigError.Kind.DC_INVALID -> context.getString(R.string.validation_dc_invalid, entry)
    ConfigError.Kind.BAD_POOL_SIZE ->
        context.getString(R.string.validation_bad_pool, 0, SettingsDraft.MAX_POOL_SIZE)
    ConfigError.Kind.BAD_BUFFER ->
        context.getString(R.string.validation_bad_buffer, SettingsDraft.MIN_BUF_KB, SettingsDraft.MAX_BUF_KB)
}

/** The user-facing text for a failure to open the listening socket. */
fun listenErrorMessage(context: Context, e: Throwable, port: Int): String = when (diagnoseListenError(e)) {
    ListenProblem.PORT_BUSY -> context.getString(R.string.diagnostics_port_busy, port)
    ListenProblem.PERMISSION -> context.getString(R.string.diagnostics_permission)
    ListenProblem.BAD_ADDRESS -> context.getString(R.string.diagnostics_bad_address)
    ListenProblem.OTHER -> context.getString(R.string.diagnostics_other, e.message ?: e.javaClass.simpleName)
}
