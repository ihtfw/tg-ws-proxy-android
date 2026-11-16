package org.flowseal.tgwsproxy.ui

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.flowseal.tgwsproxy.R
import org.flowseal.tgwsproxy.proxy.ProxyLog
import org.flowseal.tgwsproxy.proxy.UpdateCheck
import org.flowseal.tgwsproxy.service.ProxyConfig
import kotlin.concurrent.thread

/** The update check's state for this process: the on-start check and the manual one share it. */
object Updates {
    private val _status = MutableStateFlow(UpdateCheck.Status())
    val status: StateFlow<UpdateCheck.Status> = _status.asStateFlow()

    private val _checking = MutableStateFlow(false)
    val checking: StateFlow<Boolean> = _checking.asStateFlow()

    /** Set when the on-start check finds a newer release; cleared when the user answers. */
    private val _offer = MutableStateFlow(false)
    val offer: StateFlow<Boolean> = _offer.asStateFlow()

    @Volatile private var startChecked = false

    /** The check on app start, once per process, when the user has it on. */
    fun checkOnStart(context: Context) {
        if (startChecked || !ProxyConfig(context).checkUpdates) return
        startChecked = true
        check(context, offerIfNewer = true)
    }

    fun check(context: Context, offerIfNewer: Boolean = false) {
        if (_checking.value) return
        _checking.value = true
        val app = context.applicationContext
        val version = appVersion(app)
        val skipped = ProxyConfig(app).skippedUpdate
        thread(name = "update-check", isDaemon = true) {
            try {
                val st = UpdateCheck.check(version)
                if (st.error != null) {
                    ProxyLog.w("Update check failed: ${st.error}")
                } else {
                    ProxyLog.i("Update check: latest release ${st.latest}, installed $version")
                }
                _status.value = st
                if (offerIfNewer && st.hasUpdate && st.latest != skipped) _offer.value = true
            } finally {
                // An Error must not leave the button disabled until the next start.
                _checking.value = false
            }
        }
    }

    /** Keeps this release out of the start-up offer; the next one is offered again. */
    fun skipVersion(context: Context) {
        _status.value.latest?.let { ProxyConfig(context.applicationContext).skippedUpdate = it }
        _offer.value = false
    }

    fun dismissOffer() {
        _offer.value = false
    }
}

fun openUrl(context: Context, url: String) {
    try {
        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
    } catch (_: ActivityNotFoundException) {
        Toast.makeText(context, R.string.toast_no_browser, Toast.LENGTH_SHORT).show()
    }
}

/** Upstream's "New version available ... Open the release page?" after the on-start check. */
@Composable
fun UpdateOfferDialog() {
    val context = LocalContext.current
    val offer by Updates.offer.collectAsState()
    val st by Updates.status.collectAsState()
    if (!offer) return
    AlertDialog(
        onDismissRequest = { Updates.dismissOffer() },
        title = { Text(stringResource(R.string.update_title)) },
        text = { Text(stringResource(R.string.update_ask_open, st.latest.orEmpty())) },
        confirmButton = {
            TextButton(onClick = {
                Updates.dismissOffer()
                openUrl(context, st.htmlUrl)
            }) { Text(stringResource(R.string.action_open_release)) }
        },
        dismissButton = {
            Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                TextButton(onClick = { Updates.skipVersion(context) }) {
                    Text(stringResource(R.string.action_skip_version))
                }
                TextButton(onClick = { Updates.dismissOffer() }) { Text(stringResource(R.string.action_close)) }
            }
        },
    )
}

/** Settings group like upstream's "Updates" section. */
@Composable
fun UpdatesSection(config: ProxyConfig) {
    val context = LocalContext.current
    var checkOnStart by remember { mutableStateOf(config.checkUpdates) }
    val st by Updates.status.collectAsState()
    val checking by Updates.checking.collectAsState()
    val version = remember { appVersion(context) }

    SectionCard(title = stringResource(R.string.section_updates)) {
        SwitchRow(
            title = stringResource(R.string.label_check_updates),
            subtitle = stringResource(R.string.tip_check_updates),
            checked = checkOnStart,
            onCheckedChange = {
                checkOnStart = it
                config.checkUpdates = it
            },
        )
        val text = when {
            checking -> stringResource(R.string.updates_status_checking)
            st.error != null -> stringResource(R.string.updates_status_error)
            !st.checked -> stringResource(R.string.updates_status_pending)
            st.hasUpdate -> stringResource(R.string.updates_status_available, st.latest.orEmpty(), version)
            st.aheadOfRelease -> stringResource(R.string.updates_status_ahead, version, st.latest.orEmpty())
            else -> stringResource(R.string.updates_status_latest)
        }
        Text(
            text,
            style = MaterialTheme.typography.bodyMedium,
            color = if (st.hasUpdate && !checking) MaterialTheme.colorScheme.primary
            else MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedButton(
            onClick = { Updates.check(context) },
            enabled = !checking,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.action_check_updates)) }
        OutlinedButton(
            onClick = { openUrl(context, st.htmlUrl) },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.action_open_release)) }
    }
}
