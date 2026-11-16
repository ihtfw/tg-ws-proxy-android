package org.flowseal.tgwsproxy.ui

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import org.flowseal.tgwsproxy.R
import org.flowseal.tgwsproxy.proxy.Stats
import org.flowseal.tgwsproxy.proxy.humanBytes
import org.flowseal.tgwsproxy.service.LogBuffer
import org.flowseal.tgwsproxy.service.ProxyConfig
import org.flowseal.tgwsproxy.service.ProxyService
import org.flowseal.tgwsproxy.service.ProxyState
import org.flowseal.tgwsproxy.service.SettingsDraft

@Composable
fun MainScreen(config: ProxyConfig, onOpenSettings: () -> Unit) {
    val context = LocalContext.current
    val status by ProxyState.status.collectAsState()

    // What the saved settings give while the proxy is not running (no network lookups here).
    val saved = remember(status) { runCatching { config.toProxySettings() }.getOrNull() }
    val savedListen = saved?.let { "${it.host}:${it.port}" } ?: "${config.host}:${config.port}"
    val running = status as? ProxyState.Status.Running
    val localLink = running?.localLink ?: saved?.let {
        it.proxyLink(if (it.host == SettingsDraft.ALL_INTERFACES) SettingsDraft.DEFAULT_HOST else it.host)
    }

    Scaffold(
        topBar = {
            AppTopBar(
                title = stringResource(R.string.app_name),
                actions = {
                    IconButton(onClick = onOpenSettings) {
                        Icon(Icons.Default.Settings, stringResource(R.string.settings_title))
                    }
                },
            )
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            StatusCard(status, savedListen)
            ControlButtons(status, context)
            if (localLink != null) LinkCard(context, localLink, running?.lanLink)
            if (running != null) StatsCard()
            RecentLogCard()
        }
    }
}

@Composable
private fun StatusCard(status: ProxyState.Status, savedListen: String) {
    val dark = LocalIsDarkTheme.current
    val (dot, background, title) = when (status) {
        is ProxyState.Status.Running ->
            Triple(StatusColors.running, StatusColors.runningBackground(dark), stringResource(R.string.status_running))
        is ProxyState.Status.Starting ->
            Triple(StatusColors.stopped, StatusColors.stoppedBackground(dark), stringResource(R.string.status_starting))
        is ProxyState.Status.Failed ->
            Triple(StatusColors.failed, StatusColors.failedBackground(dark), stringResource(R.string.status_failed))
        is ProxyState.Status.Stopped ->
            Triple(StatusColors.stopped, StatusColors.stoppedBackground(dark), stringResource(R.string.status_stopped))
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = background),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(12.dp)
                        .background(dot, RoundedCornerShape(6.dp))
                )
                Spacer(Modifier.width(8.dp))
                Text(title, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface)
            }
            Spacer(Modifier.height(8.dp))
            val listen = (status as? ProxyState.Status.Running)?.listen ?: savedListen
            Text(
                buildAnnotatedString {
                    append(stringResource(R.string.status_mtproto))
                    append("  ")
                    withStyle(SpanStyle(fontFamily = FontFamily.Monospace)) { append(listen) }
                },
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            if (status is ProxyState.Status.Failed) {
                Spacer(Modifier.height(8.dp))
                Text(
                    status.message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
        }
    }
}

@Composable
private fun ControlButtons(status: ProxyState.Status, context: Context) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        when (status) {
            is ProxyState.Status.Stopped, is ProxyState.Status.Failed -> Button(
                onClick = { ProxyService.start(context) },
                modifier = Modifier.weight(1f),
            ) {
                Icon(Icons.Default.PlayArrow, null, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(4.dp))
                Text(stringResource(R.string.action_start))
            }
            else -> {
                Button(
                    onClick = { ProxyService.stop(context) },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = StatusColors.failed),
                ) {
                    Icon(Icons.Default.Stop, null, modifier = Modifier.size(20.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(stringResource(R.string.action_stop))
                }
                OutlinedButton(
                    onClick = { ProxyService.restart(context) },
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(Icons.Default.Refresh, null, modifier = Modifier.size(20.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(stringResource(R.string.action_restart))
                }
            }
        }
    }
}

@Composable
private fun LinkCard(context: Context, localLink: String, lanLink: String?) {
    SectionCard(title = stringResource(R.string.link_title)) {
        LinkText(localLink)
        Button(onClick = { openInTelegram(context, localLink) }, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.AutoMirrored.Filled.OpenInNew, null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(stringResource(R.string.action_open_telegram))
        }
        OutlinedButton(onClick = { copyLink(context, localLink) }, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Default.ContentCopy, null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(stringResource(R.string.action_copy_link))
        }
        Text(
            stringResource(R.string.link_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (lanLink != null) {
            HorizontalDivider()
            Text(stringResource(R.string.link_lan_title), style = MaterialTheme.typography.bodyMedium)
            LinkText(lanLink)
            OutlinedButton(onClick = { copyLink(context, lanLink) }, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.ContentCopy, null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp))
                Text(stringResource(R.string.action_copy_link))
            }
        }
    }
}

@Composable
private fun LinkText(link: String) {
    SelectionContainer {
        Text(
            link,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

private fun copyLink(context: Context, link: String) {
    copyToClipboard(context, "tg://proxy", link, context.getString(R.string.toast_link_copied))
}

private fun openInTelegram(context: Context, link: String) {
    try {
        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(link)))
    } catch (_: ActivityNotFoundException) {
        copyToClipboard(context, "tg://proxy", link, toast = null)
        Toast.makeText(context, R.string.toast_open_telegram_failed, Toast.LENGTH_LONG).show()
    }
}

@Composable
private fun StatsCard() {
    var tick by remember { mutableIntStateOf(0) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(1000)
            tick++
        }
    }
    // Re-read on every tick: the counters are atomics the proxy threads update.
    val stats: Stats = remember(tick) { ProxyState.stats } ?: return

    SectionCard(title = stringResource(R.string.stats_title)) {
        StatRow(
            stringResource(R.string.stats_connections),
            stringResource(R.string.stats_connections_value, stats.connectionsActive.get(), stats.connectionsTotal.get()),
        )
        StatRow(stringResource(R.string.stats_websocket), stats.connectionsWs.get().toString())
        StatRow(stringResource(R.string.stats_cfproxy), stats.connectionsCfproxy.get().toString())
        StatRow(stringResource(R.string.stats_h2), stats.connectionsH2.get().toString())
        StatRow(stringResource(R.string.stats_tcp_fallback), stats.connectionsTcpFallback.get().toString())
        StatRow(
            stringResource(R.string.stats_traffic),
            stringResource(R.string.stats_traffic_value, humanBytes(stats.bytesUp.get()), humanBytes(stats.bytesDown.get())),
        )
        val poolTotal = stats.poolHits.get() + stats.poolMisses.get()
        StatRow(
            stringResource(R.string.stats_pool),
            if (poolTotal > 0) stringResource(R.string.stats_pool_value, stats.poolHits.get(), poolTotal)
            else stringResource(R.string.stats_none),
        )
        StatRow(
            stringResource(R.string.stats_errors),
            stringResource(R.string.stats_errors_value, stats.wsErrors.get(), stats.connectionsBad.get()),
        )
    }
}

@Composable
private fun StatRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.width(12.dp))
        Text(value, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun RecentLogCard() {
    val version by LogBuffer.version.collectAsState()
    val lines = remember(version) { LogBuffer.snapshot().takeLast(RECENT_LOG_LINES) }
    if (lines.isEmpty()) return
    SectionCard(title = stringResource(R.string.recent_log_title)) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(8.dp))
                .padding(8.dp)
        ) {
            for (line in lines) {
                Text(
                    line,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    lineHeight = 14.sp,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
        }
    }
}

private const val RECENT_LOG_LINES = 20
