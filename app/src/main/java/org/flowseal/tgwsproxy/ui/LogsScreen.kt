package org.flowseal.tgwsproxy.ui

import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.flowseal.tgwsproxy.R
import org.flowseal.tgwsproxy.proxy.ProxyLog
import org.flowseal.tgwsproxy.service.LogBuffer
import org.flowseal.tgwsproxy.service.ProxyConfig

/** The recent log lines with the verbose switch, Share (censored) and Clear. */
@Composable
fun LogsScreen(config: ProxyConfig, onClose: () -> Unit) {
    val context = LocalContext.current
    val version by LogBuffer.version.collectAsState()
    val lines = remember(version) { LogBuffer.snapshot() }
    var verbose by remember { mutableStateOf(config.verbose) }
    val listState = rememberLazyListState()

    // Follow new lines while the list is scrolled to the end.
    LaunchedEffect(lines.size) {
        val last = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: -1
        if (lines.isNotEmpty() && (last < 0 || last >= lines.size - 3)) listState.scrollToItem(lines.size - 1)
    }

    Scaffold(
        topBar = {
            AppTopBar(
                title = stringResource(R.string.logs_title),
                onBack = onClose,
                actions = {
                    IconButton(onClick = { shareLog(context, lines) }, enabled = lines.isNotEmpty()) {
                        Icon(Icons.Default.Share, stringResource(R.string.action_share))
                    }
                    IconButton(onClick = { LogBuffer.clear() }, enabled = lines.isNotEmpty()) {
                        Icon(Icons.Default.DeleteSweep, stringResource(R.string.action_clear))
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
                .padding(16.dp),
        ) {
            SectionCard(title = null) {
                SwitchRow(
                    title = stringResource(R.string.label_verbose),
                    subtitle = stringResource(R.string.tip_verbose),
                    checked = verbose,
                    onCheckedChange = {
                        verbose = it
                        config.verbose = it
                        ProxyLog.verbose = it
                    },
                )
                Text(
                    stringResource(R.string.logs_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Box(
                modifier = Modifier
                    .padding(top = 12.dp)
                    .fillMaxWidth()
                    .weight(1f)
                    .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(8.dp)),
            ) {
                if (lines.isEmpty()) {
                    Text(
                        stringResource(R.string.logs_empty),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.align(Alignment.Center),
                    )
                } else {
                    LazyColumn(state = listState, modifier = Modifier.fillMaxSize().padding(8.dp)) {
                        itemsIndexed(lines) { _, line ->
                            Text(
                                line,
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                lineHeight = 14.sp,
                                color = logColor(line),
                                modifier = Modifier.padding(vertical = 1.dp),
                            )
                        }
                    }
                }
            }
        }
    }
}

/** Lines are "HH:mm:ss.SSS L message"; warnings and errors stand out. */
@Composable
private fun logColor(line: String) = when (line.getOrNull(13)) {
    'E' -> MaterialTheme.colorScheme.error
    'W' -> StatusColors.stopped
    'D' -> MaterialTheme.colorScheme.onSurfaceVariant
    else -> MaterialTheme.colorScheme.onSurface
}

/** Binder transactions are limited to about 1 MB; a verbose log of 2000 lines can get close. */
private const val MAX_SHARE_CHARS = 200_000

private fun shareLog(context: Context, lines: List<String>) {
    val header = "TG WS Proxy ${appVersion(context)}, Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"
    var text = (listOf(header, "") + lines).joinToString("\n")
    if (text.length > MAX_SHARE_CHARS) {
        text = context.getString(R.string.logs_share_truncated) + "\n" + text.takeLast(MAX_SHARE_CHARS)
    }
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_SUBJECT, context.getString(R.string.logs_share_subject))
        putExtra(Intent.EXTRA_TEXT, ProxyLog.censor(text))
    }
    context.startActivity(Intent.createChooser(send, context.getString(R.string.logs_share_chooser)))
}
