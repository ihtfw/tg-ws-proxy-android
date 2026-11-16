package org.flowseal.tgwsproxy.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.flowseal.tgwsproxy.R
import org.flowseal.tgwsproxy.proxy.CfProxyDomains
import org.flowseal.tgwsproxy.proxy.Connectivity
import org.flowseal.tgwsproxy.proxy.ProxyLog
import org.flowseal.tgwsproxy.service.ConfigException
import org.flowseal.tgwsproxy.service.ProxyConfig
import org.flowseal.tgwsproxy.service.message

/** Tests, from this device, every route the saved settings use (upstream ui/connectivity.py). */
@Composable
fun ConnectivityScreen(config: ProxyConfig, onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var running by remember { mutableStateOf(false) }
    var route by remember { mutableStateOf<Connectivity.Route?>(null) }
    var groups by remember { mutableStateOf<List<Connectivity.Group>?>(null) }
    var problem by remember { mutableStateOf<String?>(null) }

    val run: () -> Unit = run@{
        val settings = try {
            config.toProxySettings()
        } catch (e: ConfigException) {
            problem = context.getString(R.string.error_config, e.error.message(context))
            return@run
        }
        val plan = Connectivity.plan(settings, CfProxyDomains.current(settings))
        if (plan.isEmpty) {
            problem = context.getString(R.string.connectivity_nothing)
            groups = null
            return@run
        }
        problem = null
        running = true
        groups = null
        scope.launch {
            ProxyLog.i("Connectivity check started")
            val result = withContext(Dispatchers.IO) {
                Connectivity.check(plan, onRoute = { r -> scope.launch { route = r } })
            }
            for (g in result) {
                ProxyLog.i("Connectivity ${g.route}${if (g.route == Connectivity.Route.CF_PROXY_AUTO) "" else " ${g.name.orEmpty()}"}: ${g.okCount}/${g.results.size} OK")
            }
            groups = result
            running = false
            route = null
        }
    }

    Scaffold(
        topBar = { AppTopBar(title = stringResource(R.string.connectivity_title), onBack = onClose) },
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
            Text(
                stringResource(R.string.connectivity_intro),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(onClick = run, enabled = !running, modifier = Modifier.fillMaxWidth()) {
                if (running) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.connectivity_checking))
                } else {
                    Text(stringResource(R.string.action_run_check))
                }
            }
            if (running && route != null) {
                Text(
                    routeTitle(route!!, null),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            problem?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
            }
            groups?.forEach { GroupCard(it) }
        }
    }
}

@Composable
private fun routeTitle(route: Connectivity.Route, name: String?): String = when (route) {
    Connectivity.Route.DIRECT -> stringResource(R.string.connectivity_direct_title)
    Connectivity.Route.CF_PROXY ->
        if (name != null) stringResource(R.string.connectivity_cfproxy_domain_title, name)
        else stringResource(R.string.connectivity_cfproxy_title)
    Connectivity.Route.CF_PROXY_AUTO -> stringResource(R.string.connectivity_cfproxy_auto_title)
    Connectivity.Route.CF_WORKER ->
        if (name != null) stringResource(R.string.connectivity_cfworker_domain_title, name)
        else stringResource(R.string.connectivity_cfworker_title)
}

@Composable
private fun GroupCard(group: Connectivity.Group) {
    val auto = group.route == Connectivity.Route.CF_PROXY_AUTO
    SectionCard(title = routeTitle(group.route, if (auto) null else group.name)) {
        val total = group.results.size
        val (summary, color) = when {
            auto && group.okCount > 0 -> stringResource(
                R.string.connectivity_auto_ok, stringResource(R.string.connectivity_cfproxy_title), group.okCount, total,
            ) to StatusColors.running
            auto -> stringResource(R.string.connectivity_cf_auto_fail) to StatusColors.failed
            group.allOk -> stringResource(R.string.connectivity_all_ok, total) to StatusColors.running
            group.noneOk -> stringResource(R.string.connectivity_unavailable) to StatusColors.failed
            else -> stringResource(R.string.connectivity_partial, group.okCount, total) to StatusColors.stopped
        }
        Text(summary, style = MaterialTheme.typography.bodyLarge, color = color)
        for (r in group.results) {
            DcRow(r, censor = auto)
        }
    }
}

@Composable
private fun DcRow(result: Connectivity.DcResult, censor: Boolean) {
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
        Text(
            if (result.ok) "✓" else "✗",
            color = if (result.ok) StatusColors.running else StatusColors.failed,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.width(20.dp),
        )
        Column(modifier = Modifier.weight(1f)) {
            Text(
                "DC${result.dc}  ${result.target}",
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
            )
            if (!result.ok) {
                val text = outcomeText(result.outcome)
                Text(
                    if (censor) ProxyLog.censor(text) else text,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        if (result.ok) {
            Text(stringResource(R.string.connectivity_ok), color = StatusColors.running, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun outcomeText(outcome: Connectivity.Outcome): String = when (outcome) {
    Connectivity.Outcome.Ok -> stringResource(R.string.connectivity_ok)
    Connectivity.Outcome.Timeout -> stringResource(R.string.connectivity_timeout)
    Connectivity.Outcome.NoResponse -> stringResource(R.string.connectivity_no_response)
    Connectivity.Outcome.HostNotFound -> stringResource(R.string.connectivity_host_not_found)
    is Connectivity.Outcome.Http -> outcome.statusLine.ifBlank { "HTTP ${outcome.statusCode}" }
    is Connectivity.Outcome.Failed -> outcome.message
}
