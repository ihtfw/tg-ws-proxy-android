package org.flowseal.tgwsproxy.ui

import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import org.flowseal.tgwsproxy.R
import org.flowseal.tgwsproxy.proxy.ProxyLog
import org.flowseal.tgwsproxy.service.ConfigError
import org.flowseal.tgwsproxy.service.ConfigField
import org.flowseal.tgwsproxy.service.ProxyConfig
import org.flowseal.tgwsproxy.service.ProxyService
import org.flowseal.tgwsproxy.service.ProxyState
import org.flowseal.tgwsproxy.service.SettingsDraft
import org.flowseal.tgwsproxy.service.message

/**
 * All options, grouped like upstream's settings form. Proxy options are edited as a draft and
 * applied with Save (restarting a running proxy); app options apply at once.
 */
@Composable
fun SettingsScreen(
    config: ProxyConfig,
    themeMode: String,
    onThemeModeChange: (String) -> Unit,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    val status by ProxyState.status.collectAsState()
    val stored = remember { config.draft() }
    var draft by rememberSaveable { mutableStateOf(stored) }
    var askDiscard by rememberSaveable { mutableStateOf(false) }
    val errors = remember(draft) { draft.errors().associateBy { it.field } }
    val changed = draft != stored
    val active = status !is ProxyState.Status.Stopped

    val back = { if (changed) askDiscard = true else onClose() }
    BackHandler(onBack = back)

    val save = {
        config.save(draft)
        if (active) {
            ProxyService.restart(context)
            Toast.makeText(context, R.string.toast_saved_restarting, Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(context, R.string.toast_saved, Toast.LENGTH_SHORT).show()
        }
        onClose()
    }

    Scaffold(
        topBar = { AppTopBar(title = stringResource(R.string.settings_title), onBack = back) },
        bottomBar = {
            Surface(tonalElevation = 3.dp, shadowElevation = 3.dp) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .navigationBarsPadding()
                        .imePadding()
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                ) {
                    if (errors.isNotEmpty()) {
                        Text(
                            stringResource(R.string.validation_fix_fields),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.padding(bottom = 4.dp),
                        )
                    }
                    Button(
                        onClick = save,
                        enabled = changed && errors.isEmpty(),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(stringResource(if (active) R.string.action_save_restart else R.string.action_save))
                    }
                }
            }
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
            ConnectionSection(draft, errors) { draft = it }
            DcSection(draft, errors) { draft = it }
            CloudflareSection(draft, errors) { draft = it }
            AdvancedSection(draft, errors) { draft = it }
            AppSection(config, themeMode, onThemeModeChange)
            val version = remember { appVersion(context) }
            if (version.isNotEmpty()) {
                Text(
                    stringResource(R.string.version, version),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.fillMaxWidth(),
                    textAlign = TextAlign.Center,
                )
            }
        }
    }

    if (askDiscard) {
        AlertDialog(
            onDismissRequest = { askDiscard = false },
            title = { Text(stringResource(R.string.dialog_discard_title)) },
            text = { Text(stringResource(R.string.dialog_discard_body)) },
            confirmButton = {
                TextButton(onClick = {
                    askDiscard = false
                    onClose()
                }) { Text(stringResource(R.string.action_discard)) }
            },
            dismissButton = {
                TextButton(onClick = { askDiscard = false }) { Text(stringResource(R.string.action_cancel)) }
            },
        )
    }
}

@Composable
private fun ConnectionSection(draft: SettingsDraft, errors: Map<ConfigField, ConfigError>, onChange: (SettingsDraft) -> Unit) {
    SectionCard(title = stringResource(R.string.section_mtproto)) {
        SettingsTextField(
            value = draft.port,
            onValueChange = { onChange(draft.copy(port = it.filter(Char::isDigit))) },
            label = stringResource(R.string.label_port),
            hint = stringResource(R.string.tip_port),
            error = errors[ConfigField.PORT],
            keyboardType = KeyboardType.Number,
        )
        SettingsTextField(
            value = draft.secret,
            onValueChange = { onChange(draft.copy(secret = it.trim())) },
            label = stringResource(R.string.label_secret),
            hint = stringResource(R.string.tip_secret),
            error = errors[ConfigField.SECRET],
            monospace = true,
        )
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            TextButton(onClick = { onChange(draft.copy(secret = SettingsDraft.newSecret())) }) {
                Text(stringResource(R.string.action_regenerate_secret))
            }
        }
    }
}

@Composable
private fun DcSection(draft: SettingsDraft, errors: Map<ConfigField, ConfigError>, onChange: (SettingsDraft) -> Unit) {
    SectionCard(title = stringResource(R.string.section_dc)) {
        SettingsTextField(
            value = draft.dcIps,
            onValueChange = { onChange(draft.copy(dcIps = it)) },
            label = stringResource(R.string.label_dc_hint),
            hint = stringResource(R.string.tip_dc),
            error = errors[ConfigField.DC_IPS],
            monospace = true,
            singleLine = false,
        )
    }
}

@Composable
private fun CloudflareSection(draft: SettingsDraft, errors: Map<ConfigField, ConfigError>, onChange: (SettingsDraft) -> Unit) {
    SectionCard(title = stringResource(R.string.section_cloudflare)) {
        SwitchRow(
            title = stringResource(R.string.label_cf_enable),
            subtitle = stringResource(R.string.tip_cfproxy),
            checked = draft.cfproxy,
            onCheckedChange = { onChange(draft.copy(cfproxy = it)) },
        )
        SwitchRow(
            title = stringResource(R.string.label_cf_custom_domain),
            subtitle = stringResource(R.string.tip_cfproxy_user_domain_cb),
            checked = draft.cfUserDomainEnabled,
            enabled = draft.cfproxy,
            onCheckedChange = { onChange(draft.copy(cfUserDomainEnabled = it)) },
        )
        if (draft.cfproxy && draft.cfUserDomainEnabled) {
            SettingsTextField(
                value = draft.cfUserDomains,
                onValueChange = { onChange(draft.copy(cfUserDomains = it)) },
                label = stringResource(R.string.label_cf_domains),
                hint = stringResource(R.string.tip_cfproxy_domain),
                error = errors[ConfigField.CF_USER_DOMAINS],
                keyboardType = KeyboardType.Uri,
                singleLine = false,
            )
        }
        SwitchRow(
            title = stringResource(R.string.label_h2_enable),
            subtitle = stringResource(R.string.tip_h2),
            checked = draft.h2Media && draft.h2Available,
            enabled = draft.h2Available,
            onCheckedChange = { onChange(draft.copy(h2Media = it)) },
        )
        HorizontalDivider()
        SwitchRow(
            title = stringResource(R.string.label_cfworker_enable),
            subtitle = stringResource(R.string.tip_cfworker_enable),
            checked = draft.cfWorkerEnabled,
            onCheckedChange = { onChange(draft.copy(cfWorkerEnabled = it)) },
        )
        if (draft.cfWorkerEnabled) {
            SettingsTextField(
                value = draft.cfWorkerDomains,
                onValueChange = { onChange(draft.copy(cfWorkerDomains = it)) },
                label = stringResource(R.string.label_cfworker_domains),
                hint = stringResource(R.string.tip_cfworker_domain),
                error = errors[ConfigField.CF_WORKER_DOMAINS],
                keyboardType = KeyboardType.Uri,
                singleLine = false,
            )
        }
        HorizontalDivider()
        SwitchRow(
            title = stringResource(R.string.label_no_secure),
            subtitle = stringResource(R.string.tip_no_secure),
            checked = draft.noSecure,
            onCheckedChange = { onChange(draft.copy(noSecure = it)) },
        )
    }
}

@Composable
private fun AdvancedSection(draft: SettingsDraft, errors: Map<ConfigField, ConfigError>, onChange: (SettingsDraft) -> Unit) {
    SectionCard(title = stringResource(R.string.section_advanced)) {
        SwitchRow(
            title = stringResource(R.string.label_listen_all),
            subtitle = stringResource(R.string.tip_listen_all),
            checked = draft.listenAll,
            onCheckedChange = { onChange(draft.withListenAll(it)) },
        )
        SettingsTextField(
            value = draft.fakeTlsDomain,
            onValueChange = { onChange(draft.copy(fakeTlsDomain = it.trim())) },
            label = stringResource(R.string.label_fake_tls),
            hint = stringResource(R.string.tip_fake_tls),
            error = errors[ConfigField.FAKE_TLS_DOMAIN],
            keyboardType = KeyboardType.Uri,
        )
        SwitchRow(
            title = stringResource(R.string.label_force_test_dc),
            subtitle = stringResource(R.string.tip_force_test_dc),
            checked = draft.forceTestDc,
            onCheckedChange = { onChange(draft.copy(forceTestDc = it)) },
        )
        SettingsTextField(
            value = draft.poolSize,
            onValueChange = { onChange(draft.copy(poolSize = it.filter(Char::isDigit))) },
            label = stringResource(R.string.label_pool_size),
            hint = stringResource(R.string.tip_pool),
            error = errors[ConfigField.POOL_SIZE],
            keyboardType = KeyboardType.Number,
        )
        SettingsTextField(
            value = draft.bufKb,
            onValueChange = { onChange(draft.copy(bufKb = it.filter(Char::isDigit))) },
            label = stringResource(R.string.label_buf_kb),
            hint = stringResource(R.string.tip_buf_kb),
            error = errors[ConfigField.BUFFER],
            keyboardType = KeyboardType.Number,
        )
    }
}

@Composable
private fun AppSection(config: ProxyConfig, themeMode: String, onThemeModeChange: (String) -> Unit) {
    var autostart by remember { mutableStateOf(config.autostart) }
    var verbose by remember { mutableStateOf(config.verbose) }
    SectionCard(title = stringResource(R.string.section_app)) {
        Text(stringResource(R.string.settings_theme), style = MaterialTheme.typography.bodyLarge)
        val themes = listOf(
            "system" to stringResource(R.string.appearance_auto),
            "light" to stringResource(R.string.appearance_light),
            "dark" to stringResource(R.string.appearance_dark),
        )
        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            themes.forEachIndexed { index, (value, label) ->
                SegmentedButton(
                    selected = themeMode == value,
                    onClick = { onThemeModeChange(value) },
                    shape = SegmentedButtonDefaults.itemShape(index, themes.size),
                ) { Text(label) }
            }
        }
        SwitchRow(
            title = stringResource(R.string.label_autostart),
            subtitle = stringResource(R.string.tip_autostart),
            checked = autostart,
            onCheckedChange = {
                autostart = it
                config.autostart = it
            },
        )
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
    }
}

@Composable
fun SettingsTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    hint: String?,
    error: ConfigError?,
    modifier: Modifier = Modifier,
    keyboardType: KeyboardType = KeyboardType.Text,
    monospace: Boolean = false,
    singleLine: Boolean = true,
    enabled: Boolean = true,
) {
    val context = LocalContext.current
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        isError = error != null,
        supportingText = {
            val text = error?.message(context) ?: hint
            if (text != null) Text(text)
        },
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType, autoCorrectEnabled = false),
        textStyle = if (monospace) MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace)
        else MaterialTheme.typography.bodyLarge,
        singleLine = singleLine,
        minLines = if (singleLine) 1 else 2,
        maxLines = if (singleLine) 1 else 6,
        enabled = enabled,
        modifier = modifier.fillMaxWidth(),
    )
}
