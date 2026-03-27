package org.flowseal.tgwsproxy.ui

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import org.flowseal.tgwsproxy.proxy.Stats
import org.flowseal.tgwsproxy.service.ProxyConfig
import org.flowseal.tgwsproxy.service.ProxyService

class MainActivity : ComponentActivity() {

    private var proxyService: ProxyService? = null
    private var bound = mutableStateOf(false)

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            proxyService = (binder as ProxyService.LocalBinder).getService()
            bound.value = true
        }
        override fun onServiceDisconnected(name: ComponentName?) {
            proxyService = null
            bound.value = false
        }
    }

    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* Notification permission result — proceed regardless */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Request notification permission on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        setContent {
            val config = remember { ProxyConfig(this) }
            var themeMode by remember { mutableStateOf(config.themeMode) }

            TgWsProxyTheme(themeMode = themeMode) {
                MainScreen(
                    context = this,
                    bound = bound,
                    getService = { proxyService },
                    onStart = { startProxyService() },
                    onStop = { stopProxyService() },
                    onRestart = { restartProxyService() },
                    config = config,
                    themeMode = themeMode,
                    onThemeModeChanged = { newMode ->
                        config.themeMode = newMode
                        themeMode = newMode
                    }
                )
            }
        }
    }

    override fun onStart() {
        super.onStart()
        Intent(this, ProxyService::class.java).also { intent ->
            bindService(intent, connection, Context.BIND_AUTO_CREATE)
        }
    }

    override fun onStop() {
        super.onStop()
        if (bound.value) {
            unbindService(connection)
            bound.value = false
        }
    }

    private fun startProxyService() {
        val intent = Intent(this, ProxyService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        // Bind to get reference
        bindService(intent, connection, Context.BIND_AUTO_CREATE)
    }

    private fun stopProxyService() {
        val intent = Intent(this, ProxyService::class.java).apply {
            action = ProxyService.ACTION_STOP
        }
        startService(intent)
    }

    private fun restartProxyService() {
        proxyService?.restartProxy()
    }
}

// --- Theme ---

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF3390EC),
    onPrimary = Color.White,
    surface = Color.White,
    onSurface = Color.Black,
    surfaceVariant = Color(0xFFF0F2F5),
    onSurfaceVariant = Color(0xFF707579),
    outline = Color(0xFFDADCE0),
)

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF5EA8F0),
    onPrimary = Color.White,
    surface = Color(0xFF1E1E1E),
    onSurface = Color(0xFFE0E0E0),
    surfaceVariant = Color(0xFF2C2C2C),
    onSurfaceVariant = Color(0xFFA0A4A8),
    outline = Color(0xFF444444),
)

val LocalIsDarkTheme = staticCompositionLocalOf { false }

@Composable
fun TgWsProxyTheme(themeMode: String = "system", content: @Composable () -> Unit) {
    val isDark = when (themeMode) {
        "dark" -> true
        "light" -> false
        else -> isSystemInDarkTheme()
    }
    val colorScheme = if (isDark) DarkColorScheme else LightColorScheme
    CompositionLocalProvider(LocalIsDarkTheme provides isDark) {
        MaterialTheme(colorScheme = colorScheme, content = content)
    }
}

// --- Main Screen ---

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    context: Context,
    bound: MutableState<Boolean>,
    getService: () -> ProxyService?,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onRestart: () -> Unit,
    config: ProxyConfig,
    themeMode: String,
    onThemeModeChanged: (String) -> Unit
) {
    var showSettings by remember { mutableStateOf(false) }

    // Auto-refresh stats
    var statsText by remember { mutableStateOf("Not running") }
    var isRunning by remember { mutableStateOf(false) }
    var logs by remember { mutableStateOf(listOf<String>()) }

    LaunchedEffect(bound.value) {
        while (true) {
            val service = getService()
            isRunning = service?.isProxyRunning == true
            if (isRunning) {
                val s = service?.stats
                if (s != null) {
                    statsText = s.summary()
                }
                logs = service?.getRecentLogs() ?: emptyList()
            } else {
                statsText = "Not running"
            }
            delay(1000)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("TG WS Proxy") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    titleContentColor = MaterialTheme.colorScheme.onPrimary,
                    actionIconContentColor = MaterialTheme.colorScheme.onPrimary
                ),
                actions = {
                    IconButton(onClick = { showSettings = !showSettings }) {
                        Icon(Icons.Default.Settings, "Settings")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Status card
            StatusCard(isRunning, statsText, config)

            // Control buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                if (!isRunning) {
                    Button(
                        onClick = onStart,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary)
                    ) {
                        Icon(Icons.Default.PlayArrow, null, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Start")
                    }
                } else {
                    Button(
                        onClick = onStop,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE53935))
                    ) {
                        Icon(Icons.Default.Stop, null, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Stop")
                    }
                    OutlinedButton(
                        onClick = onRestart,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Restart")
                    }
                }
            }

            // Copy proxy URL button
            val clipboardManager = LocalClipboardManager.current
            OutlinedButton(
                onClick = {
                    val url = "socks5://${config.host}:${config.port}"
                    clipboardManager.setText(AnnotatedString(url))
                    Toast.makeText(context, "Copied: $url", Toast.LENGTH_SHORT).show()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.ContentCopy, null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp))
                Text("Copy Proxy Address")
            }

            // Open in Telegram
            OutlinedButton(
                onClick = {
                    try {
                        val uri = android.net.Uri.parse("tg://socks?server=${config.host}&port=${config.port}")
                        val intent = Intent(Intent.ACTION_VIEW, uri)
                        context.startActivity(intent)
                    } catch (e: Exception) {
                        Toast.makeText(context, "Telegram not installed", Toast.LENGTH_SHORT).show()
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Open in Telegram")
            }

            // Settings panel
            if (showSettings) {
                SettingsPanel(config, onRestart, themeMode, onThemeModeChanged)
            }

            // Logs
            if (logs.isNotEmpty()) {
                Text(
                    "Logs",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 8.dp)
                )
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                ) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        for (line in logs.takeLast(50)) {
                            Text(
                                line,
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                lineHeight = 14.sp,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun StatusCard(isRunning: Boolean, statsText: String, config: ProxyConfig) {
    val isDark = LocalIsDarkTheme.current

    val runningBg = if (isDark) Color(0xFF1B3A1B) else Color(0xFFE8F5E9)
    val stoppedBg = if (isDark) Color(0xFF3A2E1B) else Color(0xFFFFF3E0)

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isRunning) runningBg else stoppedBg
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(12.dp)
                        .background(
                            if (isRunning) Color(0xFF4CAF50) else Color(0xFFFF9800),
                            RoundedCornerShape(6.dp)
                        )
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    if (isRunning) "Running" else "Stopped",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
            if (isRunning) {
                Spacer(Modifier.height(8.dp))
                Text(
                    "${config.host}:${config.port}",
                    style = MaterialTheme.typography.bodyLarge,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    statsText,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
fun SettingsPanel(
    config: ProxyConfig,
    onRestart: () -> Unit,
    themeMode: String,
    onThemeModeChanged: (String) -> Unit
) {
    var port by remember { mutableStateOf(config.port.toString()) }
    var dcIps by remember { mutableStateOf(config.dcIps.joinToString("\n")) }
    var poolSize by remember { mutableStateOf(config.poolSize.toString()) }
    var bufKb by remember { mutableStateOf(config.bufKb.toString()) }
    var autostart by remember { mutableStateOf(config.autostart) }

    val themeOptions = listOf("system" to "System", "light" to "Light", "dark" to "Dark")

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("Settings", style = MaterialTheme.typography.titleMedium)

            // Theme selector
            Text("Theme", style = MaterialTheme.typography.bodyMedium)
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                themeOptions.forEachIndexed { index, (value, label) ->
                    SegmentedButton(
                        selected = themeMode == value,
                        onClick = { onThemeModeChanged(value) },
                        shape = SegmentedButtonDefaults.itemShape(index, themeOptions.size)
                    ) {
                        Text(label)
                    }
                }
            }

            OutlinedTextField(
                value = port,
                onValueChange = { port = it },
                label = { Text("SOCKS5 Port") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )

            OutlinedTextField(
                value = dcIps,
                onValueChange = { dcIps = it },
                label = { Text("DC IPs (DC:IP per line)") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 2,
                maxLines = 5,
                supportingText = { Text("e.g. 2:149.154.167.220") }
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = poolSize,
                    onValueChange = { poolSize = it },
                    label = { Text("Pool Size") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
                OutlinedTextField(
                    value = bufKb,
                    onValueChange = { bufKb = it },
                    label = { Text("Buffer KB") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("Start on boot")
                Switch(
                    checked = autostart,
                    onCheckedChange = { autostart = it }
                )
            }

            Button(
                onClick = {
                    config.port = port.toIntOrNull() ?: 1080
                    config.dcIps = dcIps.lines().filter { it.isNotBlank() }
                    config.poolSize = poolSize.toIntOrNull() ?: 4
                    config.bufKb = bufKb.toIntOrNull() ?: 256
                    config.autostart = autostart
                    onRestart()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Save & Restart")
            }
        }
    }
}
