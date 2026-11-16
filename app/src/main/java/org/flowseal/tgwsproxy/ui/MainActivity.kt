package org.flowseal.tgwsproxy.ui

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import org.flowseal.tgwsproxy.service.LogBuffer
import org.flowseal.tgwsproxy.service.ProxyConfig

class MainActivity : ComponentActivity() {

    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* The proxy works without it; only the notification stays hidden. */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        LogBuffer.install(applicationContext)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        val config = ProxyConfig(this)
        setContent {
            var themeMode by remember { mutableStateOf(config.themeMode) }
            val dark = isDarkTheme(themeMode)
            LaunchedEffect(dark) {
                // The top bar is blue in both themes, so the status bar icons stay light.
                enableEdgeToEdge(
                    statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
                    navigationBarStyle = if (dark) SystemBarStyle.dark(Color.TRANSPARENT)
                    else SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT),
                )
            }
            TgWsProxyTheme(themeMode = themeMode) {
                AppNavigation(
                    config = config,
                    themeMode = themeMode,
                    onThemeModeChange = {
                        config.themeMode = it
                        themeMode = it
                    },
                )
            }
        }
    }
}

enum class Screen { MAIN, SETTINGS, CONNECTIVITY }

@Composable
fun AppNavigation(config: ProxyConfig, themeMode: String, onThemeModeChange: (String) -> Unit) {
    var screen by rememberSaveable { mutableStateOf(Screen.MAIN) }
    BackHandler(enabled = screen != Screen.MAIN) { screen = Screen.MAIN }
    when (screen) {
        Screen.MAIN -> MainScreen(
            config = config,
            onOpenSettings = { screen = Screen.SETTINGS },
            onOpenConnectivity = { screen = Screen.CONNECTIVITY },
        )
        Screen.SETTINGS -> SettingsScreen(
            config = config,
            themeMode = themeMode,
            onThemeModeChange = onThemeModeChange,
            onClose = { screen = Screen.MAIN },
        )
        Screen.CONNECTIVITY -> ConnectivityScreen(
            config = config,
            onClose = { screen = Screen.MAIN },
        )
    }
}
