package org.flowseal.tgwsproxy.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF3390EC),
    onPrimary = Color.White,
    secondaryContainer = Color(0xFFD6E8FB),
    onSecondaryContainer = Color(0xFF0B3B66),
    background = Color(0xFFF7F8FA),
    surface = Color.White,
    onSurface = Color.Black,
    surfaceVariant = Color(0xFFF0F2F5),
    onSurfaceVariant = Color(0xFF707579),
    outline = Color(0xFFDADCE0),
    surfaceContainerHighest = Color(0xFFE6E8EB),
)

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF5EA8F0),
    onPrimary = Color.White,
    secondaryContainer = Color(0xFF1F3A55),
    onSecondaryContainer = Color(0xFFD6E8FB),
    background = Color(0xFF121212),
    surface = Color(0xFF1E1E1E),
    onSurface = Color(0xFFE0E0E0),
    surfaceVariant = Color(0xFF2C2C2C),
    onSurfaceVariant = Color(0xFFA0A4A8),
    outline = Color(0xFF444444),
    surfaceContainerHighest = Color(0xFF3A3A3A),
)

val LocalIsDarkTheme = staticCompositionLocalOf { false }

/** "system", "light" or "dark" (ProxyConfig.themeMode). */
@Composable
fun isDarkTheme(themeMode: String): Boolean = when (themeMode) {
    "dark" -> true
    "light" -> false
    else -> isSystemInDarkTheme()
}

@Composable
fun TgWsProxyTheme(themeMode: String = "system", content: @Composable () -> Unit) {
    val isDark = isDarkTheme(themeMode)
    CompositionLocalProvider(LocalIsDarkTheme provides isDark) {
        MaterialTheme(colorScheme = if (isDark) DarkColorScheme else LightColorScheme, content = content)
    }
}

/** Status colours that read well on both themes. */
object StatusColors {
    val running = Color(0xFF4CAF50)
    val stopped = Color(0xFFFF9800)
    val failed = Color(0xFFE53935)

    fun runningBackground(dark: Boolean) = if (dark) Color(0xFF1B3A1B) else Color(0xFFE8F5E9)
    fun stoppedBackground(dark: Boolean) = if (dark) Color(0xFF3A2E1B) else Color(0xFFFFF3E0)
    fun failedBackground(dark: Boolean) = if (dark) Color(0xFF3D1E1E) else Color(0xFFFDECEA)
}
