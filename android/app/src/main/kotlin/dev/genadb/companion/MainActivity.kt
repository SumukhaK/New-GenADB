package dev.genadb.companion

import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/** Minimal status screen; the product UI is out of scope for this milestone. */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { Screen() } }
    }

    @Composable
    private fun Screen() {
        val state by AgentService.state.collectAsStateWithLifecycle()
        var relay by remember { mutableStateOf("wss://") }
        Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("GenADB Companion", style = MaterialTheme.typography.headlineSmall)
            Text("1. Enable Developer options → Wireless debugging.")
            Button(onClick = { startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)) }) {
                Text("Open developer options")
            }
            OutlinedTextField(value = relay, onValueChange = { relay = it }, label = { Text("Relay URL") })
            Button(onClick = { AgentService.start(this@MainActivity, relay) }) { Text("Start") }
            Button(onClick = { AgentService.stop(this@MainActivity) }) { Text("Stop") }
            Text("Status: " + when {
                state.blockedReason != null -> "blocked by device policy (${state.blockedReason})"
                state.online -> "online as ${state.deviceId}"
                else -> "offline"
            })
            state.pairingCode?.let { Text("Pairing code: $it", style = MaterialTheme.typography.headlineMedium) }
            state.adbdEndpoint?.let { Text("adbd: $it") }
            state.lastError?.let { Text("Last error: $it") }
        }
    }
}
