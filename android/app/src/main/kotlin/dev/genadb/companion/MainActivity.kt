package dev.genadb.companion

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
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
import dev.genadb.sdk.ConnectionState
import dev.genadb.sdk.SetuManager

/** Minimal status screen; the product UI is out of scope for this milestone. */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Android 13+: the foreground-service notification (which shows the
        // pairing code) stays hidden unless the user grants this.
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        setContent { MaterialTheme { Screen() } }
    }

    @Composable
    private fun Screen() {
        val setu = remember { SetuManager.getInstance(this) }
        val state by setu.connectionState.collectAsStateWithLifecycle()
        val policy by setu.policyStatus.collectAsStateWithLifecycle()
        var relay by remember { mutableStateOf("wss://") }
        Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Setu", style = MaterialTheme.typography.headlineSmall)
            Text("1. Enable Developer options → Wireless debugging.")
            Button(onClick = { startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)) }) {
                Text("Open developer options")
            }
            OutlinedTextField(value = relay, onValueChange = { relay = it }, label = { Text("Relay URL") })
            Button(onClick = { AgentService.start(this@MainActivity, relay) }) { Text("Start") }
            Button(onClick = { AgentService.stop(this@MainActivity) }) { Text("Stop") }
            Text("Mode: ${policy.mode.name.lowercase()}" + if (policy.auditEnabled) " · audit on" else "")
            when (val st = state) {
                is ConnectionState.Online -> {
                    Text("Status: online as ${st.deviceId}")
                    st.pairingCode?.let { Text("Pairing code: $it", style = MaterialTheme.typography.headlineMedium) }
                    st.adbdEndpoint?.let { Text("adbd: $it") }
                    st.warning?.let { Text(it) }
                }
                is ConnectionState.Blocked -> Text("Status: blocked by device policy (${st.reason})")
                is ConnectionState.PolicyMissing -> Text("Status: waiting for device management (${st.missing} missing)")
                is ConnectionState.Reconnecting -> Text("Status: reconnecting (attempt ${st.attempt}): ${st.reason ?: ""}")
                ConnectionState.Starting -> Text("Status: starting")
                ConnectionState.Idle -> Text("Status: stopped")
            }
        }
    }
}
