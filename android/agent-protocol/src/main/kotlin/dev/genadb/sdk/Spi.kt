package dev.genadb.sdk

import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/** A running agent process. */
public interface AgentProcess {
    /** Next line of the agent's JSON event stream, or null at end of stream. Blocks. */
    public fun readLine(): String?

    /** Waits for exit and returns the exit code. */
    public fun waitFor(): Int

    /** Terminates the process; must unblock [readLine]. */
    public fun destroy()

    /**
     * Sends one command line to the agent's stdin (v1.1.0+, e.g. ending a
     * session). Returns false when the process cannot take commands.
     */
    public fun writeLine(line: String): Boolean = false
}

/** Starts the connectivity agent. Replace it in tests or to host the agent elsewhere. */
public fun interface AgentLauncher {
    public fun launch(args: List<String>, env: Map<String, String>): AgentProcess
}

/** Launches the agent executable with [ProcessBuilder]; stderr goes to [logFile]. */
public class ProcessAgentLauncher(
    private val executable: File,
    private val logFile: File? = null,
) : AgentLauncher {
    override fun launch(args: List<String>, env: Map<String, String>): AgentProcess {
        val pb = ProcessBuilder(listOf(executable.absolutePath) + args)
        if (logFile != null) pb.redirectError(logFile) else pb.redirectError(File("/dev/null")) // Redirect.DISCARD is not in android.jar
        pb.environment().putAll(env)
        val p = pb.start()
        val reader = BufferedReader(InputStreamReader(p.inputStream, Charsets.UTF_8))
        val writer = p.outputStream.bufferedWriter(Charsets.UTF_8)
        return object : AgentProcess {
            override fun readLine(): String? = runCatching { reader.readLine() }.getOrNull()
            override fun waitFor(): Int = p.waitFor()
            override fun destroy() {
                p.destroy()
            }
            override fun writeLine(line: String): Boolean = synchronized(writer) {
                runCatching { writer.write(line); writer.newLine(); writer.flush() }.isSuccess
            }
        }
    }
}

/** Configuration pushed by device management (EMM managed configuration, user restrictions). */
public data class ManagedPolicy(
    val relayUrl: String? = null,
    val enrollmentToken: String? = null,
    val policyJson: String? = null,
    val relayPin: String? = null,
    val debuggingAllowed: Boolean = true,
)

/** Supplies [ManagedPolicy]; the Android default reads RestrictionsManager and UserManager. */
public fun interface PolicyProvider {
    public fun current(): ManagedPolicy
}

/** Network facts the statically linked agent cannot discover itself. */
public fun interface NetworkInfoProvider {
    /** DNS servers of the active network (the agent has no system resolver on Android). */
    public fun dnsServers(): List<String>
}

/** Receives audit records. [HashChainedAuditLog] is the default. */
public interface AuditSink {
    /** Seals and stores an event; returns the sealed record. */
    public fun record(type: String, deviceId: String?, fields: Map<String, String>): AuditEvent

    public fun close() {}
}
