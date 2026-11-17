package dev.genadb.sdk

import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.time.Instant
import java.time.format.DateTimeFormatter

/**
 * Append-only, SHA-256 hash-chained JSONL audit log, byte-compatible with the
 * Go SDK: `genadb audit verify --log <file>` and `genadb audit report` read it.
 * Each record carries `seq`, `prev_event_hash` and `event_hash`, the SHA-256 of
 * the record's canonical JSON (sorted keys, without `event_hash`).
 */
public class HashChainedAuditLog(
    public val file: File,
    private val clock: () -> Instant = Instant::now,
) : AuditSink {
    private var seq: Long = 0
    private var prev: String = GENESIS

    init {
        file.parentFile?.mkdirs()
        if (file.exists()) {
            file.useLines { lines ->
                lines.filter { it.isNotBlank() }.lastOrNull()?.let { last ->
                    runCatching { JSONObject(last) }.getOrNull()?.let { o ->
                        val h = o.optString("event_hash")
                        if (h.isNotEmpty()) {
                            seq = o.optLong("seq")
                            prev = h
                        }
                    }
                }
            }
        }
    }

    @Synchronized
    override fun record(type: String, deviceId: String?, fields: Map<String, String>): AuditEvent {
        val ts = DateTimeFormatter.ISO_INSTANT.format(clock())
        val m = sortedMapOf<String, Any>()
        fields.forEach { (k, v) -> m[k] = v }
        m["event"] = type
        m["role"] = "device"
        if (deviceId != null) m["device"] = deviceId
        m["ts"] = ts
        m["seq"] = seq + 1
        m["prev_event_hash"] = prev
        val hash = sha256Hex(CanonicalJson.encode(m))
        m["event_hash"] = hash
        file.appendText(CanonicalJson.encode(m) + "\n")
        val ev = AuditEvent(seq + 1, ts, type, deviceId, fields, hash, prev)
        seq += 1
        prev = hash
        return ev
    }

    public companion object {
        public const val GENESIS: String = "0000000000000000000000000000000000000000000000000000000000000000"

        /** Checks every link; returns the 1-based index of the first bad record, or 0 when intact. */
        public fun verify(file: File): Int {
            var prev: String? = null
            var i = 0
            file.useLines { lines ->
                for (line in lines) {
                    if (line.isBlank()) continue
                    i++
                    val o = runCatching { JSONObject(line) }.getOrNull() ?: return i
                    val h = o.optString("event_hash")
                    val m = sortedMapOf<String, Any>()
                    for (k in o.keys()) if (k != "event_hash") m[k] = o.get(k)
                    if (sha256Hex(CanonicalJson.encode(m)) != h) return i
                    val p = o.optString("prev_event_hash")
                    if (prev != null && p != prev) return i
                    prev = h
                }
            }
            return 0
        }

        internal fun sha256Hex(s: String): String =
            MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
    }
}

/** Compact JSON with sorted keys and Go encoding/json string escaping. */
internal object CanonicalJson {
    fun encode(v: Any?): String = StringBuilder().also { write(it, v) }.toString()

    private fun write(sb: StringBuilder, v: Any?) {
        when (v) {
            null, JSONObject.NULL -> sb.append("null")
            is String -> str(sb, v)
            is Boolean -> sb.append(v)
            is Int, is Long, is Short, is Byte -> sb.append(v.toString())
            is Number -> {
                val d = v.toDouble()
                if (d == Math.rint(d) && !d.isInfinite() && kotlin.math.abs(d) < 1e15) sb.append(d.toLong()) else sb.append(v.toString())
            }
            is Map<*, *> -> {
                sb.append('{')
                v.entries.map { it.key.toString() to it.value }.sortedBy { it.first }.forEachIndexed { i, (k, x) ->
                    if (i > 0) sb.append(',')
                    str(sb, k)
                    sb.append(':')
                    write(sb, x)
                }
                sb.append('}')
            }
            is JSONObject -> write(sb, v.keys().asSequence().associateWith { v.get(it) })
            else -> str(sb, v.toString())
        }
    }

    private const val HEX = "0123456789abcdef"

    private fun str(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c == '\b' -> sb.append("\\b")
                c == '\u000c' -> sb.append("\\f")
                c < ' ' || c == '<' || c == '>' || c == '&' ->
                    sb.append("\\u00").append(HEX[(c.code shr 4) and 0xF]).append(HEX[c.code and 0xF])
                c == '\u2028' || c == '\u2029' -> sb.append("\\u").append(c.code.toString(16))
                else -> sb.append(c)
            }
        }
        sb.append('"')
    }
}
