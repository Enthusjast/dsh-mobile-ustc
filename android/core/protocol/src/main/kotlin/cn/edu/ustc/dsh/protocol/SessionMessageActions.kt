package cn.edu.ustc.dsh.protocol

const val SESSION_MESSAGE_ACTIONS_CAPABILITY = "session.message.actions.v1"

class SessionMessagePreview private constructor(val anchor: SessionForkAnchor, val text: String?, val shareable: Boolean, val complete: Boolean) {
    companion object {
        fun parse(root: JsonObject): SessionMessagePreview {
            root.exactKeys("v", "anchor", "text", "shareable", "complete"); root.integer("v", 1, 1)
            if (sessionActionPayloadBytes(root) > 48 * 1024 || (root["complete"] as? JsonBoolean)?.value != true) throw ProtocolException()
            val text = when (val value = root["text"]) { JsonNull -> null; is JsonString -> value.value; else -> throw ProtocolException() }
            val shareable = (root["shareable"] as? JsonBoolean)?.value ?: throw ProtocolException()
            if (text != null) {
                requireText(text)
                if (text.toByteArray(Charsets.UTF_8).size > 32 * 1024 || text.any { it == '\u007f' || it < ' ' && it !in "\n\r\t" }) throw ProtocolException()
            }
            if (shareable != (text != null && text.isNotEmpty())) throw ProtocolException()
            return SessionMessagePreview(SessionForkAnchor.parse(root.obj("anchor")), text, shareable, true)
        }
    }
}
