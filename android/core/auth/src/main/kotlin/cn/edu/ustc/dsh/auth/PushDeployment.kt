package cn.edu.ustc.dsh.auth

import cn.edu.ustc.dsh.protocol.*

/** Public Firebase application configuration, bound to one trusted resource deployment. */
class PushDeployment private constructor(val deploymentHash: String, val packageName: String, val projectId: String, val applicationId: String, val senderId: String, val apiKey: String,
    private val document: JsonDocument) {
    fun bytes() = document.canonicalBytes()
    val fingerprint get() = document.sha256()
    override fun toString() = "PushDeployment"
    companion object {
        fun parse(raw: ByteArray, deployment: String, applicationPackage: String): PushDeployment {
            if (raw.size > 16 * 1024) throw ProtocolException()
            Contract.digest(deployment)
            val document = JsonDocument.parse(raw); val root = document.root
            root.exactKeys("v", "deployment_sha256", "package_name", "fcm"); root.integer("v", 1, 1)
            val provider = root.obj("fcm"); provider.exactKeys("project_id", "application_id", "sender_id", "api_key")
            if (root.string("deployment_sha256") != deployment || root.string("package_name") != applicationPackage) throw ProtocolException()
            val project = provider.string("project_id"); val app = provider.string("application_id"); val sender = provider.string("sender_id"); val key = provider.string("api_key")
            if (!Regex("([a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{6,20})").matches(project) || !Regex("[0-9]{6,20}").matches(sender) ||
                !Regex("1:[0-9]{6,20}:android:[a-fA-F0-9]{8,64}").matches(app) || !app.startsWith("1:$sender:android:") || !Regex("[A-Za-z0-9_-]{20,256}").matches(key)) throw ProtocolException()
            return PushDeployment(deployment, applicationPackage, project, app, sender, key, document)
        }
    }
}
