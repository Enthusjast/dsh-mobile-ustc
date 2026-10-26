package cn.edu.ustc.dsh.auth

import cn.edu.ustc.dsh.protocol.*
import java.util.Collections

/** Independently provisioned public origins; release metadata cannot enlarge this allowlist. */
class AppUpdateDeployment private constructor(val deploymentHash: String, val packageName: String, origins: Set<String>, private val document: JsonDocument) {
    val downloadOrigins: Set<String> = Collections.unmodifiableSet(LinkedHashSet(origins))
    val fingerprint get() = document.sha256()
    fun bytes() = document.canonicalBytes()
    override fun toString() = "AppUpdateDeployment"
    companion object {
        fun parse(raw: ByteArray, deployment: String, applicationPackage: String): AppUpdateDeployment {
            if (raw.size > 16 * 1024) throw ProtocolException()
            Contract.digest(deployment)
            val document = JsonDocument.parse(raw); val root = document.root
            root.exactKeys("v", "deployment_sha256", "package_name", "download_origins"); root.integer("v", 1, 1)
            if (root.string("deployment_sha256") != deployment || root.string("package_name") != applicationPackage) throw ProtocolException()
            val values = root.array("download_origins")
            if (values.size !in 1..8) throw ProtocolException()
            val origins = values.map {
                val origin = (it as? JsonString)?.value ?: throw ProtocolException()
                if (appUpdateOrigin(origin, originOnly = true) != origin) throw ProtocolException()
                origin
            }.toSet()
            if (origins.size != values.size) throw ProtocolException()
            return AppUpdateDeployment(deployment, applicationPackage, origins, document)
        }
    }
}
