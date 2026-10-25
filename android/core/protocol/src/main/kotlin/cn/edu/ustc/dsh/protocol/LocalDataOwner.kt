package cn.edu.ustc.dsh.protocol

/** Local encrypted data is isolated from every other account, deployment and device. */
class LocalDataOwner(val accountId: String, val organizationId: String, val deploymentHash: String, val userId: String, val deviceId: String) {
    init { listOf(accountId, organizationId, userId, deviceId).forEach(Contract::uuid); Contract.digest(deploymentHash) }
    val scopeHash = scopeHash(accountId, organizationId)
    val root = jsonObject("account_id" to accountId.json(), "organization_id" to organizationId.json(), "deployment_sha256" to deploymentHash.json(), "user_id" to userId.json(), "device_id" to deviceId.json())
    val fingerprint = JsonDocument.of(root).sha256()
    companion object {
        fun scopeHash(account: String, organization: String): String = JsonDocument.of(jsonObject("account_id" to Contract.uuid(account).json(), "organization_id" to Contract.uuid(organization).json())).sha256()
    }
}
