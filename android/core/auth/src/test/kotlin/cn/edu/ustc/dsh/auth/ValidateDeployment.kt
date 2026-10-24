package cn.edu.ustc.dsh.auth

import cn.edu.ustc.dsh.protocol.JsonDocument
import java.io.File

/** Build helper only; never packaged in the Android application. */
object ValidateDeployment {
    @JvmStatic fun main(args: Array<String>) {
        require(args.size == 2)
        val input = File(args[0])
        require(input.isFile && input.length() <= JsonDocument.MAX_BYTES)
        val bytes = input.readBytes()
        LoginConfiguration.parse(bytes)
        val output = File(args[1])
        output.parentFile.mkdirs()
        output.writeBytes(JsonDocument.parse(bytes).canonicalBytes())
    }
}
