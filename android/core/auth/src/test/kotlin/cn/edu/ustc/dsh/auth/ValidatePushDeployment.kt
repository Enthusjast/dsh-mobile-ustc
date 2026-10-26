package cn.edu.ustc.dsh.auth

import java.io.File

object ValidatePushDeployment {
    @JvmStatic fun main(args: Array<String>) {
        require(args.size == 3)
        val expected = LoginConfiguration.parse(File(args[1]).readBytes())
        val parsed = PushDeployment.parse(File(args[0]).readBytes(), expected.fingerprint, "cn.edu.ustc.dsh.mobile")
        File(args[2]).apply { parentFile.mkdirs(); writeBytes(parsed.bytes()) }
    }
}
