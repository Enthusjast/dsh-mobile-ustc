package cn.edu.ustc.dsh.auth

import java.io.File

object ValidateAppUpdateDeployment {
    @JvmStatic fun main(args: Array<String>) {
        require(args.size == 3)
        val login = LoginConfiguration.parse(File(args[1]).readBytes())
        val parsed = AppUpdateDeployment.parse(File(args[0]).readBytes(), login.fingerprint, "cn.edu.ustc.dsh.mobile")
        File(args[2]).apply { parentFile.mkdirs(); writeBytes(parsed.bytes()) }
    }
}
