package cn.edu.ustc.dsh.mobile

/** Presentation position only; callers must revalidate the resource and the message key before restoring. */
class ChatReadingPosition {
    var key: String? = null
    var offset: Int = 0
    var following: Boolean = true
}
