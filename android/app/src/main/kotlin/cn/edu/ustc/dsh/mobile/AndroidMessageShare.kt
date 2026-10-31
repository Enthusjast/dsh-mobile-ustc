package cn.edu.ustc.dsh.mobile

import android.content.Context
import android.content.Intent
import cn.edu.ustc.dsh.command.CommandDataException
import cn.edu.ustc.dsh.network.AuthorizedMessageShare

/** Only a freshly confirmed, still-current message handle may leave the app. */
internal fun launchAuthorizedMessageShare(context: Context, share: AuthorizedMessageShare) {
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, share.text)
    }
    val chooser = Intent.createChooser(send, context.getString(R.string.changes_fork_share_chooser))
    if (!share.current()) throw CommandDataException("message.stale")
    context.startActivity(chooser)
}
