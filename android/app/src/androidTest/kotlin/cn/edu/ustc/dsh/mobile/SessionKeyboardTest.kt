package cn.edu.ustc.dsh.mobile

import android.graphics.Rect
import android.os.Bundle
import android.os.SystemClock
import android.view.MotionEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.isImeVisible
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.platform.LocalDensity
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.command.CommandOwner
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.ui.DshTheme
import java.io.File
import java.util.ArrayDeque
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** No Compose input-service interceptor: exercise the installed system IME and native touch dispatch. */
@OptIn(ExperimentalLayoutApi::class)
@RunWith(AndroidJUnit4::class)
class SessionKeyboardTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val automation get() = instrumentation.uiAutomation

    @Test fun actualKeyboardKeepsSendReachableAndFirstBackOnlyDismissesIt() {
        val id = "11111111-1111-4111-8111-111111111111"
        val access = RuntimeDirectoryEntry.parse(jsonObject("id" to id.json(), "host_id" to id.json(),
            "organization_id" to id.json(), "protocol_version" to 1L.json(), "access" to jsonObject(
                "role" to "operator".json(), "grant_version" to 1L.json(),
                "scope" to RelayScope(listOf("session.read", "session.list", "message.submit", "command.status"), emptyList(), listOf(id)).json())))
        val owner = CommandOwner(id, id, "a".repeat(64), id, id)
        val live = mutableStateOf(HomeState(HomePhase.READY, presentationOwner = owner,
            composer = MessageComposerState(ConversationResource(owner, id, id, id)),
            runtimes = listOf(RuntimeRow(id, id, "fixture", "电脑夹具", access)), selectedRuntimeId = id,
            selectedSessionId = id, reader = SessionReadState(SessionReadPhase.READY), outbox = CommandOutboxState(connected = true)))
        val backs = AtomicInteger()
        val imeBottom = AtomicInteger()
        val imeShown = AtomicBoolean()
        val activity = AtomicReference<ComponentActivity>()
        ActivityScenario.launch(ComponentActivity::class.java).use { scenario ->
            scenario.onActivity { host ->
                activity.set(host)
                host.enableEdgeToEdge()
                host.setContent {
                    val bottom = WindowInsets.ime.getBottom(LocalDensity.current)
                    val visible = WindowInsets.isImeVisible
                    SideEffect { imeBottom.set(bottom); imeShown.set(visible) }
                    DshTheme {
                        SessionsScreen(live.value, { backs.incrementAndGet() }, {}, {}, {},
                            onComposerChange = { live.value = live.value.copy(composer = it.copy(revision = it.revision + 1)) })
                    }
                }
            }
            waitFor("Activity window focus") { activity.get()?.hasWindowFocus() == true }
            waitFor("Editable message field") { find { it.isEditable } != null }
            tap(requireNotNull(find { it.isEditable }))
            waitFor("Focused native message field") { find { it.isEditable && it.isFocused } != null }
            try { waitFor("Installed system IME visibility") { imeShown.get() } }
            catch (failure: IllegalStateException) {
                val folder = File(instrumentation.targetContext.filesDir, "ui-navigation-fixtures").apply { mkdirs() }
                automation.takeScreenshot()?.let { bitmap ->
                    try { File(folder, "native-keyboard-failure.png").outputStream().use { check(bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it)) } }
                    finally { bitmap.recycle() }
                }
                val nativeBottom = AtomicInteger()
                val nativeVisible = AtomicInteger()
                instrumentation.runOnMainSync {
                    val insets = androidx.core.view.ViewCompat.getRootWindowInsets(activity.get().window.decorView)
                    nativeBottom.set(insets?.getInsets(androidx.core.view.WindowInsetsCompat.Type.ime())?.bottom ?: -1)
                    nativeVisible.set(if (insets?.isVisible(androidx.core.view.WindowInsetsCompat.Type.ime()) == true) 1 else 0)
                }
                throw IllegalStateException("IME visibility mismatch: Compose=${imeShown.get()}, inset=${imeBottom.get()}, platform=${nativeBottom.get()}, visible=${nativeVisible.get()}", failure)
            }
            val arguments = Bundle().apply {
                putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, "键盘中的消息")
            }
            assertTrue(requireNotNull(find { it.isEditable }).performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, arguments))
            waitFor("Send action becomes enabled") { find { it.contentDescription?.toString() == "发送 · 排队" }?.isEnabled == true }
            val send = requireNotNull(find { it.contentDescription?.toString() == "发送 · 排队" })
            val sendBounds = Rect().also(send::getBoundsInScreen)
            val screenHeight = if (android.os.Build.VERSION.SDK_INT >= 30) activity.get().windowManager.currentWindowMetrics.bounds.height()
                else android.util.DisplayMetrics().also { activity.get().windowManager.defaultDisplay.getRealMetrics(it) }.heightPixels
            assertTrue("Send must remain above the real IME: $sendBounds; inset=${imeBottom.get()}", sendBounds.bottom <= screenHeight - imeBottom.get())
            assertTrue(send.isVisibleToUser)
            automation.takeScreenshot()?.let { bitmap ->
                try {
                    val folder = File(instrumentation.targetContext.filesDir, "ui-navigation-fixtures").apply { mkdirs() }
                    File(folder, "native-keyboard.png").outputStream().use {
                        check(bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it))
                    }
                } finally { bitmap.recycle() }
            }
            tap(requireNotNull(find { it.contentDescription?.toString() == "返回会话列表" }))
            waitFor("First back closes the IME session") { !imeShown.get() }
            assertEquals(0, backs.get())
            assertEquals("键盘中的消息", requireNotNull(find { it.isEditable }).text?.toString())
            tap(requireNotNull(find { it.contentDescription?.toString() == "返回会话列表" }))
            waitFor("Second back leaves conversation") { backs.get() == 1 }
        }
    }

    private fun find(matches: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo? {
        val root = automation.rootInActiveWindow ?: return null
        val pending = ArrayDeque<AccessibilityNodeInfo>()
        pending.add(root)
        while (pending.isNotEmpty()) {
            val node = pending.removeFirst()
            if (node.packageName?.toString() == instrumentation.targetContext.packageName && node.isVisibleToUser && matches(node)) return node
            for (index in 0 until node.childCount) node.getChild(index)?.let(pending::addLast)
        }
        return null
    }

    private fun tap(node: AccessibilityNodeInfo) {
        val bounds = Rect().also(node::getBoundsInScreen)
        check(!bounds.isEmpty && node.isVisibleToUser)
        val down = SystemClock.uptimeMillis()
        for (action in intArrayOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_UP)) {
            val event = MotionEvent.obtain(down, SystemClock.uptimeMillis(), action, bounds.exactCenterX(), bounds.exactCenterY(), 0)
            event.source = android.view.InputDevice.SOURCE_TOUCHSCREEN
            try { check(automation.injectInputEvent(event, true)) } finally { event.recycle() }
            if (action == MotionEvent.ACTION_DOWN) SystemClock.sleep(50)
        }
    }

    private fun waitFor(label: String, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 10_000
        while (!condition()) {
            check(SystemClock.elapsedRealtime() < deadline) { "Timed out waiting for $label" }
            SystemClock.sleep(30)
        }
    }
}
