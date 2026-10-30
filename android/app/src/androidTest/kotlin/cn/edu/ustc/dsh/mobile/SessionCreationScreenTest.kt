package cn.edu.ustc.dsh.mobile

import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.network.*
import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.ui.DshTheme
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SessionCreationScreenTest {
    @get:Rule val rule=createAndroidComposeRule<ComponentActivity>()
    private val id="11111111-1111-4111-8111-111111111111"
    private val workspace="88888888-8888-4888-8888-888888888888"
    private val epoch="44444444-4444-4444-8444-444444444444"
    private val grant=RelayScope(listOf("session.list","session.read","session.create","command.status"),listOf(workspace),emptyList())
    private fun state(records: List<PendingCommand> = emptyList()): HomeState {
        val runtime=RuntimeDirectoryEntry.parse(jsonObject("id" to id.json(),"host_id" to id.json(),"organization_id" to id.json(),"protocol_version" to 1L.json(),"access" to jsonObject("role" to "operator".json(),"grant_version" to 1L.json(),"scope" to grant.json())))
        val choices=SessionCreationOptions.parse(jsonObject("v" to 1L.json(),"type" to "session.create.options.result".json(),"request_id" to id.json(),"runtime_id" to id.json(),"runtime_epoch" to epoch.json(),"payload" to jsonObject("workspaces" to JsonArray(listOf(jsonObject("workspace_id" to workspace.json(),"label" to "研究项目".json()))),"presets" to JsonArray(listOf("standard".json())))),id,id,grant)
        return HomeState(HomePhase.READY,runtimes=listOf(RuntimeRow(id,id,"0.2.1-rc.2","夹具电脑",runtime)),selectedRuntimeId=id,
            creation=SessionCreationState(SessionCreationPhase.READY,choices,CommandOutboxState(records,connected=true)))
    }
    private fun select() {
        rule.onNode(hasScrollToIndexAction()).performScrollToNode(hasText("选择工作区"))
        rule.onNodeWithText("选择工作区").performScrollTo().performClick()
        rule.onNodeWithText("研究项目 · 88888888").performClick()
        rule.onNodeWithText("选择助手配置").performScrollTo().performClick()
        rule.onNodeWithText("standard",substring=false).performClick()
    }
    @Test fun onlyExplicitAdvertisedWorkspaceAndPresetChoicesCanCreate() {
        var submitted: Triple<String,String,String>?=null
        rule.setContent { DshTheme {SessionCreationScreen(state(),{w,p,e->submitted=Triple(w,p,e)},{},{},{},{},{})} }
        rule.onNodeWithText("创建新会话").performScrollTo().assertIsNotEnabled()
        select();rule.onNodeWithText("创建新会话").performScrollTo().assertIsEnabled().performClick()
        rule.runOnIdle {assertEquals(Triple(workspace,"standard",epoch),submitted)}
    }
    @Test fun unsubmittedChoicesDoNotSurviveSavedInstanceStateRestore() {
        val restoration=StateRestorationTester(rule)
        restoration.setContent {DshTheme {SessionCreationScreen(state(),{_,_,_->},{},{},{},{},{})}}
        select();rule.onNodeWithText("创建新会话").assertIsEnabled()
        restoration.emulateSavedInstanceStateRestore()
        rule.onNodeWithText("创建新会话").performScrollTo().assertIsNotEnabled()
    }
    @Test fun unknownCreationRequiresANewIntentDecisionAndNeverOffersBlindRetry() {
        val intent=CommandIntent.createSession(id,id,workspace,"standard",epoch)
        val unknown=CommandEvolution.receipt(CommandEvolution.begin(CommandEvolution.created(intent,0),1),CommandReceipt(id,null,intent.digest,RemoteCommandState.OUTCOME_UNKNOWN,"2026-10-25T00:00:00Z",workspaceId=workspace))
        var submitted=0; var queries=0
        rule.setContent {
            val density=LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density,2f)) {
                DshTheme { Box(Modifier.width(320.dp)) { SessionCreationScreen(state(listOf(unknown)),{_,_,_->submitted++},{},{queries++},{},{},{}) } }
            }
        }
        rule.onNode(hasScrollToIndexAction()).performScrollToNode(hasText("创建结果待确认"))
        rule.onNodeWithText("创建结果待确认").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("重新转交同一请求").assertDoesNotExist();rule.onNodeWithText("会话已创建").assertDoesNotExist()
        rule.onNodeWithText("原始请求编号：$id").performScrollTo().assertIsDisplayed()
        select();rule.onNodeWithText("创建新会话").performScrollTo().performClick()
        rule.runOnIdle {assertEquals(0,submitted)}
        rule.onNodeWithText("先核对原请求").performClick()
        rule.runOnIdle {assertEquals(1,queries);assertEquals(0,submitted)}
        rule.onNodeWithText("创建新会话").performScrollTo().performClick()
        rule.onNodeWithText("确认为另一个新请求").performClick()
        rule.runOnIdle {assertEquals(1,submitted);assertEquals(id,unknown.intent.requestId)}
    }
    @Test fun aSettledResultOpensByItsOriginalRequestInsteadOfAnInventedSessionEntry() {
        val intent=CommandIntent.createSession(id,id,workspace,"standard",epoch)
        val settled=CommandEvolution.receipt(CommandEvolution.begin(CommandEvolution.created(intent,0),1),CommandReceipt(id,workspace,intent.digest,RemoteCommandState.SETTLED,"2026-10-25T00:00:00Z",workspaceId=workspace))
        var opened: String?=null
        rule.setContent {DshTheme {SessionCreationScreen(state(listOf(settled)),{_,_,_->},{},{},{},{opened=it},{})}}
        rule.onNode(hasScrollToIndexAction()).performScrollToNode(hasText("会话已创建"))
        rule.onNodeWithText("会话已创建").performScrollTo().assertIsDisplayed()
        rule.onNodeWithText("读取已创建的会话").performScrollTo().performClick()
        rule.runOnIdle {assertEquals(id,opened)}
    }
}
