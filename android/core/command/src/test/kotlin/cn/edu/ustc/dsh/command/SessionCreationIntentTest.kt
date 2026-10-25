package cn.edu.ustc.dsh.command

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class SessionCreationIntentTest {
    private val request="66666666-6666-4666-8666-666666666666"
    private val runtime="33333333-3333-4333-8333-333333333333"
    private val epoch="44444444-4444-4444-8444-444444444444"
    private val workspace="88888888-8888-4888-8888-888888888888"
    private val result="bd7c25f4-d5aa-512c-9ac6-90c7a2dc0911"
    private fun intent()=CommandIntent.createSession(request,runtime,workspace,"standard",epoch)
    private fun receipt(state: RemoteCommandState,session: String?=null,time: String="2026-10-25T00:00:00Z")=CommandReceipt(request,session,intent().digest,state,time,workspaceId=workspace)
    @Test fun creationMatchesTheGoNodeGoldenWithoutInventingASessionTarget() {
        val folder=File(System.getProperty("contracts.root"),"ws/v1/golden")
        val original=JsonDocument.parse(File(folder,"session-create.json").readBytes()).root
        val forwarded=JsonDocument.parse(File(folder,"session-create.forwarded.json").readBytes()).root
        val parsed=CommandIntent.parse(original)
        assertEquals(forwarded.string("payload_sha256"),parsed.digest); assertEquals(parsed.digest,intent().digest)
        assertNull(parsed.sessionId); assertEquals(workspace,parsed.workspaceId)
        assertNotEquals(parsed.digest,CommandIntent.createSession(request,runtime,workspace,"review",epoch).digest)
        assertNotEquals(parsed.digest,CommandIntent.createSession(request,runtime,workspace,"standard",request).digest)
        for(bad in listOf(original.with("session_id" to result.json()),original.with("payload" to original.obj("payload").with("cwd" to "/tmp/private".json())),original.with("payload" to original.obj("payload").with("preset" to "../standard".json())))) assertThrows(ProtocolException::class.java) {CommandIntent.parse(bad)}
    }
    @Test fun settlementStoresASeparateImmutableResultAndNeverClaimsAgentAdmission() {
        val original=intent(); val started=CommandEvolution.begin(CommandEvolution.created(original,1000),1001)
        val saved=CommandEvolution.receipt(started,receipt(RemoteCommandState.HOST_ACCEPTED))
        val settled=CommandEvolution.receipt(saved,receipt(RemoteCommandState.SETTLED,result,"2026-10-25T00:00:00.000000001Z"))
        assertEquals(result,settled.createdSessionId); assertNull(settled.intent.sessionId); assertEquals(workspace,settled.intent.workspaceId)
        assertArrayEquals(original.storageBytes(),settled.intent.storageBytes()); assertTrue(settled.everHostSaved); assertFalse(settled.everAgentQueued)
        assertThrows(CommandDataException::class.java) { CommandEvolution.receipt(settled,receipt(RemoteCommandState.SETTLED,request,"2026-10-25T00:00:00.000000002Z")) }
        assertThrows(CommandDataException::class.java) { CommandEvolution.rearm(settled,receipt(RemoteCommandState.RECEIVED,time="2026-10-25T00:00:00.000000002Z")) }
    }
    @Test fun pendingAndSettledStatusShapesAreStrictAndUnknownOutcomesCannotReplay() {
        val folder=File(System.getProperty("contracts.root"),"ws/v1/golden")
        val pending=CommandReceipt.socket(JsonDocument.parse(File(folder,"device-session-create.received.json").readBytes()).root,runtime,epoch)
        val settled=CommandReceipt.socket(JsonDocument.parse(File(folder,"device-session-create.settled.json").readBytes()).root,runtime,epoch)
        assertEquals(workspace,pending.workspaceId); assertNull(pending.sessionId); assertEquals(result,settled.sessionId)
        assertThrows(ProtocolException::class.java) { receipt(RemoteCommandState.SETTLED) }
        assertThrows(ProtocolException::class.java) { receipt(RemoteCommandState.AGENT_QUEUED,result) }
        assertThrows(ProtocolException::class.java) { receipt(RemoteCommandState.RECEIVED,result) }
        val unknown=CommandEvolution.receipt(CommandEvolution.begin(CommandEvolution.created(intent(),0),1),receipt(RemoteCommandState.OUTCOME_UNKNOWN))
        assertThrows(CommandDataException::class.java) {CommandEvolution.rearm(unknown,receipt(RemoteCommandState.RECEIVED,time="2026-10-25T00:00:01Z"))}
    }
}
