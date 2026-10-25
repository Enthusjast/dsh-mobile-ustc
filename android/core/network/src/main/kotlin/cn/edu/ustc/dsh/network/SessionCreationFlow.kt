package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import java.util.Collections
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

enum class SessionCreationPhase { CONNECTING, OPTIONS, READY, OFFLINE, BACKOFF, AUTH_REQUIRED, REVOKED, ERROR, CLOSED }
class CreationWorkspace(val id: String, val label: String)
class SessionCreationOptions private constructor(val epoch: String, val workspaces: List<CreationWorkspace>, val presets: Set<String>) {
    companion object {
        fun parse(frame: JsonObject, runtime: String, request: String, scope: RelayScope): SessionCreationOptions {
            relayEnvelope(frame, "session.create.options.result", "v", "type", "request_id", "runtime_id", "runtime_epoch", "payload")
            if (frame.string("request_id") != request || frame.string("runtime_id") != runtime) throw ProtocolException()
            val payload=frame.obj("payload"); payload.exactKeys("workspaces", "presets")
            val values=payload.array("workspaces"); if(values.size>128) throw ProtocolException()
            val workspaces=values.map { value ->
                val item=value as? JsonObject ?: throw ProtocolException(); item.exactKeys("workspace_id", "label")
                val id=Contract.uuid(item.string("workspace_id")); val label=Contract.boundedText(item.string("label"),128)
                if(id !in scope.workspaces || label.isBlank() || label.codePointCount(0,label.length)>32 || label.any(Character::isISOControl)) throw ProtocolException()
                CreationWorkspace(id,label)
            }
            val presets=payload.array("presets").map { (it as? JsonString)?.value ?: throw ProtocolException() }
            if(workspaces.map { it.id }.toSet().size!=workspaces.size || presets.size>128 || presets.toSet().size!=presets.size || presets.any { !Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}").matches(it) }) throw ProtocolException()
            return SessionCreationOptions(Contract.uuid(frame.string("runtime_epoch")),Collections.unmodifiableList(workspaces),Collections.unmodifiableSet(presets.toSet()))
        }
    }
}
data class SessionCreationState(val phase: SessionCreationPhase=SessionCreationPhase.CONNECTING, val options: SessionCreationOptions?=null,
    val outbox: CommandOutboxState=CommandOutboxState(), val error: String?=null)

/** A runtime view owns one key-proved socket and the same durable command coordinator as chat. */
class SessionCreationFlow internal constructor(private val api: RemoteApi, private val device: String, private val runtime: String, private val grant: RelayScope,
    private val journal: CommandJournal, owner: CoroutineScope) : AutoCloseable {
    private val scope=CoroutineScope(SupervisorJob(owner.coroutineContext[Job])+Dispatchers.Default)
    private val mutable=MutableStateFlow(SessionCreationState())
    val state: StateFlow<SessionCreationState> = mutable.asStateFlow()
    private val closed=AtomicBoolean()
    private var authorized=false
    private val connection=AtomicReference<SessionRelayConnection?>()
    private val refreshes=Channel<Unit>(Channel.CONFLATED)
    private val commands=SessionCommands(api,journal,runtime,null,grant,scope)
    private class Stop(val phase: SessionCreationPhase,val code: String) : IllegalStateException(code)
    init {
        scope.launch { commands.state.collect { outbox -> publishOutbox(outbox) } }
        scope.launch { run() }
        scope.coroutineContext[Job]!!.invokeOnCompletion { close() }
    }
    @Synchronized private fun update(transform: (SessionCreationState)->SessionCreationState) { if(!closed.get()) mutable.update(transform) }
    @Synchronized private fun publishOutbox(outbox: CommandOutboxState) { if(authorized && !closed.get()) mutable.update { it.copy(outbox=outbox) } }
    @Synchronized private fun authorize() { if(!closed.get()) { authorized=true; mutable.update { it.copy(outbox=commands.state.value) }; commands.authorizeStatusReads() } }
    @Synchronized private fun stop(phase: SessionCreationPhase,code: String) { if(!closed.get()) { authorized=false; commands.close(); mutable.value=SessionCreationState(phase,error=code) } }
    fun refreshOptions() { refreshes.trySend(Unit) }
    fun query()=commands.query()
    suspend fun create(workspace: String,preset: String,expectedEpoch: String): String {
        val current=state.value
        val options=current.options ?: throw RelayException("runtime.offline")
        if(current.phase!=SessionCreationPhase.READY || options.epoch!=expectedEpoch) throw CommandDataException("runtime.changed")
        if(options.workspaces.none { it.id==workspace } || preset !in options.presets) throw RemoteRequestException("access.denied")
        return commands.createSession(workspace,preset,expectedEpoch).also { publishOutbox(commands.state.value) }
    }
    fun sendPending(id: String) {
        val options=state.value.options ?: return
        val record=state.value.outbox.records.firstOrNull { it.intent.requestId==id } ?: return
        if(record.intent.epoch!=options.epoch || options.workspaces.none { it.id==record.intent.workspaceId } || record.intent.payload.string("preset") !in options.presets) {
            update { it.copy(error="runtime.changed") }; return
        }
        commands.sendPending(id)
    }
    private suspend fun pause(attempt: Int?) {
        if(attempt==null) refreshes.receive() else withTimeoutOrNull((1000L shl attempt.coerceAtMost(5)).coerceAtMost(30_000)) { refreshes.receive() }
    }
    private suspend fun run() {
        var attempt=0
        while(scope.isActive) {
            try {
                update { it.copy(phase=SessionCreationPhase.CONNECTING,options=null,error=null) }
                if(api.me().userId!=journal.owner.userId) throw RemoteRequestException("auth.identity_mismatch")
                val connected=api.creationTicket(runtime,device,grant).connect(); connection.set(connected)
                currentCoroutineContext().ensureActive(); authorize()
                if(!connected.identity.capabilities.containsAll(setOf("connection.heartbeat.v1","command.relay.v1","session.create.v1","session.create_options.v1"))) throw RelayException("protocol.unsupported")
                consume(connected)
            } catch(error: CancellationException) { throw error }
            catch(error: Stop) {
                stop(error.phase,error.code)
                return
            } catch(error: RemoteRequestException) {
                val phase=when(error.code) {
                    "auth.expired","auth.proof_invalid"->SessionCreationPhase.AUTH_REQUIRED
                    "access.denied","access.revoked","device.invalid","auth.identity_mismatch","access.organization_missing"->SessionCreationPhase.REVOKED
                    else->null
                }
                if(phase!=null) { stop(phase,error.code); return }
                update { it.copy(phase=SessionCreationPhase.BACKOFF,options=null,error=error.code) }; pause(attempt++)
            } catch(error: cn.edu.ustc.dsh.auth.LoginException) { stop(SessionCreationPhase.AUTH_REQUIRED,"auth.expired"); return }
            catch(error: RelayException) {
                val permanent=error.code in setOf("protocol.unsupported","protocol.invalid","protocol.frame_too_large","network.proxy_unsupported","network.insecure_endpoint")
                update { it.copy(phase=if(permanent) SessionCreationPhase.ERROR else SessionCreationPhase.BACKOFF,options=null,error=error.code) }
                pause(if(permanent) null else attempt++)
            } catch(_: ProtocolException) { update { it.copy(phase=SessionCreationPhase.ERROR,options=null,error="protocol.invalid") }; pause(null) }
            catch(_: Exception) { update { it.copy(phase=SessionCreationPhase.ERROR,options=null,error="network.unavailable") }; pause(null) }
            finally { commands.disconnected(); connection.getAndSet(null)?.close() }
        }
    }
    @OptIn(ExperimentalCoroutinesApi::class)
    private suspend fun consume(connected: SessionRelayConnection): Unit=coroutineScope {
        val incoming=Channel<JsonObject>(2)
        val receiver=launch { try { while(isActive) incoming.send(connected.receive()) } catch(error: CancellationException) { throw error } catch(error: Exception) { incoming.close(error) } }
        var request: String?=null; var deadline=Long.MAX_VALUE
        val retired=linkedSetOf<String>()
        val lastPong=java.util.concurrent.atomic.AtomicLong(System.nanoTime())
        suspend fun options(force: Boolean=false) {
            if(request!=null && !force) return
            if(force) request?.let { retired+=it; if(retired.size>32) retired.remove(retired.first()) }
            commands.disconnected(); request=UUID.randomUUID().toString(); deadline=System.nanoTime()+10_000_000_000
            update { it.copy(phase=SessionCreationPhase.OPTIONS,options=null,error=null) }
            connected.send(jsonObject("v" to 1L.json(),"type" to "session.create.options.get".json(),"request_id" to request!!.json(),"runtime_id" to runtime.json(),"payload" to jsonObject()))
        }
        val heartbeat=launch { while(isActive) {
            delay(20_000)
            if(System.nanoTime()-lastPong.get()>45_000_000_000) throw RelayException("relay.timeout")
            connected.send(jsonObject("v" to 1L.json(),"type" to "ping".json(),"payload" to jsonObject()))
        } }
        try {
            options()
            while(isActive) {
                if(System.nanoTime()>=deadline) throw RelayException("relay.options_timeout")
                val frame=select<JsonObject?> {
                    incoming.onReceive { it }
                    refreshes.onReceive { options(); null }
                    onTimeout(100) { null }
                } ?: continue
                when(frame.string("type")) {
                    "session.create.options.result"->{
                        if(frame.fields["request_id"]?.let { (it as? JsonString)?.value in retired }==true) continue
                        val selected=SessionCreationOptions.parse(frame,runtime,request ?: throw ProtocolException(),grant)
                        request=null; deadline=Long.MAX_VALUE; commands.ready(connected,selected.epoch)
                        update { it.copy(phase=SessionCreationPhase.READY,options=selected,error=null) }
                    }
                    "command.receipt"->commands.hint(CommandReceipt.socket(frame,runtime))
                    "pong"->{
                        relayEnvelope(frame,"pong","v","type","payload"); val payload=frame.obj("payload"); payload.exactKeys("connection_id","server_time")
                        if(payload.string("connection_id")!=connected.identity.connectionId || kotlin.math.abs(relayTime(payload.string("server_time"))-System.currentTimeMillis())>30_000) throw ProtocolException()
                        lastPong.set(System.nanoTime())
                    }
                    "runtime.changed"->{ relayEnvelope(frame,"runtime.changed","v","type","payload"); frame.obj("payload").exactKeys("runtime_id"); if(frame.obj("payload").string("runtime_id")!=runtime) throw ProtocolException(); options(true) }
                    "access.revoked"->{ relayEnvelope(frame,"access.revoked","v","type","payload"); frame.obj("payload").exactKeys("code"); throw Stop(SessionCreationPhase.REVOKED,"access.revoked") }
                    "server.draining"->{ relayEnvelope(frame,"server.draining","v","type","payload"); frame.obj("payload").exactKeys("reason"); if(frame.obj("payload").string("reason")!="server_draining") throw ProtocolException(); throw RelayException() }
                    "error"->{
                        val required=setOf("v","type","payload"); val optional=setOf("request_id","runtime_id","runtime_epoch","session_id")
                        if(!frame.fields.keys.containsAll(required) || frame.fields.keys.any { it !in required && it !in optional } || frame.integer("v",1,1)!=1L || frame.fields["session_id"]!=null || frame.fields["runtime_id"]?.let { it!=runtime.json() }==true) throw ProtocolException()
                        val payload=frame.obj("payload"); payload.exactKeys("code"); val code=payload.string("code")
                        if(code in setOf("access.denied","access.revoked","device.invalid")) throw Stop(SessionCreationPhase.REVOKED,code)
                        if(code in setOf("auth.expired","auth.proof_invalid")) throw Stop(SessionCreationPhase.AUTH_REQUIRED,code)
                        val id=frame.fields["request_id"]?.let { (it as? JsonString)?.value ?: throw ProtocolException() }
                        if(id in retired) continue
                        if(id==request && request!=null) { request=null; deadline=Long.MAX_VALUE; commands.disconnected(); update { it.copy(phase=if(code=="runtime.offline") SessionCreationPhase.OFFLINE else SessionCreationPhase.ERROR,options=null,error=code) } }
                        else if(id==null || !commands.failed(id,code)) throw ProtocolException()
                        else if(code in setOf("runtime.offline","runtime.changed")) options(true)
                    }
                    else->throw ProtocolException()
                }
            }
        } finally { receiver.cancel(); incoming.cancel(); heartbeat.cancel() }
    }
    @Synchronized override fun close() {
        if(!closed.compareAndSet(false,true)) return
        authorized=false; commands.close(); scope.cancel(); connection.getAndSet(null)?.close(); refreshes.cancel(); mutable.value=SessionCreationState(SessionCreationPhase.CLOSED)
    }
}
