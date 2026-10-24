package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.auth.*
import kotlinx.coroutines.CancellationException
import java.util.concurrent.atomic.AtomicBoolean

/** One reviewed intent. Keep only the public details in UI state and close on scope changes. */
class HostBindingRequest internal constructor(private val api: RemoteApi, val details: HostBindingDetails, code: String) : AutoCloseable {
    private val used = AtomicBoolean()
    private val cancelled = AtomicBoolean()
    private val secret = code.toCharArray()
    suspend fun confirm(onDispatch: () -> Unit = {}): HostBindingDetails {
        if (!used.compareAndSet(false, true)) throw HostBindingException("binding.intent_consumed")
        val copy = synchronized(secret) { current(); secret.copyOf() }
        return try { api.confirmReviewedBinding(details, String(copy), ::current, onDispatch) }
        finally { copy.fill('\u0000'); close() }
    }
    private fun current() { if (cancelled.get()) throw CancellationException("Binding review was retired") }
    override fun close() { cancelled.set(true); synchronized(secret) { secret.fill('\u0000') } }
    override fun toString() = "HostBindingRequest"
}
