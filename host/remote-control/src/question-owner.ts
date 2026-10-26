import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'

/** Match the existing remote directory, without reparenting native interactions. */
export function routableQuestionAgent(ctx: Context, agent: Agent | undefined, managed: (agent: Agent | undefined) => boolean,
  roots: ReadonlySet<Agent> = new Set(ctx.agents.roots())): agent is Agent {
  return agent !== undefined && managed(agent) && ctx.agents.get(agent.id) === agent && roots.has(agent) &&
    agent.session.header.parentSession === undefined && agent.session.header.origin !== 'subagent'
}
