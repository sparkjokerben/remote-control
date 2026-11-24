/**
 * E2EE 载荷消息（契约 §2.6）。帧本身由 ratchet 加密，这里只定义明文结构。
 */

export type MessageRole = 'user' | 'assistant' | 'system' | 'tool'

export interface MessageView {
  id: string
  role: MessageRole
  text: string
  ts: number
  toolName?: string
}

export interface QuestionOption {
  id: string
  label: string
}

export interface PendingQuestion {
  id: string
  header?: string
  question: string
  multiSelect: boolean
  options: QuestionOption[]
}

export interface PendingInteraction {
  id: string
  kind: 'approval' | 'question'
  toolName?: string
  callId?: string
  reason?: string
  questions?: PendingQuestion[]
}

export type EncryptedClientMessage =
  | { t: 'snapshot.request' }
  | { t: 'prompt'; text: string; mode: 'followup' | 'steer' }
  | { t: 'cancel' }
  | { t: 'approval.resolve'; interactionId: string; outcome: 'allowed-once' | 'rejected' }
  | {
      t: 'question.answer'
      interactionId: string
      answers: Array<{ id: string; selected: string[]; custom?: string }>
    }
  | { t: 'model.set'; provider: string; model: string; reasoningEffort?: string }
  | { t: 'preset.set'; preset: 'workspace-write' | 'danger-full-access' }
  | { t: 'ping'; ts: number }

export type EncryptedNodeMessage =
  | {
      t: 'snapshot'
      sessionId: string
      title: string
      cwd: string
      status: 'running' | 'idle'
      model?: { provider: string; model: string }
      preset?: string
      seq: number
      messages: MessageView[]
      pending: PendingInteraction[]
    }
  | { t: 'delta'; seq: number; text: string }
  | { t: 'message'; message: MessageView }
  | {
      t: 'tool'
      phase: 'call' | 'result'
      callId: string
      name: string
      args?: string
      result?: string
      ok?: boolean
    }
  | { t: 'status'; status: 'running' | 'idle' }
  | { t: 'interaction.open'; interaction: PendingInteraction }
  | { t: 'interaction.settled'; interactionId: string }
  | { t: 'pong'; ts: number }
  | { t: 'error'; code: string; message: string }
