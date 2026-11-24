/**
 * Web 客户端加法入口：只在会话头部与侧栏底部各注册一个 list 插槽按钮。
 * 通过同源 `api/gooftoken-remote/control` 读写远控状态，不注入全局 CSS，
 * 不注册 single/hoc 插槽。仓库未依赖 layout 包，插槽名与 props 做最小断言。
 */
import * as React from 'react'

import type { Context } from '@deepseek-ai/cordis'

export const name = 'remote-control-client'
export const inject = ['slots']

export const CONTROL_ENDPOINT = 'api/gooftoken-remote/control'

const SESSION_SLOT = 'conversation.session.header.actions'
const SIDEBAR_SLOT = 'sidebar.footer.action'

interface SlotsLike {
  inject(key: string, callback: () => unknown): unknown
  register(options: Record<string, unknown>, component: unknown): unknown
}

interface ControlStatusData {
  session?: { shared?: boolean; safetyNumber?: string }
  webui?: { available?: boolean; active?: boolean }
}

interface ControlResponse {
  ok?: boolean
  data?: ControlStatusData
  error?: { code?: string; message?: string }
}

interface SessionHeaderProps {
  sessionId?: string
}

interface SidebarFooterProps {
  wide?: boolean
}

const BUTTON_STYLE: React.CSSProperties = {
  appearance: 'none',
  border: '1px solid currentColor',
  borderRadius: 6,
  background: 'transparent',
  color: 'inherit',
  cursor: 'pointer',
  font: 'inherit',
  lineHeight: 1.2,
  padding: '2px 8px',
  whiteSpace: 'nowrap',
}

async function requestControl(body: Record<string, unknown>): Promise<ControlResponse> {
  const response = await fetch(CONTROL_ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  return (await response.json()) as ControlResponse
}

async function requestStatus(sessionId?: string): Promise<ControlResponse> {
  const query = sessionId ? `?sessionId=${encodeURIComponent(sessionId)}` : ''
  const response = await fetch(`${CONTROL_ENDPOINT}${query}`, { method: 'GET' })
  return (await response.json()) as ControlResponse
}

/** 会话头部按钮：只切换当前会话的 E2EE 远控。 */
export function SessionRemoteAction(props: SessionHeaderProps): React.ReactElement {
  const sessionId = typeof props.sessionId === 'string' ? props.sessionId : ''
  const [shared, setShared] = React.useState(false)
  const [safetyNumber, setSafetyNumber] = React.useState<string | undefined>(undefined)
  const [busy, setBusy] = React.useState(false)

  React.useEffect(() => {
    if (!sessionId) return
    let alive = true
    void requestStatus(sessionId)
      .then((response) => {
        if (!alive) return
        setShared(Boolean(response.data?.session?.shared))
        setSafetyNumber(response.data?.session?.safetyNumber)
      })
      .catch(() => undefined)
    return () => {
      alive = false
    }
  }, [sessionId])

  const onClick = React.useCallback(() => {
    if (!sessionId || busy) return
    setBusy(true)
    void requestControl({ action: 'session.toggle', sessionId, enabled: !shared })
      .then((response) => {
        if (response.ok === false) return
        setShared(Boolean(response.data?.session?.shared))
        setSafetyNumber(response.data?.session?.safetyNumber)
      })
      .catch(() => undefined)
      .finally(() => setBusy(false))
  }, [busy, sessionId, shared])

  return React.createElement(
    'button',
    {
      type: 'button',
      onClick,
      disabled: busy || !sessionId,
      'aria-pressed': shared,
      'data-gooftoken-remote': 'session',
      title: safetyNumber ? `GoofToken 会话远控（安全码 ${safetyNumber}）` : 'GoofToken 会话远控',
      style: { ...BUTTON_STYLE, opacity: busy || !sessionId ? 0.5 : 1 },
    },
    shared ? '远控中' : '远控',
  )
}

/** 侧栏底部按钮：切换整机 WebUI 远控。 */
export function WebUiRemoteAction(props: SidebarFooterProps): React.ReactElement {
  const wide = props.wide !== false
  const [active, setActive] = React.useState(false)
  const [busy, setBusy] = React.useState(false)

  React.useEffect(() => {
    let alive = true
    void requestStatus()
      .then((response) => {
        if (alive) setActive(Boolean(response.data?.webui?.active))
      })
      .catch(() => undefined)
    return () => {
      alive = false
    }
  }, [])

  const onClick = React.useCallback(() => {
    if (busy) return
    setBusy(true)
    void requestControl({ action: 'webui.toggle', enabled: !active })
      .then((response) => {
        if (response.ok === false) return
        setActive(Boolean(response.data?.webui?.active))
      })
      .catch(() => undefined)
      .finally(() => setBusy(false))
  }, [active, busy])

  const label = active ? (wide ? '关闭 WebUI 远控' : 'WebUI 开') : wide ? 'WebUI 远控' : 'WebUI'
  return React.createElement(
    'button',
    {
      type: 'button',
      onClick,
      disabled: busy,
      'aria-pressed': active,
      'data-gooftoken-remote': 'webui',
      title: active ? '关闭整机 WebUI 远控' : '开启整机 WebUI 远控',
      style: { ...BUTTON_STYLE, opacity: busy ? 0.5 : 1 },
    },
    label,
  )
}

function resolveSlots(ctx: Context): SlotsLike | undefined {
  const direct = (ctx as unknown as { slots?: Partial<SlotsLike> }).slots
  if (direct && typeof direct.inject === 'function' && typeof direct.register === 'function') {
    return direct as SlotsLike
  }
  try {
    const viaGet = (ctx as unknown as { get?: (name: string) => unknown }).get?.('slots')
    if (viaGet && typeof (viaGet as SlotsLike).inject === 'function' && typeof (viaGet as SlotsLike).register === 'function') {
      return viaGet as SlotsLike
    }
  } catch {
    // slots 服务不可用：静默跳过。
  }
  return undefined
}

/** 只做两个加法 list 插槽注册；插槽未声明时由 inject 等待/清理。 */
export function apply(ctx: Context): void {
  const slots = resolveSlots(ctx)
  if (!slots) return
  try {
    slots.inject(SESSION_SLOT, () =>
      slots.register(
        {
          name: SESSION_SLOT,
          id: 'gooftoken-remote-session',
          order: 90,
          label: '远控',
        },
        SessionRemoteAction as unknown,
      ),
    )
  } catch {
    // 宿主未声明该插槽时不影响其它功能。
  }
  try {
    slots.inject(SIDEBAR_SLOT, () =>
      slots.register(
        {
          name: SIDEBAR_SLOT,
          id: 'gooftoken-remote-webui',
          order: 90,
          label: 'WebUI 远控',
        },
        WebUiRemoteAction as unknown,
      ),
    )
  } catch {
    // 宿主未声明该插槽时不影响其它功能。
  }
}

export default { name, inject, apply }
