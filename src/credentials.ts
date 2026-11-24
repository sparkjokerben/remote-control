/**
 * 凭据持久化（契约 §6.1）：优先使用宿主 `ctx.credentials` 的 record 槽；
 * 缺失时落盘 `$DSH_HOME/gooftoken-remote.json`（0600，原子写）。
 * 保存 OIDC Grant、E2EE 设备身份与 TOFU 公钥钉死。
 */
import { randomBytes } from 'node:crypto'
import { promises as fs } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

import type { Context } from '@deepseek-ai/cordis'

import type { Logger } from './config.js'
import type { DeviceKeyBundle, DevicePrivateKeys } from './crypto/index.js'

export type { DeviceKeyBundle, DevicePrivateKeys }

export interface Grant {
  issuer: string
  relay: string
  clientId: string
  nodeId: string
  accessToken: string
  refreshToken: string
  expiresAt: number
  domain: string
}

export interface DeviceIdentity {
  bundle: DeviceKeyBundle
  privateKeys: DevicePrivateKeys
}

export interface PersistedState {
  grant?: Grant
  identity?: DeviceIdentity
  pins: Record<string, string>
}

export interface CredentialStore {
  load(): Promise<PersistedState>
  saveGrant(grant: Grant): Promise<void>
  saveIdentity(identity: DeviceIdentity): Promise<void>
  setPin(peerId: string, hash: string): Promise<void>
  clearPin(peerId: string): Promise<void>
  clear(): Promise<void>
}

export type CredentialStoreErrorCode = 'REMOTE_CREDENTIALS_CORRUPT' | 'REMOTE_CREDENTIALS_IO'

export class CredentialStoreError extends Error {
  readonly code: CredentialStoreErrorCode

  constructor(code: CredentialStoreErrorCode, message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'CredentialStoreError'
    this.code = code
  }
}

const CREDENTIAL_SCOPE = 'remote-control'
const CREDENTIAL_ID = 'state'
const CREDENTIAL_KEY = `${CREDENTIAL_SCOPE}/${CREDENTIAL_ID}`
const FILE_NAME = 'gooftoken-remote.json'

type Dict = Record<string, unknown>

function isDict(value: unknown): value is Dict {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function clone<T>(value: T): T {
  return structuredClone(value)
}

function emptyState(): PersistedState {
  return { pins: {} }
}

function corrupt(message: string): CredentialStoreError {
  return new CredentialStoreError('REMOTE_CREDENTIALS_CORRUPT', message)
}

function readString(value: unknown, field: string): string {
  if (typeof value !== 'string') throw corrupt(`credential field ${field} must be a string`)
  return value
}

function parseGrant(value: unknown): Grant | undefined {
  if (value === undefined || value === null) return undefined
  if (!isDict(value)) throw corrupt('credential field grant must be an object')
  if (typeof value.expiresAt !== 'number' || !Number.isFinite(value.expiresAt)) {
    throw corrupt('credential field grant.expiresAt must be a finite number')
  }
  return {
    issuer: readString(value.issuer, 'grant.issuer'),
    relay: readString(value.relay, 'grant.relay'),
    clientId: readString(value.clientId, 'grant.clientId'),
    nodeId: readString(value.nodeId, 'grant.nodeId'),
    accessToken: readString(value.accessToken, 'grant.accessToken'),
    refreshToken: readString(value.refreshToken, 'grant.refreshToken'),
    expiresAt: value.expiresAt,
    domain: readString(value.domain, 'grant.domain'),
  }
}

function parseIdentity(value: unknown): DeviceIdentity | undefined {
  if (value === undefined || value === null) return undefined
  if (!isDict(value) || !isDict(value.bundle) || !isDict(value.privateKeys)) {
    throw corrupt('credential field identity must contain bundle and privateKeys objects')
  }
  const bundle = value.bundle
  const privateKeys = value.privateKeys
  return {
    bundle: {
      keyId: readString(bundle.keyId, 'identity.bundle.keyId'),
      ikSignPub: readString(bundle.ikSignPub, 'identity.bundle.ikSignPub'),
      ikDhPub: readString(bundle.ikDhPub, 'identity.bundle.ikDhPub'),
      spkPub: readString(bundle.spkPub, 'identity.bundle.spkPub'),
      spkSig: readString(bundle.spkSig, 'identity.bundle.spkSig'),
    },
    privateKeys: {
      ikSignPriv: readString(privateKeys.ikSignPriv, 'identity.privateKeys.ikSignPriv'),
      ikDhPriv: readString(privateKeys.ikDhPriv, 'identity.privateKeys.ikDhPriv'),
      spkPriv: readString(privateKeys.spkPriv, 'identity.privateKeys.spkPriv'),
    },
  }
}

function parseState(value: unknown): PersistedState {
  if (!isDict(value)) throw corrupt('credential document must be a JSON object')
  const pins: Record<string, string> = {}
  if (value.pins !== undefined) {
    if (!isDict(value.pins)) throw corrupt('credential field pins must be an object')
    for (const [peerId, hash] of Object.entries(value.pins)) {
      if (typeof hash !== 'string') throw corrupt(`credential pin for ${peerId} must be a string`)
      pins[peerId] = hash
    }
  }
  return {
    grant: parseGrant(value.grant),
    identity: parseIdentity(value.identity),
    pins,
  }
}

function parseRecord(record: unknown): PersistedState {
  if (record === undefined || record === null) return emptyState()
  if (!isDict(record) || record.kind !== 'grant') throw corrupt('credentials record must be a grant record')
  return parseState(record.payload)
}

interface CredentialProviderLike {
  readRecord(key: string): Promise<unknown>
  modifyRecord(key: string, mutate: (current: unknown) => Promise<unknown>): Promise<unknown>
  deleteRecord(key: string): Promise<void>
}

function asProvider(value: unknown): CredentialProviderLike | undefined {
  if (!isDict(value)) return undefined
  if (
    typeof value.readRecord === 'function' &&
    typeof value.modifyRecord === 'function' &&
    typeof value.deleteRecord === 'function'
  ) {
    return value as unknown as CredentialProviderLike
  }
  return undefined
}

function providerStore(provider: CredentialProviderLike, log: Logger): CredentialStore {
  async function load(): Promise<PersistedState> {
    return clone(parseRecord(await provider.readRecord(CREDENTIAL_KEY)))
  }

  async function mutate(change: (state: PersistedState) => void): Promise<void> {
    await provider.modifyRecord(CREDENTIAL_KEY, async (current) => {
      const state = parseRecord(current)
      change(state)
      return { kind: 'grant', payload: state }
    })
  }

  log.debug('credentials: using ctx.credentials record store')
  return {
    load,
    async saveGrant(grant) {
      await mutate((state) => {
        state.grant = clone(grant)
      })
    },
    async saveIdentity(identity) {
      await mutate((state) => {
        state.identity = clone(identity)
      })
    },
    async setPin(peerId, hash) {
      await mutate((state) => {
        state.pins[peerId] = hash
      })
    },
    async clearPin(peerId) {
      await mutate((state) => {
        delete state.pins[peerId]
      })
    },
    async clear() {
      await provider.deleteRecord(CREDENTIAL_KEY)
    },
  }
}

function fileStore(log: Logger): CredentialStore {
  const home = process.env.DSH_HOME?.trim() || join(homedir(), '.dsh')
  const path = join(home, FILE_NAME)
  let queue: Promise<unknown> = Promise.resolve()

  function enqueue<T>(task: () => Promise<T>): Promise<T> {
    const run = queue.then(task, task)
    queue = run.then(
      () => undefined,
      () => undefined,
    )
    return run
  }

  async function readFileState(): Promise<PersistedState> {
    let text: string
    try {
      text = await fs.readFile(path, 'utf8')
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return emptyState()
      throw new CredentialStoreError('REMOTE_CREDENTIALS_IO', `cannot read ${path}`, err)
    }
    try {
      return parseState(JSON.parse(text))
    } catch (err) {
      if (err instanceof CredentialStoreError) throw err
      throw new CredentialStoreError('REMOTE_CREDENTIALS_CORRUPT', `credential document is not valid JSON: ${path}`, err)
    }
  }

  async function persist(state: PersistedState): Promise<void> {
    const dir = dirname(path)
    const temp = join(dir, `.${FILE_NAME}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`)
    try {
      await fs.mkdir(dir, { recursive: true, mode: 0o700 })
      const handle = await fs.open(temp, 'wx', 0o600)
      try {
        await handle.writeFile(`${JSON.stringify(state)}\n`, 'utf8')
        await handle.sync()
      } finally {
        await handle.close()
      }
      await fs.chmod(temp, 0o600)
      await fs.rename(temp, path)
    } catch (err) {
      await fs.rm(temp, { force: true }).catch(() => undefined)
      throw new CredentialStoreError('REMOTE_CREDENTIALS_IO', `cannot write ${path}`, err)
    }
  }

  async function mutate(change: (state: PersistedState) => void): Promise<void> {
    await enqueue(async () => {
      const state = await readFileState()
      change(state)
      await persist(state)
    })
  }

  log.debug(`credentials: using ${path}`)
  return {
    async load() {
      return enqueue(async () => clone(await readFileState()))
    },
    async saveGrant(grant) {
      await mutate((state) => {
        state.grant = clone(grant)
      })
    },
    async saveIdentity(identity) {
      await mutate((state) => {
        state.identity = clone(identity)
      })
    },
    async setPin(peerId, hash) {
      await mutate((state) => {
        state.pins[peerId] = hash
      })
    },
    async clearPin(peerId) {
      await mutate((state) => {
        delete state.pins[peerId]
      })
    },
    async clear() {
      await enqueue(async () => {
        try {
          await fs.rm(path, { force: true })
        } catch (err) {
          throw new CredentialStoreError('REMOTE_CREDENTIALS_IO', `cannot remove ${path}`, err)
        }
      })
    },
  }
}

/** 优先宿主 credentials 服务；否则使用应用内 JSON 文件。 */
export function createCredentialStore(ctx: Context, log: Logger): CredentialStore {
  let provider: CredentialProviderLike | undefined
  try {
    provider = asProvider(ctx.get('credentials'))
  } catch {
    provider = undefined
  }
  if (provider) return providerStore(provider, log)
  return fileStore(log)
}
