/**
 * 双产物构建：`lib/index.js`（ESM 宿主）与 `lib/client.cjs`（CJS 客户端工厂）。
 * client 必须用 `.cjs`：包声明 `type: module`，`.js` 会被 Node 按 ESM 解析而 `exports` 未定义。
 * 类型声明由 `tsc -p tsconfig.build.json` 生成。
 */
import { execFile } from 'node:child_process'
import { promises as fs } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import { defineConfig } from 'tsdown'

const execFileAsync = promisify(execFile)
const packageDir = dirname(fileURLToPath(import.meta.url))
const requireFromHere = createRequire(import.meta.url)
const tscBin = requireFromHere.resolve('typescript/bin/tsc')
const libDir = join(packageDir, 'lib')

let cleanPromise: Promise<void> | null = null
let typesPromise: Promise<void> | null = null

function cleanLib(): Promise<void> {
  cleanPromise ??= fs.rm(libDir, { recursive: true, force: true })
  return cleanPromise
}

async function emitTypes(): Promise<void> {
  await execFileAsync(process.execPath, [tscBin, '-p', 'tsconfig.build.json', '--pretty', 'false'], {
    cwd: packageDir,
  })

  // tsc 按 src 相对路径输出 lib/client/index.d.ts；包导出要求 lib/client.d.ts。
  try {
    const declarations = await fs.readFile(join(libDir, 'client/index.d.ts'), 'utf8')
    const hasDefault = /(^|\n)\s*(export default\b|export\s*\{[^}]*\bdefault\b[^}]*\})/.test(declarations)
    const shim = ["export * from './client/index.js'", hasDefault ? "export { default } from './client/index.js'" : '']
      .filter(Boolean)
      .join('\n')
    await fs.writeFile(join(libDir, 'client.d.ts'), `${shim}\n`, 'utf8')
  } catch {
    // client 入口缺失时由 tsc 自身的报错兜底。
  }
}

function buildTypes(): Promise<void> {
  typesPromise ??= emitTypes()
  return typesPromise
}

export default defineConfig([
  {
    entry: { index: 'src/index.ts' },
    format: 'esm',
    platform: 'node',
    target: 'node22',
    outDir: 'lib',
    clean: false,
    dts: false,
    outExtensions: () => ({ js: '.js' }),
    hooks: { 'build:prepare': cleanLib },
    onSuccess: buildTypes,
  },
  {
    entry: { client: 'src/client/index.ts' },
    format: 'cjs',
    platform: 'node',
    target: 'node22',
    outDir: 'lib',
    clean: false,
    dts: false,
    // 宿主提供 React：必须外部引用，避免内嵌第二份 React 导致 Invalid hook call。
    deps: { neverBundle: ['react'] },
    outExtensions: () => ({ js: '.cjs' }),
    hooks: { 'build:prepare': cleanLib },
    onSuccess: buildTypes,
  },
])
