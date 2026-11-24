#!/usr/bin/env node
/**
 * 生成固定文件名的离线安装包：release/remote-control.tgz。
 * 默认先执行构建；`--skip-build` 可复用现有 lib。
 */
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, renameSync, rmSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const releaseDir = join(packageDir, 'release')
const target = join(releaseDir, 'remote-control.tgz')

function run(command, args, options = {}) {
  execFileSync(command, args, { cwd: packageDir, stdio: 'inherit', ...options })
}

if (!process.argv.includes('--skip-build')) {
  run('npm', ['run', 'build'])
}

for (const file of ['lib/index.js', 'lib/client.cjs', 'lib/index.d.ts', 'lib/client.d.ts']) {
  if (!existsSync(join(packageDir, file))) {
    console.error(`缺少构建产物 ${file}，请先运行 pnpm --filter @gooftoken/remote-control run build`)
    process.exit(1)
  }
}

rmSync(releaseDir, { recursive: true, force: true })
mkdirSync(releaseDir, { recursive: true })

const output = execFileSync(
  'npm',
  ['pack', '--ignore-scripts', '--pack-destination', releaseDir, '--json'],
  {
    cwd: packageDir,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  },
)
// prepare 或 npm notice 可能混入 stdout，从首个 JSON 分隔符开始解析。
const jsonStart = output.search(/[[{]/)
if (jsonStart < 0) {
  console.error(`npm pack 未返回 JSON：${output}`)
  process.exit(1)
}
const parsed = JSON.parse(output.slice(jsonStart))
const packed = Array.isArray(parsed) ? parsed[0] : Object.values(parsed)[0]
if (!packed?.filename) {
  console.error('npm pack 未返回产物文件名')
  process.exit(1)
}

renameSync(join(releaseDir, packed.filename), target)
console.log(`已生成 ${target}`)
