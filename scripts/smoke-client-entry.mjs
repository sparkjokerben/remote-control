#!/usr/bin/env node
/**
 * 发布产物冒烟：按包导出真实加载 client 入口（require + import），
 * 断言 apply/default 可调用且能注册两个插槽。需先 build。
 */
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const requireFromPackage = createRequire(join(packageDir, 'package.json'))
const specifier = '@gooftoken/remote-control/client'
const failures = []

function check(ok, message) {
  if (ok) {
    console.log(`ok - ${message}`)
  } else {
    failures.push(message)
    console.error(`not ok - ${message}`)
  }
}

function assertLoadable(mod, source) {
  check(typeof mod.apply === 'function', `${source}: apply 可调用`)
  check(typeof mod.default?.apply === 'function', `${source}: default.apply 可调用`)
  check(mod.name === 'remote-control-client', `${source}: name 正确`)
}

function fakeContext() {
  const registered = []
  return {
    registered,
    ctx: {
      slots: {
        inject(_name, callback) {
          callback()
        },
        register(options, component) {
          registered.push({ options, component })
        },
      },
    },
  }
}

function assertApplies(apply, source) {
  const { ctx, registered } = fakeContext()
  apply(ctx)
  check(registered.length === 2, `${source}: 注册两个插槽`)
  check(
    registered.every((entry) => typeof entry.component === 'function'),
    `${source}: 插槽组件为函数`,
  )
}

/** React 必须由宿主提供：产物只能外部引用，不得内嵌实现（否则 hooks dispatcher 分裂）。 */
function assertReactExternal() {
  let artifact
  try {
    artifact = readFileSync(join(packageDir, 'lib', 'client.cjs'), 'utf8')
  } catch (error) {
    failures.push(`读取 lib/client.cjs 失败: ${error.message}`)
    return
  }
  check(/require\(['"]react['"]\)/.test(artifact), 'client 产物保留对 react 的外部引用')
  const inlined = [
    'react.development',
    'react.production',
    'REACT_ELEMENT_TYPE',
    '__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED',
    'Minified React error',
  ].filter((marker) => artifact.includes(marker))
  check(
    inlined.length === 0,
    `client 产物未内嵌 React 实现${inlined.length > 0 ? `（命中: ${inlined.join(', ')}）` : ''}`,
  )
}

assertReactExternal()

let cjs
try {
  const resolved = requireFromPackage.resolve(specifier)
  check(resolved.endsWith('.cjs'), `require 解析到 .cjs (${resolved})`)
  cjs = requireFromPackage(specifier)
} catch (error) {
  failures.push(`require 加载失败: ${error.message}`)
}

let esm
try {
  const resolved = fileURLToPath(import.meta.resolve(specifier))
  check(resolved.endsWith('.cjs'), `import 解析到 .cjs (${resolved})`)
  esm = await import(specifier)
} catch (error) {
  failures.push(`import 加载失败: ${error.message}`)
}

if (cjs) {
  assertLoadable(cjs, 'require')
  assertApplies(cjs.apply, 'require apply')
  assertApplies(cjs.default.apply, 'require default.apply')
}
if (esm) {
  assertLoadable(esm, 'import')
  assertApplies(esm.apply, 'import apply')
  assertApplies(esm.default.apply, 'import default.apply')
}

if (failures.length > 0) {
  console.error(`\n客户端入口冒烟失败：${failures.length} 项`)
  process.exit(1)
}
console.log('\n客户端入口冒烟通过')
