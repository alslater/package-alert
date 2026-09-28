// Regenerate packagealert/parsers/_npm_tables.py from the npm on PATH: every
// config key's nopt type list, the shorthand map, and cmd-list's commands and
// aliases — the data npm's own argv parsing runs on. Re-run it whenever npm is
// upgraded, then regenerate npm.json with generate_npm.js and run
// tests/unit/test_argv_oracles.py.
//
//     node tests/fixtures/argv_oracles/generate_npm_tables.js
const path = require('path')
const fs = require('fs')
const { execSync } = require('child_process')

const npmRoot = path.dirname(path.dirname(fs.realpathSync(execSync('which npm').toString().trim())))
const R = (p) => require(path.join(npmRoot, p))
const nopt = R('node_modules/nopt')
const { definitions, shorthands } = R('node_modules/@npmcli/config/lib/definitions')
const { commands, aliases } = R('lib/utils/cmd-list.js')

const typeName = (t) => {
  if (t === null) return 'null'
  if (typeof t === 'string') return '=' + t
  for (const [n, d] of Object.entries(nopt.typeDefs)) if (d.type === t) return n
  return 'other'
}
const py = (v) => JSON.stringify(v)
const lines = []
lines.push('"""npm argv-parsing data, GENERATED — do not edit by hand.')
lines.push('')
lines.push(`Generated from npm ${R('package.json').version} (nopt ${R('node_modules/nopt/package.json').version}) by`)
lines.push('tests/fixtures/argv_oracles/generate_npm_tables.js; see packagealert/parsers/npm_argv.py.')
lines.push('"""')
lines.push('')
lines.push('# Each config key\'s nopt type: ("single", name) or ("list", (name, ...)). A name is')
lines.push('# a nopt type ("Boolean", "String", "Number", "Array", ...), "null", or "=literal".')
lines.push('NPM_TYPES: dict[str, tuple[str, tuple[str, ...]]] = {')
for (const [k, d] of Object.entries(definitions).sort()) {
  // local-address's allowed values are THIS machine's IP addresses, computed at
  // runtime; they do not affect parsing (a literal-only key consumes its value
  // whatever it is), and must not be committed, so record it as a String key.
  const t = k === 'local-address' ? [null, String] : d.type
  const v = Array.isArray(t) ? `("list", (${t.map((x) => py(typeName(x))).join(', ')}${t.length === 1 ? ',' : ''}))` : `("single", (${py(typeName(t))},))`
  lines.push(`    ${py(k)}: ${v},`)
}
lines.push('}')
lines.push('NPM_SHORTHANDS: dict[str, tuple[str, ...]] = {')
for (const [k, v] of Object.entries(shorthands).sort()) {
  const parts = Array.isArray(v) ? v : v.split(/\s+/)
  lines.push(`    ${py(k)}: (${parts.map(py).join(', ')}${parts.length === 1 ? ',' : ''}),`)
}
lines.push('}')
lines.push(`NPM_COMMANDS: tuple[str, ...] = (${commands.map(py).join(', ')})`)
lines.push('NPM_COMMAND_ALIASES: dict[str, str] = {')
for (const [k, v] of Object.entries(aliases).sort()) lines.push(`    ${py(k)}: ${py(v)},`)
lines.push('}')
const out = path.resolve(__dirname, '../../../packagealert/parsers/_npm_tables.py')
fs.writeFileSync(out, lines.join('\n') + '\n')
console.log(`wrote ${out}`)
