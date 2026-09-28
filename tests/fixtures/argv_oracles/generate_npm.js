// Regenerate npm.json: package-alert's npm parser is checked against npm's OWN
// argv parsing — nopt with npm's config definitions (exactly what
// @npmcli/config's loadCLI() calls) and cmd-list's deref() for the command —
// on a corpus generated from those same definitions. Nothing is executed.
//
//     node tests/fixtures/argv_oracles/generate_npm.js
//
// Uses the npm found on PATH. Only command lines whose command npm resolves
// are recorded.
const path = require('path')
const fs = require('fs')
const { execSync } = require('child_process')

const npmRoot = path.dirname(path.dirname(fs.realpathSync(execSync('which npm').toString().trim())))
const req = (p) => require(path.join(npmRoot, p))
const nopt = req('node_modules/nopt')
const { definitions, shorthands } = req('node_modules/@npmcli/config/lib/definitions')
const { deref, commands, aliases } = req('lib/utils/cmd-list.js')
const npmVersion = req('package.json').version

const types = Object.fromEntries(Object.entries(definitions).map(([k, d]) => [k, d.type]))
const INSTALLING = new Set(['install', 'ci', 'update', 'dedupe', 'uninstall', 'audit'])

function truth (argv) {
  nopt.invalidHandler = () => {}
  nopt.unknownHandler = () => {}
  nopt.abbrevHandler = () => {}
  const conf = nopt(types, shorthands, ['node', 'npm', ...argv], 2)
  const remain = conf.argv.remain
  const cmd = deref(remain[0])
  if (!cmd) return null
  return {
    cmd,
    args: remain.slice(1),
    global: conf.global === true || conf.location === 'global',
    // npm resolves --prefix against the cwd; record it relative to that so the
    // fixture holds no machine-specific path (package-alert keeps it relative).
    prefix: conf.prefix === undefined ? null : path.relative(process.cwd(), conf.prefix),
    dry_run: conf['dry-run'] === true || conf['package-lock-only'] === true,
  }
}

function valueFor (key) {
  const t = [].concat(types[key])
  const lit = t.find((x) => typeof x === 'string')
  if (lit) return lit
  if (t.includes(Number)) return '1'
  return 'VAL'
}
function isBooleanOnly (key) {
  const t = [].concat(types[key])
  return t.every((x) => x === Boolean || x === null)
}

// every spelling deref() maps to an installing command (abbreviations included)
const cmdSpellings = []
const words = commands.concat(Object.keys(aliases))
for (const w of words) {
  for (let n = 1; n <= w.length; n++) {
    const p = w.slice(0, n)
    if (INSTALLING.has(deref(p)) && !cmdSpellings.includes(p)) cmdSpellings.push(p)
  }
}

const corpus = []
for (const c of cmdSpellings) {
  corpus.push([c, 'evilpkg'])
  corpus.push([c])
}
corpus.push(['audit', 'fix'])
const keys = Object.keys(definitions)
for (const key of keys) {
  const flags = [`--${key}`]
  for (let n = 3; n < key.length; n++) {        // unique abbreviations
    const p = key.slice(0, n)
    if (keys.filter((k) => k.startsWith(p)).length === 1 && !(p in shorthands)) flags.push(`--${p}`)
  }
  for (const f of flags) {
    if (isBooleanOnly(key)) {
      corpus.push([f, 'install', 'evilpkg'], ['install', f, 'evilpkg'], ['install', 'evilpkg', f])
      corpus.push([`--no-${f.slice(2)}`, 'install', 'evilpkg'])
    } else {
      const v = valueFor(key)
      corpus.push([f, v, 'install', 'evilpkg'], ['install', f, v, 'evilpkg'], ['install', 'evilpkg', f, v])
      corpus.push([`${f}=${v}`, 'install', 'evilpkg'])
    }
  }
}
for (const s of Object.keys(shorthands)) {
  const flag = s.length === 1 ? `-${s}` : `--${s}`
  corpus.push([flag, 'install', 'evilpkg'], [flag, 'VAL', 'install', 'evilpkg'], ['install', flag, 'VAL', 'evilpkg'])
}
corpus.push(['install', '--', '--weird'], ['--location=global', 'install', 'x'], ['install', 'x', '--global', '--local'])

const cases = []
for (const argv of corpus) {
  const t = truth(argv)
  if (t && INSTALLING.has(t.cmd)) cases.push([argv, t])
}
const out = path.join(__dirname, 'npm.json')
fs.writeFileSync(out, JSON.stringify({ npm: npmVersion, cases }, null, 0) + '\n')
console.log(`npm ${npmVersion}: ${cases.length} cases recorded in ${out}`)
