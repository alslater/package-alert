"""pnpm 12+ (native, clap) argv-parsing data, GENERATED — do not edit by hand.

Generated from pnpm 12.14.0 by tests/fixtures/argv_oracles/generate_pnpm_native.py;
see packagealert/parsers/pnpm_argv.py.
"""

PNPM_NATIVE_VERSION = '12.14.0'
# Every command name (aliases included) -> its full name.
PNPM_NATIVE_COMMANDS: dict[str, str] = {'access': 'access', 'add': 'add', 'adduser': 'login', 'approve': 'approve', 'approve-builds': 'approve-builds', 'audit': 'audit', 'bin': 'bin', 'bugs': 'bugs', 'c': 'config', 'cache': 'cache', 'cat-file': 'cat-file', 'cat-index': 'cat-index', 'change': 'change', 'ci': 'ci', 'clean': 'clean', 'clean-install': 'ci', 'completion': 'completion', 'config': 'config', 'create': 'create', 'dedupe': 'dedupe', 'deploy': 'deploy', 'deprecate': 'deprecate', 'dislink': 'unlink', 'dist-tag': 'dist-tag', 'dist-tags': 'dist-tag', 'dlx': 'dlx', 'docs': 'docs', 'doctor': 'doctor', 'edit': 'edit', 'env': 'env', 'exec': 'exec', 'fetch': 'fetch', 'find': 'search', 'find-hash': 'find-hash', 'get': 'get', 'help': 'help', 'home': 'docs', 'i': 'install', 'ic': 'ci', 'ignored-builds': 'ignored-builds', 'import': 'import', 'info': 'view', 'init': 'init', 'install': 'install', 'install-clean': 'ci', 'install-test': 'install-test', 'issues': 'bugs', 'it': 'install-test', 'la': 'll', 'lane': 'lane', 'licences': 'licenses', 'licenses': 'licenses', 'link': 'link', 'list': 'list', 'll': 'll', 'ln': 'link', 'login': 'login', 'logout': 'logout', 'ls': 'list', 'm': 'recursive', 'multi': 'recursive', 'outdated': 'outdated', 'owner': 'owner', 'owners': 'owner', 'pack': 'pack', 'pack-app': 'pack-app', 'patch': 'patch', 'patch-commit': 'patch-commit', 'patch-remove': 'patch-remove', 'peers': 'peers', 'permissions': 'permissions', 'ping': 'ping', 'pipeline': 'pipeline', 'pkg': 'pkg', 'prefix': 'prefix', 'profile': 'profile', 'prune': 'prune', 'publish': 'publish', 'purge': 'purge', 'rb': 'rb', 'rebuild': 'rebuild', 'recursive': 'recursive', 'remove': 'remove', 'repo': 'repo', 'restart': 'restart', 'rm': 'remove', 'root': 'root', 'rt': 'runtime', 'run': 'run', 'run-script': 'run', 'runtime': 'runtime', 's': 'search', 'sbom': 'sbom', 'se': 'search', 'search': 'search', 'self-update': 'self-update', 'set': 'set', 'set-script': 'set-script', 'setup': 'setup', 'shim': 'shim', 'show': 'view', 'ss': 'set-script', 'stage': 'stage', 'star': 'star', 'stars': 'stars', 'start': 'start', 'stop': 'stop', 'store': 'store', 't': 'test', 'tasks': 'tasks', 'team': 'team', 'test': 'test', 'token': 'token', 'tst': 'test', 'un': 'remove', 'undeprecate': 'undeprecate', 'uni': 'remove', 'uninstall': 'remove', 'unlink': 'unlink', 'unpublish': 'unpublish', 'unstar': 'unstar', 'up': 'update', 'update': 'update', 'upgrade': 'update', 'v': 'view', 'version': 'version', 'view': 'view', 'whoami': 'whoami', 'why': 'why', 'with': 'with', 'xmas': 'xmas'}
# Options per installing command ('' = global, accepted anywhere): 'value' takes one
# value, 'multi' every value that follows, 'optional' one only when attached
# (`--color=auto`), 'flag' none.
PNPM_NATIVE_OPTIONS: dict[str, dict[str, str]] = {
    '': {'--aggregate-output': 'flag', '--bail': 'flag', '--changed-files-ignore-pattern': 'value', '--color': 'optional', '--dir': 'value', '--fail-if-no-match': 'flag', '--filter': 'value', '--filter-prod': 'value', '--help': 'flag', '--http-proxy': 'value', '--https-proxy': 'value', '--ignore-workspace': 'flag', '--include-workspace-root': 'flag', '--loglevel': 'value', '--no-color': 'flag', '--no-fail-if-no-match': 'flag', '--no-include-workspace-root': 'flag', '--no-progress': 'flag', '--no-proxy': 'value', '--no-sort': 'flag', '--npmrc-auth-file': 'value', '--parallel': 'flag', '--recursive': 'flag', '--registry': 'value', '--reporter': 'value', '--reverse': 'flag', '--sort': 'flag', '--state-dir': 'value', '--store-dir': 'value', '--stream': 'flag', '--test-pattern': 'value', '--use-stderr': 'flag', '--version': 'flag', '--workspace-concurrency': 'value', '--workspace-packages': 'value', '--workspace-root': 'flag', '--yes': 'flag'},
    'add': {'--allow-build': 'value', '--auto-dedupe': 'flag', '--config': 'flag', '--cpu': 'multi', '--dev': 'flag', '--force': 'flag', '--global': 'flag', '--ignore-pnpmfile': 'flag', '--ignore-scripts': 'flag', '--ignore-workspace-root-check': 'flag', '--libc': 'multi', '--lockfile-dir': 'value', '--lockfile-only': 'flag', '--no-auto-dedupe': 'flag', '--no-ignore-scripts': 'flag', '--no-optional': 'flag', '--no-save-peer': 'flag', '--no-save-types': 'flag', '--optional': 'flag', '--os': 'multi', '--prod': 'flag', '--save-build': 'flag', '--save-catalog': 'flag', '--save-catalog-name': 'value', '--save-dev': 'flag', '--save-exact': 'flag', '--save-optional': 'flag', '--save-peer': 'flag', '--save-prefix': 'value', '--save-prod': 'flag', '--save-types': 'flag', '--tilde': 'flag', '--workspace': 'flag'},
    'ci': {'--allow-build': 'value', '--auto-dedupe': 'flag', '--cpu': 'multi', '--dev': 'flag', '--dry-run': 'flag', '--fetch-min-speed-ki-bps': 'value', '--fetch-timeout': 'value', '--fetch-warn-timeout-ms': 'value', '--fix-lockfile': 'flag', '--force': 'flag', '--frozen-lockfile': 'flag', '--frozen-store': 'flag', '--ignore-manifest-check': 'flag', '--ignore-pnpmfile': 'flag', '--ignore-scripts': 'flag', '--libc': 'multi', '--lockfile': 'flag', '--lockfile-dir': 'value', '--lockfile-only': 'flag', '--merge-git-branch-lockfiles': 'flag', '--merge-git-branch-lockfiles-branch-pattern': 'value', '--network-concurrency': 'value', '--no-auto-dedupe': 'flag', '--no-frozen-lockfile': 'flag', '--no-frozen-store': 'flag', '--no-ignore-scripts': 'flag', '--no-offline': 'flag', '--no-optional': 'flag', '--no-prefer-frozen-lockfile': 'flag', '--no-prefer-offline': 'flag', '--no-runtime': 'flag', '--no-trust-lockfile': 'flag', '--node-linker': 'value', '--offline': 'flag', '--optional': 'flag', '--os': 'multi', '--pnpr-server': 'value', '--prefer-frozen-lockfile': 'flag', '--prefer-offline': 'flag', '--prod': 'flag', '--trust-lockfile': 'flag', '--update-checksums': 'flag', '--user-agent': 'value'},
    'dedupe': {'--check': 'flag', '--ignore-pnpmfile': 'flag', '--ignore-scripts': 'flag', '--lockfile-only': 'flag', '--no-ignore-scripts': 'flag', '--no-offline': 'flag', '--no-prefer-offline': 'flag', '--offline': 'flag', '--prefer-offline': 'flag'},
    'deploy': {'--allow-build': 'value', '--auto-dedupe': 'flag', '--cpu': 'multi', '--dev': 'flag', '--dry-run': 'flag', '--fetch-min-speed-ki-bps': 'value', '--fetch-timeout': 'value', '--fetch-warn-timeout-ms': 'value', '--fix-lockfile': 'flag', '--force': 'flag', '--frozen-lockfile': 'flag', '--frozen-store': 'flag', '--ignore-manifest-check': 'flag', '--ignore-pnpmfile': 'flag', '--ignore-scripts': 'flag', '--legacy': 'flag', '--libc': 'multi', '--lockfile-dir': 'value', '--lockfile-only': 'flag', '--merge-git-branch-lockfiles': 'flag', '--merge-git-branch-lockfiles-branch-pattern': 'value', '--network-concurrency': 'value', '--no-auto-dedupe': 'flag', '--no-frozen-lockfile': 'flag', '--no-frozen-store': 'flag', '--no-ignore-scripts': 'flag', '--no-offline': 'flag', '--no-optional': 'flag', '--no-prefer-frozen-lockfile': 'flag', '--no-prefer-offline': 'flag', '--no-runtime': 'flag', '--no-trust-lockfile': 'flag', '--node-linker': 'value', '--offline': 'flag', '--optional': 'flag', '--os': 'multi', '--pnpr-server': 'value', '--prefer-frozen-lockfile': 'flag', '--prefer-offline': 'flag', '--prod': 'flag', '--trust-lockfile': 'flag', '--update-checksums': 'flag', '--user-agent': 'value'},
    'fetch': {'--dev': 'flag', '--ignore-pnpmfile': 'flag', '--prod': 'flag'},
    'import': {'--pnpr-server': 'value'},
    'install': {'--allow-build': 'value', '--auto-dedupe': 'flag', '--cpu': 'multi', '--dev': 'flag', '--dry-run': 'flag', '--fetch-min-speed-ki-bps': 'value', '--fetch-timeout': 'value', '--fetch-warn-timeout-ms': 'value', '--fix-lockfile': 'flag', '--force': 'flag', '--frozen-lockfile': 'flag', '--frozen-store': 'flag', '--ignore-manifest-check': 'flag', '--ignore-pnpmfile': 'flag', '--ignore-scripts': 'flag', '--libc': 'multi', '--lockfile-dir': 'value', '--lockfile-only': 'flag', '--merge-git-branch-lockfiles': 'flag', '--merge-git-branch-lockfiles-branch-pattern': 'value', '--network-concurrency': 'value', '--no-auto-dedupe': 'flag', '--no-frozen-lockfile': 'flag', '--no-frozen-store': 'flag', '--no-ignore-scripts': 'flag', '--no-offline': 'flag', '--no-optional': 'flag', '--no-prefer-frozen-lockfile': 'flag', '--no-prefer-offline': 'flag', '--no-runtime': 'flag', '--no-trust-lockfile': 'flag', '--node-linker': 'value', '--offline': 'flag', '--optional': 'flag', '--os': 'multi', '--pnpr-server': 'value', '--prefer-frozen-lockfile': 'flag', '--prefer-offline': 'flag', '--prod': 'flag', '--trust-lockfile': 'flag', '--update-checksums': 'flag', '--user-agent': 'value'},
    'install-test': {'--allow-build': 'value', '--auto-dedupe': 'flag', '--cpu': 'multi', '--dev': 'flag', '--dry-run': 'flag', '--fetch-min-speed-ki-bps': 'value', '--fetch-timeout': 'value', '--fetch-warn-timeout-ms': 'value', '--fix-lockfile': 'flag', '--force': 'flag', '--frozen-lockfile': 'flag', '--frozen-store': 'flag', '--ignore-manifest-check': 'flag', '--ignore-pnpmfile': 'flag', '--ignore-scripts': 'flag', '--libc': 'multi', '--lockfile-dir': 'value', '--lockfile-only': 'flag', '--merge-git-branch-lockfiles': 'flag', '--merge-git-branch-lockfiles-branch-pattern': 'value', '--network-concurrency': 'value', '--no-auto-dedupe': 'flag', '--no-frozen-lockfile': 'flag', '--no-frozen-store': 'flag', '--no-ignore-scripts': 'flag', '--no-offline': 'flag', '--no-optional': 'flag', '--no-prefer-frozen-lockfile': 'flag', '--no-prefer-offline': 'flag', '--no-runtime': 'flag', '--no-trust-lockfile': 'flag', '--node-linker': 'value', '--offline': 'flag', '--optional': 'flag', '--os': 'multi', '--pnpr-server': 'value', '--prefer-frozen-lockfile': 'flag', '--prefer-offline': 'flag', '--prod': 'flag', '--trust-lockfile': 'flag', '--update-checksums': 'flag', '--user-agent': 'value'},
    'pipeline': {'--allow-build': 'value', '--auto-dedupe': 'flag', '--base': 'value', '--branch': 'value', '--cpu': 'multi', '--dev': 'flag', '--dry-run': 'flag', '--fetch-min-speed-ki-bps': 'value', '--fetch-timeout': 'value', '--fetch-warn-timeout-ms': 'value', '--fix-lockfile': 'flag', '--force': 'flag', '--frozen-lockfile': 'flag', '--frozen-store': 'flag', '--full': 'flag', '--ignore-manifest-check': 'flag', '--ignore-pnpmfile': 'flag', '--ignore-scripts': 'flag', '--interval': 'value', '--json': 'flag', '--libc': 'multi', '--lockfile-dir': 'value', '--lockfile-only': 'flag', '--merge-git-branch-lockfiles': 'flag', '--merge-git-branch-lockfiles-branch-pattern': 'value', '--network-concurrency': 'value', '--no-auto-dedupe': 'flag', '--no-cache': 'flag', '--no-frozen-lockfile': 'flag', '--no-frozen-store': 'flag', '--no-ignore-scripts': 'flag', '--no-offline': 'flag', '--no-optional': 'flag', '--no-prefer-frozen-lockfile': 'flag', '--no-prefer-offline': 'flag', '--no-runtime': 'flag', '--no-trust-lockfile': 'flag', '--node-linker': 'value', '--offline': 'flag', '--once': 'flag', '--optional': 'flag', '--os': 'multi', '--pnpr-server': 'value', '--prefer-frozen-lockfile': 'flag', '--prefer-offline': 'flag', '--prod': 'flag', '--repo': 'value', '--report': 'flag', '--report-to': 'value', '--trust-lockfile': 'flag', '--update-checksums': 'flag', '--user-agent': 'value', '--watch': 'flag'},
    'recursive': {},
    'remove': {'--global': 'flag', '--lockfile-dir': 'value', '--lockfile-only': 'flag', '--no-trust-lockfile': 'flag', '--save-dev': 'flag', '--save-optional': 'flag', '--save-prod': 'flag', '--trust-lockfile': 'flag'},
    'self-update': {},
    'unlink': {'--ignore-pnpmfile': 'flag'},
    'update': {'--changeset': 'flag', '--cpu': 'multi', '--depth': 'value', '--dev': 'flag', '--global': 'flag', '--ignore-pnpmfile': 'flag', '--ignore-scripts': 'flag', '--include-github-actions': 'flag', '--interactive': 'flag', '--latest': 'flag', '--libc': 'multi', '--lockfile-dir': 'value', '--lockfile-only': 'flag', '--no-changeset': 'flag', '--no-ignore-scripts': 'flag', '--no-optional': 'flag', '--no-save': 'flag', '--optional': 'flag', '--os': 'multi', '--patches': 'flag', '--peer': 'flag', '--pnpr-server': 'value', '--prod': 'flag', '--save-exact': 'flag', '--workspace': 'flag'},
}
# Short forms and long aliases per command ('' = before the command).
PNPM_NATIVE_SHORTS: dict[str, dict[str, str]] = {
    '': {'-C': '--dir', '-F': '--filter', '-h': '--help', '-r': '--recursive', '-v': '--version', '-w': '--workspace-root', '-y': '--yes'},
    'add': {'-C': '--dir', '-D': '--save-dev', '-E': '--save-exact', '-F': '--filter', '-O': '--save-optional', '-P': '--save-prod', '-g': '--global', '-h': '--help', '-r': '--recursive', '-w': '--workspace-root', '-y': '--yes'},
    'ci': {'-C': '--dir', '-D': '--dev', '-F': '--filter', '-P': '--prod', '-h': '--help', '-l': '--lockfile', '-r': '--recursive', '-w': '--workspace-root', '-y': '--yes'},
    'dedupe': {'-C': '--dir', '-F': '--filter', '-h': '--help', '-r': '--recursive', '-w': '--workspace-root', '-y': '--yes'},
    'deploy': {'-C': '--dir', '-D': '--dev', '-F': '--filter', '-P': '--prod', '-h': '--help', '-r': '--recursive', '-w': '--workspace-root', '-y': '--yes'},
    'fetch': {'-C': '--dir', '-D': '--dev', '-F': '--filter', '-P': '--prod', '-h': '--help', '-r': '--recursive', '-w': '--workspace-root', '-y': '--yes'},
    'import': {'-C': '--dir', '-F': '--filter', '-h': '--help', '-r': '--recursive', '-w': '--workspace-root', '-y': '--yes'},
    'install': {'-C': '--dir', '-D': '--dev', '-F': '--filter', '-P': '--prod', '-h': '--help', '-r': '--recursive', '-w': '--workspace-root', '-y': '--yes'},
    'install-test': {'-C': '--dir', '-D': '--dev', '-F': '--filter', '-P': '--prod', '-h': '--help', '-r': '--recursive', '-w': '--workspace-root', '-y': '--yes'},
    'pipeline': {'-C': '--dir', '-D': '--dev', '-F': '--filter', '-P': '--prod', '-h': '--help', '-r': '--recursive', '-w': '--workspace-root', '-y': '--yes'},
    'recursive': {'-C': '--dir', '-F': '--filter', '-h': '--help', '-r': '--recursive', '-w': '--workspace-root', '-y': '--yes'},
    'remove': {'-C': '--dir', '-D': '--save-dev', '-F': '--filter', '-O': '--save-optional', '-P': '--save-prod', '-g': '--global', '-h': '--help', '-r': '--recursive', '-w': '--workspace-root', '-y': '--yes'},
    'self-update': {'-C': '--dir', '-F': '--filter', '-h': '--help', '-r': '--recursive', '-w': '--workspace-root', '-y': '--yes'},
    'unlink': {'-C': '--dir', '-F': '--filter', '-h': '--help', '-r': '--recursive', '-w': '--workspace-root', '-y': '--yes'},
    'update': {'-C': '--dir', '-D': '--dev', '-E': '--save-exact', '-F': '--filter', '-L': '--latest', '-P': '--prod', '-g': '--global', '-h': '--help', '-i': '--interactive', '-r': '--recursive', '-w': '--workspace-root', '-y': '--yes'},
}
PNPM_NATIVE_ALIASES: dict[str, dict[str, str]] = {
    '': {'--prefix': '--dir', '--store': '--store-dir', '--userconfig': '--npmrc-auth-file'},
    'add': {'--prefix': '--dir', '--production': '--prod', '--userconfig': '--npmrc-auth-file'},
    'ci': {'--prefix': '--dir', '--production': '--prod', '--userconfig': '--npmrc-auth-file'},
    'dedupe': {'--prefix': '--dir', '--userconfig': '--npmrc-auth-file'},
    'deploy': {'--prefix': '--dir', '--production': '--prod', '--userconfig': '--npmrc-auth-file'},
    'fetch': {'--prefix': '--dir', '--production': '--prod', '--userconfig': '--npmrc-auth-file'},
    'import': {'--prefix': '--dir', '--userconfig': '--npmrc-auth-file'},
    'install': {'--prefix': '--dir', '--production': '--prod', '--userconfig': '--npmrc-auth-file'},
    'install-test': {'--prefix': '--dir', '--production': '--prod', '--userconfig': '--npmrc-auth-file'},
    'pipeline': {'--prefix': '--dir', '--production': '--prod', '--userconfig': '--npmrc-auth-file'},
    'recursive': {'--prefix': '--dir', '--userconfig': '--npmrc-auth-file'},
    'remove': {'--prefix': '--dir', '--userconfig': '--npmrc-auth-file'},
    'self-update': {'--prefix': '--dir', '--userconfig': '--npmrc-auth-file'},
    'unlink': {'--prefix': '--dir', '--userconfig': '--npmrc-auth-file'},
    'update': {'--prefix': '--dir', '--production': '--prod', '--userconfig': '--npmrc-auth-file'},
}
# Settings pnpm takes out of argv before clap, unless the command declares the
# name itself: [kind, values, dotted values]. 'bool' (also `--no-<name>`,
# `--<name>=<bool>`, and a following true/false/1/0; values: keywords `--<name>=`
# also takes), 'text' (a following token not starting with `-`), 'int'/'uint',
# or 'enum' (one of values). Dotted values: what `--config.<name>=` takes besides.
# An 'optional' option's accepted attached values (empty: any).
PNPM_NATIVE_OPTIONAL_VALUES: dict[str, list[str]] = {'--color': ['always', 'auto', 'false', 'never', 'true']}
# Renamed options: an alias pnpm drops when its canonical option is also given.
PNPM_NATIVE_RENAMED: dict[str, str] = {'--prefix': '--dir', '--store': '--store-dir'}
PNPM_NATIVE_SETTINGS: dict[str, list] = {
    'allow-unused-patches': ['bool', [], []],
    'child-concurrency': ['int', [], []],
    'dangerously-allow-all-builds': ['bool', [], []],
    'engine-strict': ['bool', [], []],
    'force-legacy-deploy': ['bool', [], []],
    'frozen-store': ['bool', [], []],
    'global-dir': ['text', [], []],
    'hoist': ['bool', [], []],
    'hoist-pattern': ['text', [], []],
    'ignore-pnpmfile': ['bool', [], []],
    'ignore-scripts': ['bool', [], []],
    'link-workspace-packages': ['bool', ['deep', 'false', 'true'], ['deep', 'false', 'true']],
    'lockfile': ['bool', [], []],
    'lockfile-include-tarball-url': ['bool', [], []],
    'merge-git-branch-lockfiles': ['bool', [], []],
    'modules-dir': ['text', [], []],
    'node-experimental-package-map': ['bool', [], []],
    'offline': ['bool', [], []],
    'optimistic-repeat-install': ['bool', [], []],
    'package-import-method': ['enum', ['auto', 'hardlink', 'clone', 'copy', 'clone-or-copy'], ['auto', 'hardlink', 'clone', 'copy', 'clone-or-copy']],
    'pm-on-fail': ['enum', ['download', 'error', 'warn', 'ignore'], ['download', 'error', 'warn', 'ignore']],
    'prefer-frozen-lockfile': ['bool', [], []],
    'prefer-offline': ['bool', [], []],
    'public-hoist-pattern': ['text', [], []],
    'runtime-on-fail': ['enum', ['download', 'error', 'warn', 'ignore'], ['download', 'error', 'warn', 'ignore']],
    'save-workspace-protocol': ['bool', ['false', 'true'], ['false', 'rolling', 'true']],
    'shamefully-hoist': ['bool', [], []],
    'shared-workspace-lockfile': ['bool', [], []],
    'side-effects-cache': ['bool', [], []],
    'side-effects-cache-readonly': ['bool', [], []],
    'strict-peer-dependencies': ['bool', [], []],
    'trust-lockfile': ['bool', [], []],
    'trust-policy': ['enum', ['off', 'no-downgrade'], ['off', 'no-downgrade']],
    'trust-policy-exclude': ['text', [], []],
    'trust-policy-ignore-after': ['uint', [], []],
    'unsafe-perm': ['bool', [], []],
    'verify-store-integrity': ['bool', [], []],
    'virtual-store-dir': ['text', [], []],
    'virtual-store-only': ['bool', [], []],
}
