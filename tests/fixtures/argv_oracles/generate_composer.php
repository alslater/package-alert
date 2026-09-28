<?php
// Regenerate composer.json: package-alert's composer parser is checked against
// composer's OWN parsing — Symfony Console's Application::find() for the
// command (aliases and abbreviations included) and ArgvInput::bind() against
// that command's merged definition — on a corpus generated from those same
// definitions. Nothing is executed.
//
//     php tests/fixtures/argv_oracles/generate_composer.php
//
// Uses the composer phar on PATH. Only accepted command lines are recorded.
$phar = realpath(trim(shell_exec('command -v composer')));
Phar::loadPhar($phar, 'composer.phar');
require 'phar://composer.phar/vendor/autoload.php';

use Composer\Console\Application;
use Symfony\Component\Console\Input\ArgvInput;
use Symfony\Component\Console\Input\InputDefinition;

$app = new Application();
$app->setAutoExit(false);
$INSTALLING = ['require', 'install', 'update', 'global'];

function command_for($app, $argv) {
    $input = new ArgvInput(array_merge(['composer'], $argv));
    $name = $input->getFirstArgument();
    if ($name === null) return [null, null];
    try { $cmd = $app->find($name); } catch (Throwable $e) { return [null, null]; }
    return [$cmd, $input];
}

function truth($app, $argv) {
    [$cmd, $input] = command_for($app, $argv);
    if ($cmd === null) return null;
    $cmd->mergeApplicationDefinition();
    try { $input->bind($cmd->getDefinition()); $input->validate(); } catch (Throwable $e) { return null; }
    $name = $cmd->getName();
    $t = ['cmd' => $name,
          'working_dir' => $input->hasOption('working-dir') ? $input->getOption('working-dir') : null,
          'dry_run' => $input->hasOption('dry-run') && $input->getOption('dry-run'),
          'packages' => [], 'nested' => null];
    if ($input->hasArgument('packages')) $t['packages'] = array_values((array) $input->getArgument('packages'));
    if ($name === 'global') {
        $t['nested'] = $input->getArgument('command-name');
        $t['packages'] = array_values((array) $input->getArgument('args'));
    }
    return $t;
}

function spellings($opt) {
    $out = ['--' . $opt->getName()];
    if ($opt->getShortcut()) foreach (explode('|', $opt->getShortcut()) as $s) $out[] = '-' . $s;
    return $out;
}

$corpus = [];
$names = array_keys($app->all());
foreach ($names as $n) {                       // command name abbreviations
    for ($k = 1; $k <= strlen($n); $k++) {
        $p = substr($n, 0, $k);
        [$c] = command_for($app, [$p]);
        if ($c && in_array($c->getName(), $INSTALLING, true)) { $corpus[] = [$p, 'vendor/evilpkg']; $corpus[] = [$p]; }
    }
}
foreach ($app->all() as $c) foreach ($c->getAliases() as $alias) { $corpus[] = [$alias, 'vendor/evilpkg']; }
$appDef = $app->getDefinition();
foreach ($appDef->getOptions() as $opt) {       // global options before the command
    foreach (spellings($opt) as $sp) {
        $v = $opt->acceptValue() ? ['VAL'] : [];
        $corpus[] = array_merge([$sp], $v, ['require', 'vendor/evilpkg']);
        if ($v) { $corpus[] = [$sp . (str_starts_with($sp, '--') ? '=' : '') . 'VAL', 'require', 'vendor/evilpkg']; }
    }
}
foreach (['require', 'install', 'update'] as $cname) {
    $c = $app->find($cname); $c->mergeApplicationDefinition();
    $tail = $cname === 'install' ? [] : ['vendor/evilpkg'];
    foreach ($c->getDefinition()->getOptions() as $opt) {
        foreach (spellings($opt) as $sp) {
            $v = $opt->acceptValue() ? ['VAL'] : [];
            $corpus[] = array_merge([$cname, $sp], $v, $tail);
            $corpus[] = array_merge([$cname], $tail, [$sp], $v);
            if ($v) $corpus[] = array_merge([$cname, $sp . (str_starts_with($sp, '--') ? '=' : '') . 'VAL'], $tail);
        }
    }
    $corpus[] = array_merge([$cname, '--'], $tail);
}
$corpus[] = ['global', 'require', 'vendor/evilpkg'];
$corpus[] = ['global', 'update', 'vendor/evilpkg'];
// an OPTIONAL value consumes a following package name
$corpus[] = ['update', '--bump-after-update', 'vendor/evilpkg'];
$corpus[] = ['-n', 'global', 'require', 'vendor/evilpkg'];

$cases = [];
foreach ($corpus as $argv) {
    $t = truth($app, $argv);
    if ($t !== null && in_array($t['cmd'], $INSTALLING, true)) $cases[] = [$argv, $t];
}
$out = __DIR__ . '/composer.json';
file_put_contents($out, json_encode(['composer' => Composer\Composer::getVersion(), 'cases' => $cases]) . "\n");
fwrite(STDERR, 'composer ' . Composer\Composer::getVersion() . ': ' . count($cases) . " cases recorded in $out\n");
