<?php
// Regenerate the _COMPOSER_COMMANDS table in packagealert/parsers/process_args.py:
// every spelling composer's Application::find() resolves to an install-family
// command — names, aliases and unique abbreviations. Prints the Python literal.
//
//     php tests/fixtures/argv_oracles/generate_composer_commands.php
$phar = realpath(trim(shell_exec('command -v composer')));
Phar::loadPhar($phar, 'composer.phar');
require 'phar://composer.phar/vendor/autoload.php';
$app = new Composer\Console\Application();
$app->setAutoExit(false);
$words = [];
foreach ($app->all() as $c) { $words[] = $c->getName(); foreach ($c->getAliases() as $a) $words[] = $a; }
$map = [];
foreach (array_unique($words) as $w) {
    for ($k = 1; $k <= strlen($w); $k++) {
        $p = substr($w, 0, $k);
        try { $name = $app->find($p)->getName(); } catch (Throwable $e) { continue; }
        if (in_array($name, ['require', 'install', 'update', 'global'], true)) $map[$p] = $name;
    }
}
ksort($map);
echo "# Every spelling composer resolves to an install-family command (names, aliases,\n";
echo "# unique abbreviations), from Symfony's Application::find(). GENERATED against\n";
echo "# Composer " . Composer\Composer::getVersion() . " by tests/fixtures/argv_oracles/generate_composer_commands.php.\n";
echo "_COMPOSER_COMMANDS: dict[str, str] = {\n";
foreach ($map as $k => $v) echo "    \"$k\": \"$v\",\n";
echo "}\n";
