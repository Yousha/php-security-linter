<?php

declare(strict_types=1);

use PhpCsFixer\Finder;
use PhpCsFixer\Config;

static $rules = [
    '@PSR1'  => true,
    '@PSR2'  => true,
    '@PSR12' => true,
    '@PER-CS' => true,
    '@PHP8x5Migration' => true
];

static $excludeFolders = [
    '.git/',
    '.github/',
    'resources/',
    'vendor/'
];

$finder = Finder::create()
    ->in(__DIR__)
    ->exclude($excludeFolders)
    ->ignoreDotFiles(true)
    ->ignoreVCS(true);


$config = new Config();
$config->setRules($rules);
$config->setFinder($finder);

return $config;
