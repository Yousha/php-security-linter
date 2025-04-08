<?php

declare(strict_types=1);

use PhpCsFixer\Finder;
use PhpCsFixer\Config;

static $rules = [
    '@PSR1'  => true,
    '@PSR2'  => true,
    '@PSR12' => true,
    '@PER-CS2.0' => true,
    '@PHP83Migration' => true
];

static $excludeFolders = [
    'vendor/'
];

$finder = Finder::create()
    ->in(__DIR__)
    ->exclude($excludeFolders)
    ->ignoreDotFiles(true)
    ->ignoreVCS(true);


return (new Config())
    ->setRules($rules)
    ->setFinder($finder);
