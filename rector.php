<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\ValueObject\PhpVersion;

return RectorConfig::configure()
    ->withPaths([
        __DIR__ . '/.',
    ])
    ->withSkip([
        __DIR__ . '/.git',
        __DIR__ . '/.github',
        __DIR__ . '/resources',
        __DIR__ . '/vendor',
    ])
    ->withRootFiles()
    ->withIndent(' ', 4)
    ->withTypeCoverageLevel(10)
    ->withDeadCodeLevel(10)
    ->withCodeQualityLevel(10)
    ->withCodingStyleLevel(10)
    // Force Rector to use PHP x.x features only.
    ->withPhpVersion(PhpVersion::PHP_74)
    // Import Rector sets relevant for PHP x.x.
    ->withSets([SetList::PHP_74]);
