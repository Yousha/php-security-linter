<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\ValueObject\PhpVersion;

return RectorConfig::configure()
    ->withPaths([
        __DIR__ . '/.',
    ])
    // Skip non-project directories.
    ->withSkip([
        __DIR__ . '/.git',
        __DIR__ . '/.github',
        __DIR__ . '/vendor',
        __DIR__ . '/resources',
    ])
    ->withRootFiles()
    ->withIndent(' ', 4)
    ->withComposerBased(phpunit: true)
    ->withTypeCoverageLevel(10)
    ->withDeadCodeLevel(10)
    ->withCodeQualityLevel(10)
    ->withCodingStyleLevel(10)
    // Force Rector to use PHP x.x features only.
    ->withPhpVersion(PhpVersion::PHP_85)
    // Import Rector sets relevant for PHP x.x.
    ->withPhpSets(php85: true);
