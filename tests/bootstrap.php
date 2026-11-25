<?php

// Enforce strict type checking only for THIS file.
declare(strict_types=1);

// Include Composer autoloader to load dependencies.
require_once dirname(__DIR__) . '/vendor/autoload.php';

// Error/Exception engine, always `E_ALL`.
error_reporting(E_ALL);
// Error/Exception display system.
ini_set('display_errors', '1');
ini_set('display_startup_errors', 'On');
ini_set('ignore_repeated_errors', 'On');
ini_set('memory_limit', '-1');
// Current application environment.
putenv('APPLICATION_ENVIRONMENT=test');
