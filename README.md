# PHP Security Linter (Beta)

PHP 7.4-compatible static analysis for PHP source code and inline HTML templates.

[![Latest Packagist release across branches](https://img.shields.io/packagist/v/yousha/php-security-linter.svg)](https://packagist.org/packages/yousha/php-security-linter) [![PHP 7.4 CI](https://github.com/Yousha/php-security-linter/actions/workflows/main.yml/badge.svg?branch=main-php7.4)](https://github.com/Yousha/php-security-linter/actions/workflows/main.yml?query=branch%3Amain-php7.4) [![PHP](https://img.shields.io/badge/PHP-7.4-617CBE)](https://php.net/) [![issues](https://img.shields.io/github/issues/yousha/php-security-linter)](https://github.com/yousha/php-security-linter/issues) ![repo size](https://img.shields.io/github/repo-size/yousha/php-security-linter) [![GitHub license](https://img.shields.io/github/license/yousha/php-security-linter)](LICENSE) [![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.txt)

## Contents

* [Overview](#overview)
* [Features](#features)
* [Requirements](#requirements)
* [Installation](#installation)
* [Configuration](#configuration)
* [Usage](#usage)
* [FAQ](#faq)
* [Support](#support)
* [Changelog](#changelog)
* [ToDo](#todo)
* [Contributing](#contributing)
* [Code of Conduct](#code-of-conduct)
* [DCO](#dco)
* [Contributors](#contributors)
* [Notice](#notice)
* [License](#license)

## Overview

This tool checks PHP 7.4 code and inline HTML templates for potential security issues. It parses PHP expressions to distinguish calls, arguments, and assignments from comments and strings. HTML checks inspect form controls and script sources in the template.

## Features

* **26 built-in checks** across two project catalogs (10 CIS-prefixed and 16 OWASP-prefixed)
* Checks for request-data propagation through simple assignments, sensitive output, unsafe configuration, cookie-supplied session IDs, and literal credentials.
* Template checks for static POST forms and versioned jQuery or Bootstrap script references.
* **Fast static analysis** 
* **Text reports** 
* **DevSecOps ready** CI/CD pipeline integration
* **Exclusion support** 
* **Supported platforms:** Windows, GNU/Linux

## Requirements

1. Windows or GNU/Linux OS
2. PHP 7.4.x with PCRE, DOM, and tokenizer
3. Composer >= 2

### Versions

| Package version | Branch        | PHP version | Status         |
|-----------------|---------------|-------------|----------------|
| dev-main        | `main`        | 8.0+        | Active         |
| 3.*             | `main`        | Per tag     | Active         |
| dev-main-php7.4 | `main-php7.4` | 7.4.x       | Maintenance    |
| 2.*             | `main-php7.4` | 7.4         | Maintenance    |
| 1.*             |               | 5.6         | EOL            |

* **Active**: Full support
* **Maintenance**: Bug/Security fixes only
* **EOL**: Unsupported

## Screenshots

![Screenshot](resources/images/screenshots/1.png)

## Diagrams

* Component diagram:

![Component diagram](resources/images/diagrams/artifacts/Component-diagram.png)

* Dataflow diagram:

![Dataflow diagram](resources/images/diagrams/artifacts/Dataflow-diagram.png)

## Installation

To install the branch described here in a PHP 7.4 project:

```shell
composer require --dev yousha/php-security-linter:dev-main-php7.4
```

Or Composer global installation:

```shell
composer global require yousha/php-security-linter:dev-main-php7.4
```

## Usage

Lint a directory:

```shell
php vendor/bin/php-sl --path=./src
```

Lint with exclusions:

```shell
php vendor/bin/php-sl --path=./app --exclude=vendor,tests
```

| Exit code | Meaning |
|---|---|
| 0 | Clean scan or help |
| 1 | Findings |
| 2 | Invalid arguments or scan target |
| 3 | Fatal error |
| 4 | Incomplete scan (read, traversal, parse, or rule evaluation warning), including when findings are present |

### Command options

| Option       | Description                      |
| ------------ | -------------------------------- |
| `-p, --path` | Path to scan (required)          |
| `--exclude`  | Comma-separated paths to exclude |
| `--help`     | Show help message                |

### Example console output

```shell
Scan results
========================================

File: example/settings.php
  ✗ [HIGH] OWASP-A7: Configured minimum password length is six or less (Line 1) [OWASP A07:2021]

Summary: Scanned 1 files, found 1 potential issues.
```

### Test

```shell
composer validate --strict
composer install
composer audit
composer lint
composer format-check
composer refactor-check
composer test
```

## FAQ

See [FAQ.txt](FAQ.txt) file.

## Support

For any question, issues and feature requests, [open an issue.](https://github.com/yousha/php-security-linter/issues).

## Changelog

See [CHANGELOG.txt](CHANGELOG.txt) file.

## ToDo

See [TODO.txt](TODO.txt) file.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork repository.
2. Create a new branch for your feature or bugfix.
3. Submit a pull request with a detailed description of your changes.

For more details see [CONTRIBUTING.txt](CONTRIBUTING.txt).

## Code of Conduct

See [CODE_OF_CONDUCT.txt](CODE_OF_CONDUCT.txt) file.

## DCO

See [DCO.txt](DCO.txt) file.

## Contributors

See [CONTRIBUTORS.txt](CONTRIBUTORS.txt) file.

## Notice

See [NOTICE.txt](NOTICE.txt) file.

## License

This open-source software is distributed under the GPL-3.0 license. See [LICENSE](LICENSE) file.
