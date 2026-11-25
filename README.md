# PHP Security Linter (Beta)

A PHP tool to lint PHP files for security issues based on CIS and OWASP best practices.

[![current version](https://img.shields.io/packagist/v/yousha/php-security-linter.svg)](https://packagist.org/packages/yousha/php-security-linter) [![Build and Test](https://github.com/Yousha/php-security-linter/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/Yousha/php-security-linter/actions/workflows/main.yml) [![CodeQL](https://github.com/Yousha/php-security-linter/actions/workflows/github-code-scanning/codeql/badge.svg?branch=main)](https://github.com/Yousha/php-security-linter/actions/workflows/github-code-scanning/codeql) [![Dependabot Updates](https://github.com/Yousha/php-security-linter/actions/workflows/dependabot/dependabot-updates/badge.svg?branch=main)](https://github.com/Yousha/php-security-linter/actions/workflows/dependabot/dependabot-updates) [![PHP](https://img.shields.io/badge/PHP-8.0%2B-617CBE)](https://php.net/) [![issues](https://img.shields.io/github/issues/yousha/php-security-linter)](https://github.com/yousha/php-security-linter/issues) ![repo size](https://img.shields.io/github/repo-size/yousha/php-security-linter) [![GitHub license](https://img.shields.io/github/license/yousha/php-security-linter)](LICENSE) [![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.txt)

## Contents

* [Overview](#overview)
* [Features](#features)
* [Requirements](#requirements)
* [Installation](#installation)
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

PHP Security Linter is a static application security testing (SAST) tool for identifying potentially insecure patterns in PHP source code. It applies CIS- and OWASP-oriented rules, with optional MITRE ATT&CK behavior indicators. It analyzes source files without executing the application and can report risks such as injection, cross-site scripting (XSS), insecure configuration, and sensitive-data exposure.

Findings are heuristic indicators that require review in the context of the application. The linter does not prove that a vulnerability is exploitable and should be used alongside code review, testing, and other security controls.

## Features

* **48 registered rules** across 16 CIS, 29 OWASP, and 3 optional MITRE ATT&CK checks.
* **Fast static analysis** without executing code
* **Console output** with file-level findings and scan summary
* **SARIF 2.1.0 output** for interoperable security findings and CI/CD integrations
* **Configurable ruleset**
* **DevSecOps ready** CI/CD pipeline integration
* **Exclusion support** for ignoring specific paths
* **Supported PHP:** 8.0 and newer
* **Supported platforms:** Windows, GNU/Linux, MacOS

## Requirements

1. PHP 8.0 or newer
2. Composer 2 or newer

### PHP Compatibility

The current `main` branch requires PHP 8.0 or newer. The package declares this requirement in `composer.json`.

For the latest development version:

```shell
composer require --dev yousha/php-security-linter:dev-main
```

For a released version, install the package without a branch constraint and Composer will select a compatible published release.

## Screenshots

![CLI scan of two PHP files showing OWASP findings and an opt-in ATT&CK finding](resources/images/screenshots/1.png)

## Diagrams

* C3 — Component View (UML):

![C4 C3 Component View — PHP Security Linter](resources/images/diagrams/artifacts/Component-diagram.svg)

* C2 — Container View (UML):

![C4 C2 Container View — PHP Security Linter](resources/images/diagrams/artifacts/Container-view.svg)

* Dataflow — UML Activity Diagram:

![UML activity diagram showing CLI validation, rule selection, PHP file traversal, exclusions, regex and token analysis, findings, warnings, report generation, and exit status](resources/images/diagrams/artifacts/Dataflow-diagram.svg)

## Installation

Via [Composer](https://getcomposer.org/) per project:

```shell
composer require --dev yousha/php-security-linter
```

Or via [Composer](https://getcomposer.org/) globally:

```shell
composer global require yousha/php-security-linter
```

## Usage

Lint current directory:

```shell
php vendor/bin/php-sl --path=.
```

Or (Windows):

```shell
vendor\bin\php-sl.bat --path=.
```

Lint a directory:

```shell
php vendor/bin/php-sl --path=./src
```

Lint with path exclusion:

```shell
php vendor/bin/php-sl --path=./app --exclude=storage,tests
```

Excluding a specific directory, path exclusion, and rule exclusion:

```bash
php bin/php-sl --path=./src --exclude=storage --exclude-rules=CIS-003,OWASP-001
```


Generate a SARIF 2.1.0 report and write it to a file:

```shell
php vendor/bin/php-sl --path=./src --format=sarif --output=results.sarif
```

Write SARIF to standard output:

```shell
php vendor/bin/php-sl --path=./src --format=sarif > results.sarif
```

The default `text` format remains unchanged. SARIF output includes rule descriptors, severity levels, source file URIs, line locations, and scan warnings as invocation notifications.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean scan |
| 1 | One or more findings |
| 2 | Invalid CLI input or scan error |
| 3 | Fatal error |
| 4 | One or more files/directories could not be scanned |

### Cross-platform notes

- Line endings are normalized (CRLF → LF) before rule matching.
- Path exclusion is case-insensitive.
- Absolute paths (`/…` and `X:\…`) and mixed separators are handled.
- On Windows use `vendor\bin\php-sl.bat` (Composer wrapper).

### Commands

| Option       | Description                      |
| ------------ | -------------------------------- |
| `-p, --path` | Path to scan (required)          |
| `--exclude`  | Comma-separated paths to exclude |
| `--exclude-rules` | Comma-separated rule IDs to ignore |
| `--include-attack` | Enable three MITRE ATT&CK review rules |
| `--list-rules` | List available rule IDs |
| `--format` | Output format: `text` (default) or `sarif` |
| `--output` | Write SARIF output to a file (requires `--format=sarif`) |
| `--help`     | Show help message                |

### Example output

```shell
Scan Results
========================================

File: /src/auth.php
  ✗ [CRITICAL] OWASP: SQL Injection vulnerability detected (Line 42)
  ✗ [HIGH] CIS: Hardcoded database credentials (Line 15)

File: /src/utils.php
  ✗ [MEDIUM] OWASP: XSS vulnerability possible (Line 88)

Summary: Scanned 24 files, found 3 potential issues.
```

### Tests

Run the PHPUnit test suite:

```shell
composer test
```

Or:

```shell
vendor/bin/phpunit tests/
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
