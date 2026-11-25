# PHP Security Linter (Beta)

Security checks for PHP 7.4 code and inline HTML. This page documents the main-php7.4 maintenance branch.

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

This branch checks PHP 7.4 code and inline HTML templates for potential security issues. It parses PHP expressions to distinguish calls, arguments, and assignments from comments and strings. HTML checks inspect form controls and script sources in the template.

## Features

* **24 built-in checks** across two project catalogs (10 CIS-prefixed and 14 OWASP-prefixed).
* Checks for request-data propagation through simple assignments, sensitive output, unsafe configuration, cookie-supplied session IDs, and literal credentials.
* Template checks for static POST forms and versioned jQuery or Bootstrap script references.
* **Fast static analysis** without executing code
* **Text reports** with file paths and line numbers
* **DevSecOps ready** CI/CD pipeline integration
* **Exclusion support** for ignoring specific paths
* **Supported PHP on this branch:** 7.4.x
* **Supported platforms:** Windows, GNU/Linux, MacOS

## Requirements

1. PHP 7.4.x with PCRE, DOM, and tokenizer
2. Composer >= 2

### Versions

| Package version | Branch        | PHP version | Status         |
|-----------------|---------------|-------------|----------------|
| dev-main        | `main`        | 8.0+         | Active         |
| 3.*             | `main`        | Per tag         | Active         |
| dev-main-php7.4 | `main-php7.4` | 7.4.x       | Maintenance    |
| 2.*             | `main-php7.4` | 7.4         | Maintenance    |
| 1.*             |               | 5.6         | EOL            |

* **Active**: Full support
* **Maintenance**: Critical/Security fixes only
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

For a tagged release use the Composer constraint `2.*`. Features and requirements follow the selected tag. In a source checkout run `composer install` and invoke `php bin/php-sl`.

## Configuration

Use the built-in checks with path exclusions. The PHP checks follow request-controlled values through straightforward variable assignments, concatenation, and interpolation to supported SQL, command, output, include, and remote-resource sinks. This is a conservative single-pass analysis, not full interprocedural or control-flow taint analysis. SQL sinks include common MySQL, PostgreSQL, PDO, and raw query-builder APIs. The scanner also flags weak random generators assigned to security-sensitive names and unrestricted `unserialize()` calls. The session check reports request-supplied session IDs. The rate-limit check reports explicit removal of throttle middleware.

A POST form finding means no recognized hidden CSRF field or recognizable PHP CSRF helper was visible in its static markup. Unrelated PHP fragments no longer suppress the form check. Dynamically generated token markup that does not use a recognized helper may still require manual review. Script version checks use literal JavaScript asset paths. A finding identifies a reference for review, rather than verifying deployed asset contents.

### Rule IDs and standards references

The scanner prints a stable project rule ID and severity with every finding. Mapped findings also carry `standardReference` in the library result and show a separate OWASP reference in the CLI. The category numbers refer to the edition shown.

| Project rule IDs | OWASP reference |
|---|---|
| OWASP-A1-SQL, OWASP-A1-CMD, OWASP-A3 | A03:2021 Injection (SQL, commands, and reflected XSS) |
| OWASP-A2 | A02:2021 Cryptographic Failures (hard-coded password) |
| OWASP-A4 | A01:2021 Broken Access Control (CSRF) |
| OWASP-A5 | A05:2021 Security Misconfiguration |
| OWASP-A6 | A06:2021 Vulnerable and Outdated Components |
| OWASP-A7 | A07:2021 Identification and Authentication Failures |
| OWASP-A10 | A10:2021 Server-Side Request Forgery |
| OWASP-API1 | API4:2023 Unrestricted Resource Consumption (throttle removal) |

Unmapped OWASP-prefixed checks flag direct writes of sensitive fields (OWASP-A8), credential-shaped literals (OWASP-CLOUD1), weak security-token randomness (OWASP-WEAK-RNG), and unrestricted deserialization (OWASP-DESERIALIZATION). These findings have no category mapping. CIS-001 through CIS-010 are local hardening identifiers. The project has no verified mapping from those IDs to numbered CIS Benchmark controls. Severity values express the project's review priorities.

Sources: [OWASP Top 10:2021](https://top10.owasp.org/2021/), [OWASP API Security Top 10:2023, API4](https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/).

## Usage

Lint a directory:

```shell
php vendor/bin/php-sl --path=./src
```

Lint with exclusions:

```shell
php vendor/bin/php-sl --path=./app --exclude=vendor,tests
```

A scan accepts one directory. It skips excluded subtrees, special files, directory symlinks, and file symlinks leading outside the scan root. Relative exclusions match complete path components within the root. Absolute exclusions match the named path and its descendants.

The PHP 7.4 CLI produces text reports. Reports go to stdout. Warnings and argument errors go to stderr. An incomplete scan preserves findings from files it could check. The scanned-file count includes successfully read PHP files.

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

### CI and local checks

Pushes to `main-php7.4` and pull requests targeting it run these checks on Ubuntu with PHP 7.4 and Composer 2. From a source checkout:

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
