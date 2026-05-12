# DBRecon

Database Reconnaissance Tool for Penetration Testing

[![Tests](https://img.shields.io/badge/tests-331%20passed-brightgreen)](.)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)](.)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](.)
[![License](https://img.shields.io/badge/license-MIT-blue)](.)

## Overview

DBRecon is a CLI tool designed for penetration testing scenarios that connects to MySQL databases, identifies the applications they support, and discovers sensitive information. It supports **7 application fingerprints**, **6 sensitive data types**, and **5 report output formats**.

## Features

- **Database Connection** — Secure MySQL connections with SSL, custom ports, and connection pooling
- **Application Fingerprinting** — Automatically identify CMS and frameworks:
  - WordPress (with WooCommerce & Yoast SEO plugin detection)
  - Drupal 7 / Drupal 8
  - Laravel
  - Django
  - Joomla
  - Magento
  - PrestaShop
- **Sensitive Data Discovery** — Find passwords, API keys, emails, phone numbers, credit cards, and URLs via field name matching and data pattern analysis
- **Database Structure Analysis** — Analyze table structures and column metadata
- **Report Generation** — Generate detailed security assessment reports in JSON, CSV, HTML, Markdown, or Console format

## Installation

```bash
pip install dbrecon
```

For development:

```bash
git clone https://github.com/yourusername/dbrecon.git
cd dbrecon
pip install -e .[dev]
```

## Usage

### Test Database Connection

```bash
dbrecon --host 192.168.1.100 --user root --password pass123 test-connection
```

Options: `--port`, `--ssl/--no-ssl`, `--timeout`, `--database`

### Application Fingerprinting

```bash
dbrecon --host 192.168.1.100 --user root --password pass123 fingerprint --database mydb
```

Options: `--deep/--shallow`, `--format json|csv|html|markdown|console`, `--output FILE`

### Sensitive Data Scan

```bash
dbrecon --host 192.168.1.100 --user root --password pass123 scan-sensitive --database mydb
```

Options: `--data-types passwords,emails,api_keys,phones`, `--format`, `--output`

### Full Security Assessment

```bash
dbrecon --host 192.168.1.100 --user root --password pass123 full-scan --database mydb
```

Options: `--deep/--shallow`, `--format`, `--output`

### Global Options

| Option | Description |
|--------|-------------|
| `--host` | Database host address (required) |
| `--port` | Database port (default: 3306) |
| `--user` | Database username (required) |
| `--password` | Database password (required) |
| `--database` | Target database name |
| `--ssl/--no-ssl` | Enable SSL connection |
| `--timeout` | Connection timeout in seconds (default: 30) |
| `--version` | Show version |
| `--help` | Show help |

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=dbrecon --cov-report=term-missing

# Run specific test categories
pytest -m unit          # Unit tests only
pytest -m cli           # CLI tests only

# Run specific test file
pytest tests/test_scenarios.py -v
```

### Test Architecture

```
tests/
├── conftest.py                        # Shared fixtures
├── test_database.py                   # DatabaseManager unit tests
├── test_database_extended.py          # Extended database edge cases
├── test_fingerprint.py                # FingerprintEngine unit tests
├── test_fingerprint_extended.py       # Extended fingerprint edge cases
├── test_scanner.py                    # SensitiveDataScanner unit tests
├── test_scanner_extended.py           # Extended scanner edge cases
├── test_reporter.py                   # ReportGenerator unit tests
├── test_reporter_extended.py          # Extended reporter edge cases
├── test_cli.py                        # CLI unit tests
├── test_cli_extended.py               # Extended CLI tests + connection failures
├── test_scenarios.py                  # TDD scenario tests (E2E workflows)
├── test_scenarios_fingerprint.py      # TDD fingerprint & sensitive data scenarios
└── test_scenarios_models.py           # TDD model validation & report format scenarios
```

**331 tests** organized into three layers:

| Layer | Files | Count | Purpose |
|-------|-------|-------|---------|
| Unit | `test_*.py` | 97 | Per-module method coverage |
| Extended | `test_*_extended.py` | 125 | Edge cases, error handling, parameterized |
| TDD Scenarios | `test_scenarios*.py` | 109 | End-to-end business workflows |

### Code Quality

```bash
# Format code
black .

# Lint
flake8

# Type check
mypy dbrecon/
```

### Project Structure

```
dbrecon/
├── configs/
│   └── signatures.yaml          # Application fingerprints & data patterns
├── dbrecon/
│   ├── __init__.py              # Package metadata
│   ├── cli.py                   # CLI commands (Click)
│   ├── database.py              # DatabaseManager (MySQL operations)
│   ├── fingerprint.py           # FingerprintEngine (app detection)
│   ├── models.py                # Pydantic data models
│   ├── reporter.py              # ReportGenerator (5 formats)
│   └── scanner.py               # SensitiveDataScanner (data discovery)
├── tests/                       # 331 tests, 100% coverage
├── pyproject.toml               # Build config, dependencies, tool settings
├── CHANGELOG.md                 # Version history
└── README.md                    # This file
```

## Configuration

Application fingerprints and sensitive data patterns are defined in `configs/signatures.yaml`:

```yaml
applications:
  wordpress:
    name: "WordPress"
    priority: 100
    tables:
      required: ["wp_options", "wp_users", "wp_posts"]
      optional: ["wp_comments", "wp_links"]
    fields:
      wp_users: ["ID", "user_login", "user_pass", "user_email"]
    version_detection:
      table: "wp_options"
      field: "option_value"
      key: "db_version"
    plugins:
      woocommerce: { tables: ["wp_woocommerce_*"] }
      yoast_seo: { tables: ["wp_yoast_*"] }

sensitive_patterns:
  passwords:
    field_patterns: ["*password*", "*passwd*", "*pwd*", "*hash*"]
  emails:
    field_patterns: ["*email*", "*mail*"]
  # ... more patterns
```

## License

MIT License

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Always ensure you have proper authorization before testing any system.
