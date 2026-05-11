# DBRecon

Database Reconnaissance Tool for Penetration Testing

## Overview

DBRecon is a CLI tool designed for penetration testing scenarios that connects to MySQL databases, identifies the applications they support, and discovers sensitive information.

## Features

- **Database Connection**: Secure connection to MySQL databases
- **Application Fingerprinting**: Automatically identify CMS, frameworks, and custom applications
- **Sensitive Data Discovery**: Find passwords, API keys, PII, and other sensitive information
- **Database Structure Analysis**: Analyze table structures and relationships
- **URL/Host Discovery**: Extract URLs and host information from database content
- **Report Generation**: Generate detailed security assessment reports

## Installation

```bash
pip install dbrecon
```

## Usage

```bash
# Test database connection
dbrecon --host 192.168.1.100 --user root --password pass123 test-connection

# Full security scan
dbrecon --host 192.168.1.100 --user root --password pass123 full-scan

# Scan for sensitive data only
dbrecon --host 192.168.1.100 --user root --password pass123 scan-sensitive

# Generate fingerprint report
dbrecon --host 192.168.1.100 --user root --password pass123 fingerprint
```

## Development

```bash
# Clone the repository
git clone https://github.com/yourusername/dbrecon.git
cd dbrecon

# Install in development mode
pip install -e .[dev]

# Run tests
pytest

# Run with coverage
pytest --cov=dbrecon
```

## License

MIT License

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Always ensure you have proper authorization before testing any system.