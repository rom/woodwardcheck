# WoodwardCheck

A comprehensive security auditing tool for Woodward EasyGen generator controllers, with specific focus on the 3500XT model.

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Version](https://img.shields.io/badge/Version-1.0.0-green.svg)

## Overview

WoodwardCheck performs security checks, vulnerability assessments, and configuration audits to ensure industrial control systems meet security best practices and compliance requirements such as IEC 62443.

### Key Features

- **Modular Security Checks**: Authentication, network, configuration, firmware, and cryptographic assessments
- **Vulnerability Scanning**: Detection of known CVEs and common security misconfigurations
- **Multiple Protocols**: Support for Modbus TCP, HTTP/HTTPS, SNMP, VNC, Telnet, SSH, and FTP
- **Protocol Security Auditing**: VNC, Telnet, SSH, and FTP scanning with security configuration checks
- **Flexible Test Selection**: Run specific checks, categories, or predefined profiles
- **Custom Port Configuration**: Configurable ports for all supported protocols
- **Multiple Report Formats**: HTML, JSON, RTF, Markdown, and plain text
- **Safe Mode**: Read-only checks that won't disrupt production systems
- **IEC 62443 Compliance**: Mapping to industrial security standards

## Installation

### From Source

```bash
git clone https://github.com/woodwardcheck/woodwardcheck.git
cd woodwardcheck
pip install -e .
```

### With Optional Dependencies

```bash
pip install -e ".[full]"  # Includes pymodbus, pysnmp, requests, rich
```

### Development Installation

```bash
pip install -e ".[dev]"   # Includes pytest, black, flake8, mypy
```

## Quick Start

### Basic Audit

```bash
# Run default audit on target
woodwardcheck 192.168.1.100

# Quick scan with essential checks
woodwardcheck 192.168.1.100 --profile quick-scan

# Full comprehensive audit
woodwardcheck 192.168.1.100 --profile full-audit
```

### Selective Testing

```bash
# Run specific categories
woodwardcheck 192.168.1.100 --category auth,net

# Run specific checks
woodwardcheck 192.168.1.100 --checks AUTH-001,NET-001,CFG-001

# Exclude certain checks
woodwardcheck 192.168.1.100 --exclude FW-001,FW-002

# Only high severity and above
woodwardcheck 192.168.1.100 --min-severity high
```

### Report Generation

```bash
# HTML report
woodwardcheck 192.168.1.100 --format html -o report.html

# JSON for automation
woodwardcheck 192.168.1.100 --format json -o report.json

# Markdown for documentation
woodwardcheck 192.168.1.100 --format markdown -o report.md

# RTF for formal documents
woodwardcheck 192.168.1.100 --format rtf -o report.rtf
```

### Information Commands

```bash
# List all available checks
woodwardcheck --list-checks

# List scan profiles
woodwardcheck --list-profiles

# List check categories
woodwardcheck --list-categories
```

## Check Categories

| Category | Description |
|----------|-------------|
| AUTH | Authentication & Access Control |
| NET | Network Security |
| CFG | Configuration Security |
| FW | Firmware & Updates |
| PROTO | Communication Protocols |
| CRYPTO | Cryptographic Controls |

## Security Checks

### Authentication (AUTH)

| Check ID | Name | Severity |
|----------|------|----------|
| AUTH-001 | Default Credentials Detection | Critical |
| AUTH-002 | Password Policy Check | High |
| AUTH-003 | Authentication Required | Critical |
| AUTH-004 | Session Timeout Configuration | Medium |
| AUTH-005 | Concurrent Session Limits | Low |

### Network Security (NET)

| Check ID | Name | Severity |
|----------|------|----------|
| NET-001 | Port Scan Analysis | Medium |
| NET-002 | Unencrypted Modbus TCP | Medium |
| NET-003 | HTTP Without TLS | High |
| NET-004 | SNMP Protocol Version | High |
| NET-005 | Network Segmentation Check | High |
| NET-006 | DNS Configuration | Low |
| NET-007 | VNC Security Audit | High |
| NET-008 | Telnet Security Audit | Critical |
| NET-009 | SSH Security Audit | Medium |
| NET-010 | FTP Security Audit | Critical |

### Vulnerability (VULN)

| Check ID | Name | Severity |
|----------|------|----------|
| VULN-001 | Insecure Service Detection | High |
| VULN-002 | Debug Mode Detection | High |
| VULN-003 | Information Disclosure Check | Medium |

### Firmware (FW)

| Check ID | Name | Severity |
|----------|------|----------|
| FW-001 | Outdated Firmware Detection | High |
| FW-002 | Known CVE Detection | Critical |
| FW-003 | Unsigned Firmware Check | High |

### Configuration (CFG)

| Check ID | Name | Severity |
|----------|------|----------|
| CFG-001 | Logging Configuration | Medium |
| CFG-002 | NTP Configuration | Low |
| CFG-003 | Backup Configuration | Medium |
| CFG-004 | Factory Defaults Check | High |
| CFG-005 | SNMP Configuration | High |
| CFG-006 | Access Control Lists | Medium |
| CFG-007 | Modbus Function Code Restrictions | Medium |

### Cryptographic (CRYPTO)

| Check ID | Name | Severity |
|----------|------|----------|
| CRYPTO-001 | Encryption Configuration | High |
| CRYPTO-002 | Certificate Validation | High |

## Scan Profiles

| Profile | Description |
|---------|-------------|
| quick-scan | Fast scan with essential checks only |
| full-audit | Comprehensive security audit |
| compliance-62443 | IEC 62443 compliance-focused audit |
| network-only | Network security checks only |

## Configuration File

Create a `woodwardcheck.yaml` file:

```yaml
target:
  host: 192.168.1.100
  port: 502
  protocol: modbus-tcp
  timeout: 30
  custom_ports:
    vnc: 5900
    telnet: 23
    ssh: 22
    ftp: 21
    http: 80
    https: 443
    snmp: 161
    modbus_tcp: 502

authentication:
  username: admin
  password: password
  # Or use custom credential files for testing
  users_file: /path/to/custom_users.txt
  passwords_file: /path/to/custom_passwords.txt
  use_default_creds: true

scan:
  categories:
    - auth
    - net
    - cfg
  min_severity: medium
  safe_mode: true

output:
  format: html
  path: ./reports/
  include_evidence: true

logging:
  level: INFO
  file: ./woodwardcheck.log
```

Use with:
```bash
woodwardcheck --config woodwardcheck.yaml
```

## Default Credentials

WoodwardCheck includes default credential files for testing common username/password combinations found on industrial control systems:

- **Default Users File**: `woodwardcheck/data/default_users.txt`
- **Default Passwords File**: `woodwardcheck/data/default_passwords.txt`

These files contain common usernames and passwords found on Woodward devices and similar ICS equipment.

### Using Custom Credential Files

You can specify custom credential files in the configuration:

```yaml
authentication:
  users_file: /path/to/my_users.txt
  passwords_file: /path/to/my_passwords.txt
```

Or via command line (when supported):

```bash
woodwardcheck 192.168.1.100 --users-file custom_users.txt --passwords-file custom_passwords.txt
```

### Credential File Format

Each file should contain one entry per line. Lines starting with `#` are comments:

```text
# Custom users file
admin
operator
engineer
custom_user
```

```text
# Custom passwords file
admin
password
1234
# Empty password (leave a blank line)

custom_password
```

**Note**: Empty passwords are supported (common on ICS devices) - just include a blank line in the passwords file.

### Command-Line Port Configuration

You can also configure ports via command line:

```bash
# Use custom ports for protocols
woodwardcheck 192.168.1.100 --vnc-port 5901 --ssh-port 2222 --telnet-port 2323 --ftp-port 2121

# Combine with other options
woodwardcheck 192.168.1.100 --http-port 8080 --https-port 8443 --ftp-port 2121 --format html -o report.html
```

## Report Formats

### HTML
Interactive reports with charts, filtering, and expandable findings. Best for human review.

### JSON
Machine-readable output with full details. Supports SARIF format for CI/CD integration.

### Markdown
GitHub-compatible markdown with badges and tables. Ideal for documentation.

### RTF
Rich text format for formal documentation and reports.

### Text
Plain text with optional ANSI colors for terminal output.

## API Usage

```python
from woodwardcheck import AuditEngine
from woodwardcheck.utils.config import Config

# Create configuration
config = Config()
config.target.host = "192.168.1.100"
config.apply_profile("quick-scan")

# Run audit
engine = AuditEngine(config)
findings = engine.run_audit()

# Generate report
report = engine.generate_report("html", "./reports/")
print(f"Report saved to: {report}")

# Cleanup
engine.cleanup()
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no failed checks |
| 1 | Failed checks found (medium/low severity) |
| 2 | Critical or high severity findings |

## Security Considerations

- **Authorized Testing Only**: Only use on systems you have permission to test
- **Safe Mode**: Enabled by default to prevent disruption
- **No Credential Storage**: Credentials are not logged or stored
- **Audit Trail**: All scan activities are logged

## Supported Devices

- Woodward EasyGen 3500XT
- Other Woodward EasyGen series (partial support)

## Documentation

- [Design Document](docs/DESIGN.md) - Architecture and technical details
- [Manual Page](docs/woodwardcheck.1) - Unix man page

## Project Structure

```
woodwardcheck/
├── woodwardcheck/
│   ├── __init__.py          # Package initialization
│   ├── cli.py               # Command-line interface
│   ├── engine.py            # Core audit engine
│   ├── data/                # Default credential files
│   │   ├── __init__.py      # Data loading utilities
│   │   ├── default_users.txt    # Default usernames
│   │   └── default_passwords.txt # Default passwords
│   ├── modules/             # Security check modules
│   │   ├── base.py          # Base module class
│   │   ├── security_checks.py
│   │   ├── vulnerability_scanner.py
│   │   ├── config_controls.py
│   │   └── network_analysis.py
│   ├── reporters/           # Report generators
│   │   ├── html_reporter.py
│   │   ├── json_reporter.py
│   │   ├── markdown_reporter.py
│   │   ├── rtf_reporter.py
│   │   └── text_reporter.py
│   └── utils/               # Utilities
│       ├── config.py
│       ├── connection.py
│       ├── constants.py
│       └── logger.py
├── tests/                   # Comprehensive test suite
│   ├── conftest.py          # Pytest fixtures
│   ├── test_data.py
│   ├── test_constants.py
│   ├── test_config.py
│   ├── test_connection.py
│   ├── test_base_module.py
│   ├── test_security_checks.py
│   ├── test_reporters.py
│   ├── test_engine.py
│   └── test_cli.py
├── docs/
│   ├── DESIGN.md            # Design document
│   └── woodwardcheck.1      # Man page
├── reports/                 # Default report output
├── README.md
├── LICENSE
├── setup.py
├── requirements.txt
└── woodwardcheck.yaml.example
```

## Testing

WoodwardCheck includes a comprehensive test suite using pytest.

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run tests with coverage
pytest --cov=woodwardcheck --cov-report=html

# Run specific test file
pytest tests/test_config.py

# Run tests with verbose output
pytest -v

# Run only fast tests (skip slow integration tests)
pytest -m "not slow"
```

### Test Structure

```
tests/
├── conftest.py           # Shared fixtures
├── test_data.py          # Tests for data/credential file loading
├── test_constants.py     # Tests for constants and enums
├── test_config.py        # Tests for configuration management
├── test_connection.py    # Tests for connection handlers
├── test_base_module.py   # Tests for base module classes
├── test_security_checks.py  # Tests for security check module
├── test_reporters.py     # Tests for report generators
├── test_engine.py        # Tests for audit engine
└── test_cli.py           # Tests for CLI
```

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

## Author

**WoodwardCheck Security Team**

- Project Lead: WoodwardCheck Contributors
- Email: security@woodwardcheck.io
- GitHub: [https://github.com/woodwardcheck/woodwardcheck](https://github.com/woodwardcheck/woodwardcheck)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. The authors are not responsible for misuse of this tool.

## Support

- GitHub Issues: [Report bugs](https://github.com/woodwardcheck/woodwardcheck/issues)
- Documentation: [Wiki](https://github.com/woodwardcheck/woodwardcheck/wiki)
