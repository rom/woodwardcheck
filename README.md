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
- **Multiple Protocols**: Support for Modbus TCP, HTTP/HTTPS, and SNMP
- **Flexible Test Selection**: Run specific checks, categories, or predefined profiles
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
├── docs/
│   ├── DESIGN.md            # Design document
│   └── woodwardcheck.1      # Man page
├── tests/                   # Test suite
├── reports/                 # Default report output
├── README.md
├── LICENSE
├── setup.py
├── requirements.txt
└── woodwardcheck.yaml.example
```

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. The authors are not responsible for misuse of this tool.

## Support

- GitHub Issues: [Report bugs](https://github.com/woodwardcheck/woodwardcheck/issues)
- Documentation: [Wiki](https://github.com/woodwardcheck/woodwardcheck/wiki)
