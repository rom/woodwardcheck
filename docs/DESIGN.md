# WoodwardCheck - Security Audit Tool Design Document

## Overview

WoodwardCheck is a comprehensive security auditing tool designed for Woodward EasyGen generator controllers, with specific focus on the 3500XT model. The tool performs security checks, vulnerability assessments, and configuration audits to ensure industrial control systems meet security best practices and compliance requirements.

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         WoodwardCheck CLI                           │
├─────────────────────────────────────────────────────────────────────┤
│                        Core Audit Engine                            │
├───────────────┬───────────────┬───────────────┬────────────────────┤
│   Security    │ Vulnerability │ Configuration │    Network         │
│   Checks      │   Scanner     │   Controls    │    Analysis        │
├───────────────┴───────────────┴───────────────┴────────────────────┤
│                       Report Generator                              │
│         (HTML | JSON | RTF | Markdown | Text)                       │
├─────────────────────────────────────────────────────────────────────┤
│                    Target Interface Layer                           │
│              (Modbus TCP | HTTP API | SNMP)                         │
└─────────────────────────────────────────────────────────────────────┘
```

### Component Description

#### 1. CLI Interface (`cli.py`)
- Command-line argument parsing
- Test selection and filtering
- Output format selection
- Verbosity and logging control
- Configuration file support

#### 2. Core Audit Engine (`engine.py`)
- Orchestrates all audit modules
- Manages test execution flow
- Collects and aggregates results
- Handles timeouts and error recovery

#### 3. Audit Modules

##### 3.1 Security Checks (`modules/security_checks.py`)
- Authentication mechanism verification
- Password policy compliance
- Session management security
- Access control verification
- Encryption configuration
- Certificate validation

##### 3.2 Vulnerability Scanner (`modules/vulnerability_scanner.py`)
- Known CVE checks for EasyGen firmware
- Default credential detection
- Insecure protocol detection
- Buffer overflow susceptibility tests
- Firmware version analysis

##### 3.3 Configuration Controls (`modules/config_controls.py`)
- Network configuration audit
- Protocol settings verification
- Logging configuration
- Backup configuration status
- Parameter validation
- Compliance with IEC 62443

##### 3.4 Network Analysis (`modules/network_analysis.py`)
- Port scanning and service detection
- Protocol analysis (Modbus, HTTP, SNMP)
- Network segmentation verification
- Firewall rule assessment

#### 4. Report Generators (`reporters/`)
- `html_reporter.py` - Interactive HTML reports with charts
- `json_reporter.py` - Machine-readable JSON output
- `rtf_reporter.py` - Rich Text Format for documents
- `markdown_reporter.py` - GitHub-compatible markdown
- `text_reporter.py` - Plain text terminal output

#### 5. Utilities (`utils/`)
- `connection.py` - Target connection handling
- `logger.py` - Logging infrastructure
- `config.py` - Configuration management
- `constants.py` - EasyGen-specific constants

## Data Flow

```
User Input → CLI Parser → Engine
                           ↓
                    Load Configuration
                           ↓
                    Initialize Modules
                           ↓
              ┌────────────┼────────────┐
              ↓            ↓            ↓
         Security    Vulnerability  Configuration
         Checks        Scanner       Controls
              ↓            ↓            ↓
              └────────────┼────────────┘
                           ↓
                    Aggregate Results
                           ↓
                    Report Generator
                           ↓
                    Output (file/stdout)
```

## Security Check Categories

### Authentication & Access Control (AUTH)
| Check ID | Description | Severity |
|----------|-------------|----------|
| AUTH-001 | Default credentials in use | Critical |
| AUTH-002 | Weak password policy | High |
| AUTH-003 | No authentication required | Critical |
| AUTH-004 | Session timeout not configured | Medium |
| AUTH-005 | Concurrent session limits | Low |

### Network Security (NET)
| Check ID | Description | Severity |
|----------|-------------|----------|
| NET-001 | Insecure protocols enabled (Telnet, FTP) | High |
| NET-002 | Unencrypted Modbus TCP | Medium |
| NET-003 | SNMP v1/v2c in use | High |
| NET-004 | Unnecessary ports open | Medium |
| NET-005 | No network segmentation | High |

### Configuration Security (CFG)
| Check ID | Description | Severity |
|----------|-------------|----------|
| CFG-001 | Logging disabled | Medium |
| CFG-002 | NTP not configured | Low |
| CFG-003 | Backup not configured | Medium |
| CFG-004 | Factory defaults in use | High |
| CFG-005 | Debug mode enabled | High |

### Firmware & Updates (FW)
| Check ID | Description | Severity |
|----------|-------------|----------|
| FW-001 | Outdated firmware version | High |
| FW-002 | Known CVE vulnerabilities | Critical |
| FW-003 | Unsigned firmware allowed | High |
| FW-004 | No update mechanism | Medium |

### Communication Protocols (PROTO)
| Check ID | Description | Severity |
|----------|-------------|----------|
| PROTO-001 | Modbus function code restrictions | Medium |
| PROTO-002 | HTTP without TLS | High |
| PROTO-003 | Certificate validation disabled | High |
| PROTO-004 | Weak cipher suites | Medium |

## EasyGen 3500XT Specific Considerations

### Supported Communication Interfaces
- Modbus TCP (Port 502)
- HTTP/HTTPS Web Interface (Port 80/443)
- SNMP (Port 161)
- ToolKit communication (Proprietary)

### Register Map Knowledge Base
The tool maintains a knowledge base of EasyGen 3500XT Modbus registers:
- Configuration registers
- Status registers
- Control registers
- Diagnostic registers

### Firmware Version Database
- Known vulnerable versions
- Security patch history
- Feature availability by version

## Test Selection System

### By Category
```bash
woodwardcheck --category auth,net TARGET
```

### By Severity
```bash
woodwardcheck --min-severity high TARGET
```

### By Specific Checks
```bash
woodwardcheck --checks AUTH-001,NET-003,CFG-002 TARGET
```

### Exclude Checks
```bash
woodwardcheck --exclude FW-001 TARGET
```

### Using Profiles
```bash
woodwardcheck --profile quick-scan TARGET
woodwardcheck --profile full-audit TARGET
woodwardcheck --profile compliance-62443 TARGET
```

## Report Structure

### Summary Section
- Overall security score (0-100)
- Critical/High/Medium/Low finding counts
- Test execution summary
- Target information

### Findings Section
- Finding ID and category
- Severity classification
- Detailed description
- Evidence collected
- Remediation recommendations
- References (CVE, CWE, IEC 62443)

### Technical Details Section
- Raw test results
- Network traces
- Configuration dumps
- Timing information

### Appendices
- Test methodology
- Tool version information
- Glossary of terms

## Configuration File Format

```yaml
# woodwardcheck.yaml
target:
  host: 192.168.1.100
  port: 502
  protocol: modbus

authentication:
  username: admin
  password_file: /path/to/credentials

scan:
  categories:
    - auth
    - net
    - cfg
  min_severity: medium
  timeout: 30
  parallel: true

output:
  format: html
  path: ./reports/
  include_evidence: true

logging:
  level: INFO
  file: ./woodwardcheck.log
```

## Security Considerations

### Tool Security
- No hardcoded credentials
- Secure credential storage
- Encrypted configuration files
- Audit logging of tool usage

### Safe Scanning Practices
- Read-only checks by default
- Configurable rate limiting
- Safe mode for production systems
- No denial-of-service inducing tests

### Compliance
- Designed for authorized testing only
- Requires explicit target specification
- Logging of all scan activities
- Warning prompts for intrusive tests

## Future Enhancements

1. **Plugin System** - Allow custom check modules
2. **Scheduled Scanning** - Automated periodic audits
3. **Baseline Comparison** - Track security posture changes
4. **Integration APIs** - SIEM/SOAR integration
5. **Multi-target Scanning** - Scan multiple controllers
6. **Graphical Interface** - Web-based dashboard

## Dependencies

- Python 3.8+
- pymodbus - Modbus communication
- requests - HTTP communication
- pysnmp - SNMP communication
- jinja2 - Report templating
- pyyaml - Configuration parsing
- rich - Terminal output formatting

## File Structure

```
woodwardcheck/
├── woodwardcheck/
│   ├── __init__.py
│   ├── cli.py
│   ├── engine.py
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── security_checks.py
│   │   ├── vulnerability_scanner.py
│   │   ├── config_controls.py
│   │   └── network_analysis.py
│   ├── reporters/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── html_reporter.py
│   │   ├── json_reporter.py
│   │   ├── rtf_reporter.py
│   │   ├── markdown_reporter.py
│   │   └── text_reporter.py
│   └── utils/
│       ├── __init__.py
│       ├── connection.py
│       ├── logger.py
│       ├── config.py
│       └── constants.py
├── docs/
│   ├── DESIGN.md
│   └── woodwardcheck.1
├── tests/
│   └── ...
├── reports/
│   └── ...
├── README.md
├── LICENSE
├── setup.py
├── requirements.txt
└── woodwardcheck.yaml.example
```

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01 | Initial release |

---

*This document is part of the WoodwardCheck project.*
*For authorized security testing of Woodward EasyGen controllers.*
