# Auth0 Explorer

> Security assessment and reconnaissance tool for Auth0 implementations

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/EVA-Information-Security-Consluting/auth0-explorer)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![EVA Security](https://img.shields.io/badge/EVA-Security-red.svg)](https://github.com/EVA-Information-Security-Consluting)

Auth0 Explorer is a black-box security assessment tool designed to discover misconfigurations and security issues in Auth0 implementations. It performs automated reconnaissance and testing across multiple attack surfaces.

**Author:** Bar Hajby  
**Organization:** [E.V.A Security](https://github.com/EVA-Information-Security-Consluting)

## 🎯 Features

- **Multi-Phase Testing**: Organized workflow from reconnaissance to exploitation
- **Connection Discovery**: Enumerate available authentication methods
- **Username Enumeration**: Test for account enumeration vulnerabilities
- **Password Policy Analysis**: Discover weak password requirements
- **Public Signup Detection**: Identify unintended registration endpoints
- **Open Redirect Testing**: Validate redirect URI configurations
- **Comprehensive Reporting**: JSON and text-based output formats

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Security Checks](#security-checks)
- [Command-Line Options](#command-line-options)
- [Output](#output)
- [Examples](#examples)
- [Development](#development)
- [Legal Disclaimer](#legal-disclaimer)
- [Contributing](#contributing)
- [License](#license)

## 🚀 Installation

### Prerequisites

- Python 3.10 or higher
- pip (comes with Python) or [uv](https://github.com/astral-sh/uv) package manager

### Method 1: Standard Python Installation

```bash
# Clone the repository
git clone https://github.com/EVA-Information-Security-Consluting/auth0-explorer.git
cd auth0-explorer

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On macOS/Linux:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
# Or install from pyproject.toml:
pip install -e .
```

### Method 2: Using uv (Recommended)

[uv](https://github.com/astral-sh/uv) is a fast Python package manager that simplifies dependency management.

```bash
# Install uv
# macOS/Linux:
curl -LsSf https://astral.sh/uv/install.sh | sh
# Windows:
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

# Clone and setup
git clone https://github.com/EVA-Information-Security-Consluting/auth0-explorer.git
cd auth0-explorer
uv venv

# Dependencies will be automatically installed on first run
```

## ⚡ Quick Start

### Using Standard Python

```bash
# Activate virtual environment first
source .venv/bin/activate  # macOS/Linux
# or: .venv\Scripts\activate  # Windows

# Basic scan
python -m src.cli \
  --domain victim.auth0.com \
  --client-id YOUR_CLIENT_ID \
  --target-app https://app.victim.com

# Or if installed with pip install -e .
auth0-pentest \
  --domain victim.auth0.com \
  --client-id YOUR_CLIENT_ID \
  --target-app https://app.victim.com
```

### Using uv

```bash
# Basic scan (no activation needed)
uv run auth0-pentest \
  --domain victim.auth0.com \
  --client-id YOUR_CLIENT_ID \
  --target-app https://app.victim.com

# Scan with custom connection keyword
uv run auth0-pentest \
  --domain victim.auth0.com \
  --client-id YOUR_CLIENT_ID \
  --target-app https://app.victim.com \
  --connections-keyword mycompany

# Test specific email for enumeration
uv run auth0-pentest \
  --domain victim.auth0.com \
  --client-id YOUR_CLIENT_ID \
  --target-app https://app.victim.com \
  --enumerate-user admin@victim.com
```

## 📖 Usage

### Basic Command Structure

```bash
# With uv (recommended):
uv run auth0-pentest [OPTIONS]

# With Python (after activating venv):
python -m src.cli [OPTIONS]

# Or if installed with pip:
auth0-pentest [OPTIONS]
```

### Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `--domain` | Auth0 tenant domain | `victim.auth0.com` |
| `--client-id` | Auth0 application client ID | `abc123xyz` |
| `--target-app` | Target application URL | `https://app.victim.com` |

### Optional Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--connection-wordlist` | - | Path to custom connection names wordlist |
| `--connections-keyword` | - | Generate connection variations (e.g., `google` → `google-prod`, `google-dev`) |
| `--enumerate-user` | - | Email address to test for enumeration |
| `--output` | `./output` | Output directory for reports |
| `--rate-limit-delay` | `1.0` | Delay between requests (seconds) |
| `--workers` | `5` | Number of concurrent workers |
| `--proxy` | - | HTTP proxy URL (e.g., `http://127.0.0.1:8080`) |
| `--user-agent` | (default) | Custom User-Agent header |
| `--cleanup/--no-cleanup` | `--cleanup` | Delete test accounts after scan |
| `--phases` | `all` | Comma-separated phases to run: 1, 2, or 3 |

## 🔍 Security Checks

### Phase 1: Reconnaissance
- **1.1 OpenID Configuration Discovery** - Discovers supported grant types and algorithms
- **1.2 Open Redirect** - Tests redirect URI validation

### Phase 2: Connection Discovery
- **2.1 Connection Enumeration** - Discovers available authentication methods

### Phase 3: Per-Connection Testing
- **3.1 Username Enumeration** - Identifies valid user accounts via signup endpoint
- **3.2 Password Policy Discovery** - Determines password complexity requirements
- **3.3 Public Signup Misconfiguration** - Tests if unintended public registration is possible

## 📊 Output

The tool generates two types of reports in the output directory:

### JSON Report
```
output/auth0_scan_[domain]_[timestamp].json
```
Complete scan results with detailed findings, metadata, and structured data.

### Text Summary
```
output/auth0_summary_[domain]_[timestamp].txt
```
Human-readable summary with findings organized by severity.

## 💡 Examples

### Example 1: Full Scan with Connection Discovery

```bash
# With uv:
uv run auth0-pentest \
  --domain your-tenant.auth0.com \
  --client-id YOUR_CLIENT_ID \
  --target-app https://your-app.com \
  --connections-keyword YourCompany \
  --rate-limit-delay 0.5 \
  --output results/full-scan

# With Python:
auth0-pentest \
  --domain your-tenant.auth0.com \
  --client-id YOUR_CLIENT_ID \
  --target-app https://your-app.com \
  --connections-keyword YourCompany \
  --rate-limit-delay 0.5 \
  --output results/full-scan
```

### Example 2: Username Enumeration Only

```bash
# With uv:
uv run auth0-pentest \
  --domain your-tenant.auth0.com \
  --client-id YOUR_CLIENT_ID \
  --target-app https://your-app.com \
  --phases 3 \
  --enumerate-user admin@example.com

# With Python:
auth0-pentest \
  --domain your-tenant.auth0.com \
  --client-id YOUR_CLIENT_ID \
  --target-app https://your-app.com \
  --phases 3 \
  --enumerate-user admin@example.com
```

### Example 3: Reconnaissance with Proxy

```bash
auth0-pentest \
  --domain your-tenant.auth0.com \
  --client-id YOUR_CLIENT_ID \
  --target-app https://your-app.com \
  --phases 1,2 \
  --proxy http://127.0.0.1:8080 \
  --rate-limit-delay 2.0
```

### Example 4: Custom Connection Wordlist

```bash
# Create custom wordlist
echo "Custom-DB" > connections.txt
echo "Legacy-Auth" >> connections.txt
echo "Enterprise-SSO" >> connections.txt

# Run scan
auth0-pentest \
  --domain your-tenant.auth0.com \
  --client-id YOUR_CLIENT_ID \
  --target-app https://your-app.com \
  --connection-wordlist connections.txt
```

## 🛠️ Development

### Project Structure

```
auth0-explorer/
├── src/
│   ├── __init__.py           # Package initialization
│   ├── cli.py                # Command-line interface
│   ├── config.py             # Configuration models
│   ├── scanner.py            # Main scanner orchestration
│   ├── http_client.py        # HTTP client wrapper
│   ├── report.py             # Report generation
│   └── checks/               # Security check modules
│       ├── phase1_recon.py
│       ├── phase2_discovery.py
│       ├── phase3_testing.py
│       └── phase4_attacks.py
├── docs/                     # Additional documentation
├── pyproject.toml            # Project dependencies
├── README.md                 # This file
└── LICENSE                   # License information
```

### Running Tests

```bash
# With uv:
uv pip install pytest pytest-asyncio
uv run pytest

# With standard Python:
pip install pytest pytest-asyncio
pytest
```

### Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ⚖️ Legal Disclaimer

**FOR AUTHORIZED SECURITY RESEARCH AND PENETRATION TESTING ONLY**

This tool is designed for security professionals to assess Auth0 implementations **with proper authorization**. Unauthorized testing of systems you don't own or have explicit permission to test is **illegal**.

### Usage Guidelines

✅ **Authorized Use:**
- Testing your own Auth0 tenants
- Authorized penetration testing engagements
- Security research with written permission
- Bug bounty programs that explicitly allow Auth0 testing

❌ **Prohibited Use:**
- Testing without authorization
- Unauthorized access attempts
- Malicious activities
- Violating any laws or regulations

### Responsibility

Users of this tool are solely responsible for ensuring they have proper authorization before conducting any security assessments. The authors and contributors of Auth0 Explorer assume no liability for misuse or damage caused by this tool.

### Compliance

By using this tool, you agree to:
- Obtain written authorization before testing
- Comply with all applicable laws and regulations
- Use the tool ethically and responsibly
- Report findings through responsible disclosure

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Auth0 Security Team for their comprehensive documentation
- The security research community
- E.V.A Security team
- All contributors and testers

## 👤 Author

**Bar Hajby**
- Organization: [E.V.A Security](https://github.com/EVA-Information-Security-Consluting)
- GitHub: [@EVA-Information-Security-Consluting](https://github.com/EVA-Information-Security-Consluting)

## 📞 Contact

- **Issues**: [GitHub Issues](https://github.com/EVA-Information-Security-Consluting/auth0-explorer/issues)
- **Security**: Report security vulnerabilities responsibly

---

**⚠️ Remember: Always get authorization before testing!**
