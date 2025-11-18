# Auth0 Explorer - Usage Guide

## Table of Contents
- [Getting Started](#getting-started)
- [Command Reference](#command-reference)
- [Testing Phases](#testing-phases)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)

## Getting Started

### Finding Your Auth0 Credentials

Before using Auth0 Explorer, you need:

1. **Auth0 Domain**: Found in your Auth0 Dashboard → Settings → Domain
   - Format: `your-tenant.auth0.com` or `your-tenant.region.auth0.com`
   
2. **Client ID**: Found in Applications → Your Application → Settings → Client ID
   - Format: 32-character alphanumeric string

3. **Target Application URL**: The URL where your application is hosted
   - Example: `https://app.example.com`

### Basic Scan

```bash
uv run auth0-pentest \
  --domain your-tenant.auth0.com \
  --client-id YOUR_CLIENT_ID \
  --target-app https://your-app.com
```

## Command Reference

### Required Flags

```bash
--domain TEXT          Auth0 tenant domain (e.g., victim.auth0.com)
--client-id TEXT       Auth0 application client ID
--target-app TEXT      Target application URL
```

### Connection Discovery

```bash
# Use custom wordlist
--connection-wordlist PATH    Path to custom connection names file

# Generate connection variations
--connections-keyword TEXT    Generates variations like:
                              keyword, Keyword, keyword-prod, 
                              keyword-dev, prod-keyword, etc.
```

Example:
```bash
--connections-keyword Company
# Generates: Company, company, Company-Prod, company-prod,
#            CompanyAuth, company-sso, etc.
```

### User Enumeration

```bash
--enumerate-user EMAIL    Test if a specific email exists
                          Example: admin@example.com
```

### Performance Tuning

```bash
--rate-limit-delay FLOAT    Delay between requests (default: 1.0 seconds)
--workers INT               Concurrent workers (default: 5)
```

Examples:
```bash
# Aggressive scan (use carefully)
--rate-limit-delay 0.1 --workers 10

# Conservative scan
--rate-limit-delay 2.0 --workers 2
```

### Output Control

```bash
--output PATH              Output directory (default: ./output)
--cleanup / --no-cleanup   Delete test accounts (default: cleanup)
```

### Proxy & Headers

```bash
--proxy URL               HTTP proxy (e.g., http://127.0.0.1:8080)
--user-agent TEXT         Custom User-Agent header
```

### Phase Selection

```bash
--phases TEXT    Comma-separated phases:
                 1 = Recon (OpenID/redirect)
                 2 = Connections
                 3 = Per-Connection (enum/policy/signup)
```

## Testing Phases

### Phase 1: Reconnaissance

**What it does:**
- Discovers OpenID configuration
- Tests for open redirect vulnerabilities

**When to use:**
- Initial information gathering
- Understanding Auth0 setup

**Example:**
```bash
uv run auth0-pentest \
  --domain victim.auth0.com \
  --client-id abc123 \
  --target-app https://app.victim.com \
  --phases 1
```

### Phase 2: Connection Discovery

**What it does:**
- Enumerates available authentication connections
- Tests default and custom connection names
- Generates variations if `--connections-keyword` is used

**When to use:**
- After reconnaissance
- To discover hidden authentication methods

**Example:**
```bash
uv run auth0-pentest \
  --domain victim.auth0.com \
  --client-id abc123 \
  --target-app https://app.victim.com \
  --phases 2 \
  --connections-keyword MyCompany
```

### Phase 3: Per-Connection Testing

**What it does:**
- Tests username enumeration (if `--enumerate-user` provided)
- Discovers password policies
- Tests for public signup misconfiguration

**When to use:**
- After discovering connections in Phase 2
- To assess connection-specific security

**Example:**
```bash
uv run auth0-pentest \
  --domain victim.auth0.com \
  --client-id abc123 \
  --target-app https://app.victim.com \
  --phases 2,3 \
  --enumerate-user admin@victim.com
```

### Phase 4: Application Attacks

**What it does:**
- Tests for open redirect vulnerabilities

**When to use:**
- Application-level security testing
- Testing OAuth flow security

**Example:**
```bash
uv run auth0-pentest \
  --domain victim.auth0.com \
  --client-id abc123 \
  --target-app https://app.victim.com \
  --phases 4
```

## Advanced Usage

### Full Scan with All Options

```bash
uv run auth0-pentest \
  --domain your-tenant.auth0.com \
  --client-id YOUR_CLIENT_ID \
  --target-app https://your-app.com \
  --connections-keyword YourCompany \
  --enumerate-user admin@example.com \
  --output results/full-scan-$(date +%Y%m%d) \
  --rate-limit-delay 0.5 \
  --workers 8 \
  --proxy http://127.0.0.1:8080 \
  --cleanup
```

### Connection Wordlist

Create a custom wordlist for connection names:

```bash
cat > custom-connections.txt << EOF
Production-DB
Staging-Database
Legacy-Auth
Enterprise-SSO
Partner-Integration
EOF

uv run auth0-pentest \
  --domain victim.auth0.com \
  --client-id abc123 \
  --target-app https://app.victim.com \
  --connection-wordlist custom-connections.txt
```

### Testing Specific Scenarios

**Scenario 1: Quick Reconnaissance**
```bash
uv run auth0-pentest \
  --domain victim.auth0.com \
  --client-id abc123 \
  --target-app https://app.victim.com \
  --phases 1,2 \
  --rate-limit-delay 0.2
```

**Scenario 2: Focused User Enumeration**
```bash
uv run auth0-pentest \
  --domain victim.auth0.com \
  --client-id abc123 \
  --target-app https://app.victim.com \
  --phases 3 \
  --enumerate-user target@victim.com
```

**Scenario 3: Through Proxy for Analysis**
```bash
# Start Burp Suite or similar proxy on 8080
uv run auth0-pentest \
  --domain victim.auth0.com \
  --client-id abc123 \
  --target-app https://app.victim.com \
  --proxy http://127.0.0.1:8080 \
  --rate-limit-delay 2.0
```

## Troubleshooting

### Rate Limiting

**Symptom:** Many 429 errors or "rate limited" messages

**Solution:**
```bash
# Increase delay between requests
--rate-limit-delay 2.0

# Reduce concurrent workers
--workers 2
```

### Connection Not Found

**Symptom:** No connections discovered

**Solutions:**
1. Try custom keywords:
   ```bash
   --connections-keyword CompanyName
   ```

2. Use a custom wordlist with known connection patterns

3. Check if the client_id has password grant enabled:
   - The tool will automatically detect and adapt

### Test Account Creation Failed

**Symptom:** Cannot create test accounts during password policy testing

**Possible causes:**
- Signup is disabled (this is expected)
- Email domain is blocked
- Captcha is enabled

**Solution:** This is informational; the tool will skip affected tests

### Proxy Not Working

**Symptom:** Connection errors when using `--proxy`

**Solutions:**
1. Verify proxy is running:
   ```bash
   curl -x http://127.0.0.1:8080 https://google.com
   ```

2. Check proxy URL format:
   ```bash
   --proxy http://127.0.0.1:8080  # Correct
   --proxy 127.0.0.1:8080         # Incorrect
   ```

3. For HTTPS proxy:
   ```bash
   --proxy https://127.0.0.1:8080
   ```

### Output Not Generated

**Symptom:** No JSON or text reports created

**Solutions:**
1. Check output directory permissions:
   ```bash
   mkdir -p output
   chmod 755 output
   ```

2. Specify custom output directory:
   ```bash
   --output /tmp/auth0-results
   ```

## Best Practices

### 1. Start Conservative

```bash
# Begin with slow, careful scans
--rate-limit-delay 2.0 --workers 2
```

### 2. Progress Through Phases

```bash
# Phase 1: Recon
uv run auth0-pentest --domain ... --phases 1

# Phase 2: Discovery (use findings from Phase 1)
uv run auth0-pentest --domain ... --phases 2 --connections-keyword ...

# Phase 3 & 4: Testing (use connections from Phase 2)
uv run auth0-pentest --domain ... --phases 3,4
```

### 3. Document Your Testing

```bash
# Include timestamps in output directories
--output results/scan-$(date +%Y%m%d-%H%M%S)
```

### 4. Review Reports

After each scan, review:
- `auth0_scan_*.json` - Full technical details
- `auth0_summary_*.txt` - High-level findings

### 5. Responsible Testing

- Always get authorization first
- Use conservative rate limits initially
- Test during maintenance windows when possible
- Clean up test accounts (`--cleanup`)

## Need Help?

- Check the [Tool Specification](TOOL_SPECIFICATION.md) for detailed check descriptions
- Open an issue on GitHub
- Review example scans in the output directory

