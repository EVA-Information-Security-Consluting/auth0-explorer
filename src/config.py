"""Configuration and data models for Auth0 Explorer"""

from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field, HttpUrl


class ScanConfig(BaseModel):
    """Main configuration for the scanner"""
    
    # Required parameters
    domain: str = Field(..., description="Auth0 tenant domain (e.g., victim.auth0.com)")
    client_id: str = Field(..., description="Auth0 application client ID")
    target_app_url: HttpUrl = Field(..., description="Target application URL")
    
    # Optional wordlists
    connection_wordlist: Optional[Path] = Field(None, description="Path to connection names wordlist")
    
    # Connection name combination
    connections_keyword: Optional[str] = Field(
        None, 
        description="Generate connection name variations (e.g., 'google' creates google-prod, google-dev, etc.)"
    )
    
    # User enumeration
    enumerate_user: Optional[str] = Field(None, description="Email address to test for username enumeration")
    
    # Operational parameters
    output_dir: Path = Field(default=Path("./output"), description="Output directory for results")
    rate_limit_delay: float = Field(default=1.0, description="Delay between requests in seconds")
    workers: int = Field(default=5, description="Number of concurrent workers")
    proxy: Optional[str] = Field(None, description="HTTP proxy URL")
    user_agent: str = Field(
        default="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        description="Custom User-Agent header"
    )
    
    # Testing options
    cleanup_test_accounts: bool = Field(default=True, description="Delete test accounts after scan")
    
    # Phase selection
    phases: Optional[str] = Field(None, description="Comma-separated phases to run (e.g., '1,2,3')")
    
    class Config:
        arbitrary_types_allowed = True


def generate_connection_combinations(keyword: str) -> list[str]:
    """
    Generate connection name variations based on a keyword.
    
    Args:
        keyword: Base keyword to combine (e.g., 'google', 'company', 'prod')
    
    Returns:
        List of connection name variations
    
    Example:
        >>> generate_connection_combinations('google')
        ['google-oauth2', 'google-production', 'google-prod', 'google-dev', ...]
    """
    
    # Comprehensive suffixes
    suffixes = [
        # Auth methods
        "oauth2",
        "oauth",
        "oidc",
        "saml",
        "saml2",
        "SSO",
        "SAML",
        "Auth",
        "Authentication",
        "Login",
        "AD",
        "LDAP",
        "ActiveDirectory",
        "ADFS",
        "Okta",
        "Azure",
        "AzureAD",
        "Google",
        "Facebook",
        "GitHub",
        "Microsoft",
        
        # Database/Connection types
        "Database",
        "DB",
        "Connection",
        "Users",
        "Accounts",
        "Members",
        "Customers",
        "Employees",
        "Staff",
        "Admin",
        "Admins",
        
        # Environments
        "production",
        "prod",
        "prd",
        "live",
        "development",
        "dev",
        "develop",
        "staging",
        "stage",
        "stg",
        "test",
        "testing",
        "qa",
        "uat",
        "demo",
        "sandbox",
        "sbx",
        "local",
        "localhost",
        
        # Descriptors
        "internal",
        "external",
        "public",
        "private",
        "corporate",
        "enterprise",
        "business",
        "partner",
        "vendor",
        "client",
        "legacy",
        "old",
        "new",
        "v1",
        "v2",
        "v3",
        "api",
        "app",
        "web",
        "mobile",
        
        # Geographic
        "us",
        "eu",
        "uk",
        "apac",
        "global",
        "america",
        "europe",
        "asia",
        
        # Special combinations
        "Username-Password-Authentication",
        "email",
        "sms",
        "passwordless",
    ]
    
    # Comprehensive prefixes
    prefixes = [
        # Environments
        "production",
        "prod",
        "prd",
        "live",
        "development",
        "dev",
        "develop",
        "staging",
        "stage",
        "stg",
        "test",
        "testing",
        "qa",
        "uat",
        "demo",
        "sandbox",
        "sbx",
        "local",
        
        # Descriptors
        "internal",
        "external",
        "public",
        "private",
        "corporate",
        "enterprise",
        "business",
        "partner",
        "vendor",
        "client",
        "legacy",
        "old",
        "new",
        
        # Geographic
        "us",
        "eu",
        "uk",
        "apac",
        "global",
        "america",
        "europe",
        "asia",
        
        # Company-specific
        "company",
        "corp",
        "org",
        "team",
    ]
    
    combinations = []
    
    # Max length for Auth0 connection names
    MAX_LENGTH = 35
    
    # Keyword alone (if not too long)
    if len(keyword) <= MAX_LENGTH:
        combinations.append(keyword)
        combinations.append(keyword.capitalize())
        combinations.append(keyword.upper())
    
    # Keyword-Suffix patterns
    for suffix in suffixes:
        # Skip if suffix alone is too long
        if len(suffix) > MAX_LENGTH:
            continue
            
        # With dash
        combo = f"{keyword}-{suffix}"
        if len(combo) <= MAX_LENGTH:
            combinations.append(combo)
        
        combo = f"{keyword.capitalize()}-{suffix}"
        if len(combo) <= MAX_LENGTH:
            combinations.append(combo)
        
        combo = f"{keyword}-{suffix.capitalize()}"
        if len(combo) <= MAX_LENGTH:
            combinations.append(combo)
        
        combo = f"{keyword.capitalize()}-{suffix.capitalize()}"
        if len(combo) <= MAX_LENGTH:
            combinations.append(combo)
        
        # Without dash
        combo = f"{keyword}{suffix}"
        if len(combo) <= MAX_LENGTH:
            combinations.append(combo)
        
        combo = f"{keyword.capitalize()}{suffix.capitalize()}"
        if len(combo) <= MAX_LENGTH:
            combinations.append(combo)
    
    # Prefix-Keyword patterns
    for prefix in prefixes:
        # Skip if prefix alone is too long
        if len(prefix) > MAX_LENGTH:
            continue
            
        # With dash
        combo = f"{prefix}-{keyword}"
        if len(combo) <= MAX_LENGTH:
            combinations.append(combo)
        
        combo = f"{prefix.capitalize()}-{keyword}"
        if len(combo) <= MAX_LENGTH:
            combinations.append(combo)
        
        combo = f"{prefix}-{keyword.capitalize()}"
        if len(combo) <= MAX_LENGTH:
            combinations.append(combo)
        
        combo = f"{prefix.capitalize()}-{keyword.capitalize()}"
        if len(combo) <= MAX_LENGTH:
            combinations.append(combo)
        
        # Without dash
        combo = f"{prefix}{keyword}"
        if len(combo) <= MAX_LENGTH:
            combinations.append(combo)
        
        combo = f"{prefix.capitalize()}{keyword.capitalize()}"
        if len(combo) <= MAX_LENGTH:
            combinations.append(combo)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_combinations = []
    for combo in combinations:
        if combo not in seen and len(combo) <= MAX_LENGTH:
            seen.add(combo)
            unique_combinations.append(combo)
    
    return unique_combinations


def load_connection_wordlist(config: ScanConfig) -> list[str]:
    """
    Load connection names from wordlist and/or generate combinations.
    
    Always includes default wordlist, plus custom wordlist and/or combinations.
    
    Args:
        config: Scanner configuration
    
    Returns:
        List of connection names to test
    """
    connections = []
    
    # ALWAYS start with default list
    default_connections = [
        "Username-Password-Authentication",
        "email",
        "sms",
        "google-oauth2",
        "facebook",
        "github",
        "twitter",
        "linkedin",
        "windowslive",
        "apple",
        "Database-Connection",
        "Legacy-Database",
        "Corporate-AD",
        "LDAP",
    ]
    connections.extend(default_connections)
    
    # Add from custom wordlist file if provided
    if config.connection_wordlist and config.connection_wordlist.exists():
        with open(config.connection_wordlist, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    connections.append(line)
    
    # Add generated combinations if --connections-keyword provided
    if config.connections_keyword:
        generated = generate_connection_combinations(config.connections_keyword)
        connections.extend(generated)
    
    # Remove duplicates while preserving order
    return list(dict.fromkeys(connections))




# Check result models
class CheckResult(BaseModel):
    """Result of a single security check"""
    check_id: str
    check_name: str
    phase: str
    severity: str
    vulnerable: bool
    details: dict
    risk_description: Optional[str] = None


class ScanReport(BaseModel):
    """Complete scan report"""
    scan_metadata: dict
    phase1_reconnaissance: dict = {}
    phase2_connections: dict = {}
    phase3_per_connection: dict = {}
    phase4_application_attacks: dict = {}
    risk_summary: dict = {}
    all_checks: list[CheckResult] = []

