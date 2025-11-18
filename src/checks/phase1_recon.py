"""Phase 1: Reconnaissance Checks"""

from typing import Optional
from rich.console import Console
from ..http_client import Auth0HttpClient
from ..config import CheckResult, ScanConfig

console = Console()


async def check_openid_configuration(client: Auth0HttpClient) -> CheckResult:
    """
    Check 1.1: OpenID Configuration Discovery
    
    Discovers Auth0 tenant configuration including supported grant types and algorithms.
    """
    console.print("\n[bold cyan]Check 1.1:[/bold cyan] OpenID Configuration Discovery")
    
    try:
        response = await client.get("/.well-known/openid-configuration")
        
        if response.status_code != 200:
            return CheckResult(
                check_id="1.1",
                check_name="OpenID Configuration",
                phase="Phase 1: Reconnaissance",
                severity="INFO",
                vulnerable=False,
                details={"error": f"HTTP {response.status_code}"},
            )
        
        config = response.json()
        
        # Check for issues
        password_grant_enabled = "password" in config.get("grant_types_supported", [])
        weak_algorithms = []
        
        supported_algs = config.get("id_token_signing_alg_values_supported", [])
        if "none" in supported_algs:
            weak_algorithms.append("none")
        
        # Extract key endpoints
        endpoints = {
            "authorization_endpoint": config.get("authorization_endpoint"),
            "token_endpoint": config.get("token_endpoint"),
            "userinfo_endpoint": config.get("userinfo_endpoint"),
            "jwks_uri": config.get("jwks_uri"),
        }
        
        details = {
            "issuer": config.get("issuer"),
            "password_grant_enabled": password_grant_enabled,
            "weak_algorithms": weak_algorithms,
            "grant_types_supported": config.get("grant_types_supported", []),
            "id_token_signing_alg_values_supported": supported_algs,
            "endpoints": endpoints,
        }
        
        # Determine if vulnerable
        vulnerable = password_grant_enabled or len(weak_algorithms) > 0
        
        risk_description = None
        if password_grant_enabled:
            risk_description = "Resource Owner Password Grant enabled - allows direct credential submission"
        if weak_algorithms:
            risk_description = f"Weak signing algorithms supported: {', '.join(weak_algorithms)}"
        
        if password_grant_enabled:
            console.print("  [yellow]⚠️  Password grant enabled[/yellow]")
        if weak_algorithms:
            console.print(f"  [red]🔴 Weak algorithms: {weak_algorithms}[/red]")
        if not vulnerable:
            console.print("  [green]✓ Configuration looks good[/green]")
        
        return CheckResult(
            check_id="1.1",
            check_name="OpenID Configuration",
            phase="Phase 1: Reconnaissance",
            severity="INFO",
            vulnerable=vulnerable,
            details=details,
            risk_description=risk_description,
        )
    
    except Exception as e:
        console.print(f"  [red]Error:[/red] {e}")
        return CheckResult(
            check_id="1.1",
            check_name="OpenID Configuration",
            phase="Phase 1: Reconnaissance",
            severity="INFO",
            vulnerable=False,
            details={"error": str(e)},
        )


async def check_cors_misconfiguration(client: Auth0HttpClient) -> CheckResult:
    """
    Check 1.2: CORS Misconfiguration
    
    Tests if Auth0 endpoints allow cross-origin requests from arbitrary origins.
    """
    console.print("\n[bold cyan]Check 1.2:[/bold cyan] CORS Misconfiguration")
    
    try:
        # Test OPTIONS request to token endpoint
        headers = {
            "Origin": "https://attacker.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        }
        
        response = await client.options("/oauth/token", headers=headers)
        
        # Check CORS headers
        cors_headers = {
            "Access-Control-Allow-Origin": response.headers.get("Access-Control-Allow-Origin"),
            "Access-Control-Allow-Credentials": response.headers.get("Access-Control-Allow-Credentials"),
            "Access-Control-Allow-Methods": response.headers.get("Access-Control-Allow-Methods"),
            "Access-Control-Allow-Headers": response.headers.get("Access-Control-Allow-Headers"),
        }
        
        allow_origin = cors_headers["Access-Control-Allow-Origin"]
        allow_credentials = cors_headers["Access-Control-Allow-Credentials"]
        
        # Determine vulnerability
        vulnerable = False
        risk_description = None
        
        if allow_origin == "*":
            vulnerable = True
            risk_description = "CRITICAL: Allows any origin (*)"
            console.print("  [red]🔴 CRITICAL: Access-Control-Allow-Origin: *[/red]")
        elif allow_origin == "https://attacker.com":
            vulnerable = True
            risk_description = "CRITICAL: Reflects attacker origin"
            console.print("  [red]🔴 CRITICAL: Reflects attacker origin[/red]")
        
        if allow_origin and allow_credentials == "true":
            if not vulnerable:
                vulnerable = True
            risk_description = (risk_description or "") + " + credentials allowed (session theft possible)"
            console.print("  [red]🔴 Access-Control-Allow-Credentials: true[/red]")
        
        if not vulnerable:
            console.print("  [green]✓ CORS properly configured[/green]")
        
        details = {
            "cors_headers": cors_headers,
            "allows_wildcard_origin": allow_origin == "*",
            "reflects_attacker_origin": allow_origin == "https://attacker.com",
            "allows_credentials": allow_credentials == "true",
        }
        
        return CheckResult(
            check_id="1.2",
            check_name="CORS Misconfiguration",
            phase="Phase 1: Reconnaissance",
            severity="HIGH" if vulnerable else "INFO",
            vulnerable=vulnerable,
            details=details,
            risk_description=risk_description,
        )
    
    except Exception as e:
        console.print(f"  [red]Error:[/red] {e}")
        return CheckResult(
            check_id="1.2",
            check_name="CORS Misconfiguration",
            phase="Phase 1: Reconnaissance",
            severity="HIGH",
            vulnerable=False,
            details={"error": str(e)},
        )


async def check_open_redirect(
    client: Auth0HttpClient,
    config: ScanConfig
) -> CheckResult:
    """
    Check 1.3: Open Redirect
    
    Tests redirect URI validation for open redirect vulnerabilities.
    """
    console.print("\n[bold cyan]Check 1.3:[/bold cyan] Open Redirect")
    
    test_redirects = [
        "https://attacker.com",
        "http://localhost:9999",
        f"{config.target_app_url}@attacker.com",
        f"{config.target_app_url}/../../../attacker.com",
        f"{config.target_app_url}%2f%2fattacker.com",
        f"{config.target_app_url}.attacker.com",
        "javascript:alert(1)",
    ]
    
    vulnerable_uris = []
    
    console.print(f"  Testing {len(test_redirects)} redirect URI(s)...")
    
    for redirect_uri in test_redirects:
        try:
            response = await client.get(
                "/authorize",
                params={
                    "client_id": config.client_id,
                    "response_type": "code",
                    "redirect_uri": redirect_uri,
                    "state": "test",
                    "scope": "openid",
                }
            )
            
            # Check if redirect was accepted (302/301) or if we get an error
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get("Location", "")
                
                # Check if redirecting to our malicious URI
                if "attacker.com" in location or "javascript:" in location:
                    vulnerable_uris.append(redirect_uri)
                    console.print(f"  [red]🔴 VULNERABLE:[/red] {redirect_uri}")
            
            # Sometimes Auth0 returns 200 with error in body instead of redirect
            elif response.status_code == 200:
                # This might be Universal Login page - check for error
                try:
                    body = response.json()
                    if "error" not in body:
                        # No error means might be vulnerable
                        console.print(f"  [yellow]⚠️  Unclear:[/yellow] {redirect_uri}")
                except ValueError:
                    # HTML response, probably login page
                    pass
        
        except Exception as e:
            console.print(f"  [red]Error testing {redirect_uri}:[/red] {e}")
    
    vulnerable = len(vulnerable_uris) > 0
    
    if vulnerable:
        console.print(f"\n  [red]Found {len(vulnerable_uris)} vulnerable redirect(s)[/red]")
    else:
        console.print(f"\n  [green]✓ Redirect validation is strict[/green]")
    
    return CheckResult(
        check_id="1.3",
        check_name="Open Redirect",
        phase="Phase 1: Reconnaissance",
        severity="HIGH" if vulnerable else "INFO",
        vulnerable=vulnerable,
        details={
            "vulnerable_bypasses": vulnerable_uris,
            "total_tested": len(test_redirects),
        },
        risk_description=f"Open redirect found - can steal authorization codes" if vulnerable else None,
    )


async def run_phase1_checks(client: Auth0HttpClient, config: ScanConfig) -> list[CheckResult]:
    """Run all Phase 1 reconnaissance checks"""
    console.print("\n[bold magenta]═══ PHASE 1: RECONNAISSANCE ═══[/bold magenta]")
    
    results = []
    
    # Check 1.1: OpenID Configuration
    result = await check_openid_configuration(client)
    results.append(result)
    
    # Check 1.2: CORS Misconfiguration
    result = await check_cors_misconfiguration(client)
    results.append(result)
    
    # Check 1.3: Open Redirect
    result = await check_open_redirect(client, config)
    results.append(result)
    
    return results

