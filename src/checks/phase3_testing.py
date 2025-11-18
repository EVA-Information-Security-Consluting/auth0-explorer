"""Phase 3: Per-Connection Testing Checks"""

import time
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from ..http_client import Auth0HttpClient
from ..config import CheckResult, ScanConfig

console = Console()


async def check_username_enumeration(
    client: Auth0HttpClient,
    config: ScanConfig,
    connection: str
) -> CheckResult:
    """
    Check 3.1: Username Enumeration - Signup Method
    
    Tests if username enumeration is possible via the signup endpoint.
    If --enumerate-user is provided, tests that specific email.
    Otherwise, skips the check.
    """
    console.print(f"\n[bold cyan]Check 3.1:[/bold cyan] Username Enumeration ({connection})")
    
    # Skip if no email provided
    if not config.enumerate_user:
        console.print(f"  [dim]Skipped (use --enumerate-user to test specific email)[/dim]")
        return CheckResult(
            check_id="3.1",
            check_name=f"Username Enumeration - {connection}",
            phase="Phase 3: Per-Connection Testing",
            severity="MEDIUM",
            vulnerable=False,
            details={"skipped": True, "reason": "No --enumerate-user provided"},
        )
    
    test_email = config.enumerate_user
    console.print(f"  Testing email: {test_email}")
    
    try:
        response = await client.post(
            "/dbconnections/signup",
            json={
                "client_id": config.client_id,
                "email": test_email,
                "password": "TestPassword123!",
                "connection": connection,
            }
        )
        
        try:
            body = response.json()
            message = body.get("message", "").lower()
            
            # Check if signup disabled
            if response.status_code == 403 and "signup is disabled" in message:
                console.print(f"  [green]✓ Signup is disabled (enumeration not possible via signup)[/green]")
                return CheckResult(
                    check_id="3.1",
                    check_name=f"Username Enumeration - {connection}",
                    phase="Phase 3: Per-Connection Testing",
                    severity="MEDIUM",
                    vulnerable=False,
                    details={"signup_disabled": True, "enumeration_possible": False, "tested_email": test_email},
                )
            
            # Check response for enumeration indicators
            if response.status_code == 400 and "already exists" in message:
                console.print(f"  [red]🔴 USER EXISTS:[/red] {test_email}")
                vulnerable = True
                risk_description = f"User exists: {test_email}"
            elif "_id" in body:
                console.print(f"  [green]✓ User does NOT exist[/green]")
                console.print(f"  [dim]   Created test account: {test_email}[/dim]")
                vulnerable = False
                risk_description = None
            else:
                console.print(f"  [green]✓ User does NOT exist (or enumeration not possible)[/green]")
                vulnerable = False
                risk_description = None
            
            return CheckResult(
                check_id="3.1",
                check_name=f"Username Enumeration - {connection}",
                phase="Phase 3: Per-Connection Testing",
                severity="MEDIUM",
                vulnerable=vulnerable,
                details={
                    "tested_email": test_email,
                    "response_code": response.status_code,
                    "signup_disabled": False,
                    "user_exists": vulnerable,
                },
                risk_description=risk_description,
            )
        
        except ValueError:
            pass
    
    except Exception as e:
        console.print(f"  [red]Error:[/red] {e}")
    
    return CheckResult(
        check_id="3.1",
        check_name=f"Username Enumeration - {connection}",
        phase="Phase 3: Per-Connection Testing",
        severity="MEDIUM",
        vulnerable=False,
        details={"error": "Could not test enumeration", "tested_email": test_email},
    )


async def check_password_policy(
    client: Auth0HttpClient,
    config: ScanConfig,
    connection: str
) -> CheckResult:
    """
    Check 3.2: Password Policy Discovery
    
    Determines password complexity requirements.
    """
    console.print(f"\n[bold cyan]Check 3.2:[/bold cyan] Password Policy Discovery ({connection})")
    
    test_passwords = [
        ("a", "too_short_1"),
        ("password", "no_numbers"),
        ("password1", "no_uppercase"),
        ("Password1", "no_special"),
        ("Pass1!", "short_all"),
        ("Password1!", "fair_minimum"),
        ("Pass123456789!", "excellent_minimum"),
    ]
    
    weakest_accepted = None
    policy_level = "UNKNOWN"
    
    for password, label in test_passwords:
        test_email = f"policy_test_{int(time.time())}_{label}@test.com"
        
        try:
            response = await client.post(
                "/dbconnections/signup",
                json={
                    "client_id": config.client_id,
                    "email": test_email,
                    "password": password,
                    "connection": connection,
                }
            )
            
            try:
                body = response.json()
                
                # Password rejected as too weak
                if "password" in body.get("message", "").lower() and "weak" in body.get("message", "").lower():
                    console.print(f"  [green]✓ Rejected:[/green] '{password}' (too weak)")
                    break  # Found the minimum policy
                
                # Password accepted
                elif "_id" in body:
                    weakest_accepted = password
                    policy_label = label
                    console.print(f"  [yellow]⚠️  Accepted:[/yellow] '{password}' ({label})")
                    
                    # Mark for cleanup
                    if config.cleanup_test_accounts:
                        # We'd need to delete this, but that requires Management API
                        pass
                
                # Signup disabled
                elif response.status_code == 403:
                    console.print(f"  [yellow]⚠️  Signup disabled, cannot test policy[/yellow]")
                    return CheckResult(
                        check_id="3.2",
                        check_name=f"Password Policy - {connection}",
                        phase="Phase 3: Per-Connection Testing",
                        severity="INFO",
                        vulnerable=False,
                        details={"skipped": True, "reason": "Signup disabled"},
                    )
            
            except ValueError:
                pass
        
        except Exception as e:
            console.print(f"  [red]Error:[/red] {e}")
            break
    
    # Classify policy level
    if weakest_accepted:
        if "no_numbers" in policy_label or "too_short" in policy_label:
            policy_level = "LOW"
        elif "no_uppercase" in policy_label or "no_special" in policy_label:
            policy_level = "FAIR"
        elif "fair_minimum" in policy_label:
            policy_level = "GOOD"
        else:
            policy_level = "EXCELLENT"
    else:
        policy_level = "GOOD"  # Rejected weak passwords
    
    vulnerable = policy_level in ["LOW", "FAIR"]
    
    console.print(f"\n  [bold]Password Policy:[/bold] {policy_level}")
    
    return CheckResult(
        check_id="3.2",
        check_name=f"Password Policy - {connection}",
        phase="Phase 3: Per-Connection Testing",
        severity="INFO",
        vulnerable=vulnerable,
        details={
            "password_policy": policy_level,
            "weakest_accepted": weakest_accepted,
        },
        risk_description=f"Weak password policy: {policy_level}" if vulnerable else None,
    )


async def check_public_signup(
    client: Auth0HttpClient,
    config: ScanConfig,
    connection: str
) -> CheckResult:
    """
    Check 3.3: Public Signup Misconfiguration
    
    Tests if public registration is accessible when not intended.
    """
    console.print(f"\n[bold cyan]Check 3.3:[/bold cyan] Public Signup Misconfiguration ({connection})")
    
    test_email = f"signup_test_{int(time.time())}@test.com"
    
    try:
        response = await client.post(
            "/dbconnections/signup",
            json={
                "client_id": config.client_id,
                "email": test_email,
                "password": "TestPassword123!",
                "connection": connection,
            }
        )
        
        try:
            body = response.json()
            
            # Signup disabled (GOOD)
            if response.status_code == 403 and "signup is disabled" in body.get("message", "").lower():
                console.print(f"  [green]✓ Public signup is disabled[/green]")
                return CheckResult(
                    check_id="3.3",
                    check_name=f"Public Signup - {connection}",
                    phase="Phase 3: Per-Connection Testing",
                    severity="HIGH",
                    vulnerable=False,
                    details={"public_signup_enabled": False},
                )
            
            # Signup enabled (BAD)
            elif "_id" in body:
                console.print(f"  [red]🔴 Public signup is ENABLED[/red]")
                console.print(f"  [red]   Created test account: {test_email}[/red]")
                
                return CheckResult(
                    check_id="3.3",
                    check_name=f"Public Signup - {connection}",
                    phase="Phase 3: Per-Connection Testing",
                    severity="HIGH",
                    vulnerable=True,
                    details={
                        "public_signup_enabled": True,
                        "test_account_created": test_email,
                        "test_account_id": body.get("_id"),
                    },
                    risk_description="Public signup is enabled - anyone can create accounts",
                )
        
        except ValueError:
            pass
    
    except Exception as e:
        console.print(f"  [red]Error:[/red] {e}")
    
    return CheckResult(
        check_id="3.3",
        check_name=f"Public Signup - {connection}",
        phase="Phase 3: Per-Connection Testing",
        severity="HIGH",
        vulnerable=False,
        details={"error": "Could not determine signup status"},
    )


async def run_phase3_checks_for_connection(
    client: Auth0HttpClient,
    config: ScanConfig,
    connection: str
) -> list[CheckResult]:
    """Run all Phase 3 checks for a specific connection"""
    
    console.print(f"\n[bold magenta]═══ Testing Connection: {connection} ═══[/bold magenta]")
    
    results = []
    
    # Check 3.1: Username Enumeration
    result = await check_username_enumeration(client, config, connection)
    results.append(result)
    
    # Check 3.2: Password Policy Discovery
    result = await check_password_policy(client, config, connection)
    results.append(result)
    
    # Check 3.3: Public Signup Misconfiguration
    result = await check_public_signup(client, config, connection)
    results.append(result)
    
    return results


async def run_phase3_checks(
    client: Auth0HttpClient,
    config: ScanConfig,
    discovered_connections: list[str]
) -> list[CheckResult]:
    """Run all Phase 3 per-connection testing checks"""
    
    console.print("\n[bold magenta]═══ PHASE 3: PER-CONNECTION TESTING ═══[/bold magenta]")
    
    if not discovered_connections:
        console.print("[yellow]⚠️  No connections discovered, skipping Phase 3[/yellow]")
        return []
    
    all_results = []
    
    for connection in discovered_connections:
        results = await run_phase3_checks_for_connection(client, config, connection)
        all_results.extend(results)
    
    return all_results

