"""Phase 2: Connection Discovery Checks"""

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from ..http_client import Auth0HttpClient
from ..config import CheckResult, ScanConfig, load_connection_wordlist

console = Console()


async def check_connection_enumeration(
    client: Auth0HttpClient,
    config: ScanConfig
) -> tuple[CheckResult, list[str]]:
    """
    Check 2.1: Connection Enumeration
    
    Discovers available authentication methods by testing connection names.
    Uses optimized detection: tests one connection first to detect if password grant is enabled,
    then uses the appropriate method for the rest.
    """
    console.print("\n[bold cyan]Check 2.1:[/bold cyan] Connection Enumeration")
    
    # Load connection wordlist (includes combinations if --connections-keyword used)
    connection_wordlist = load_connection_wordlist(config)
    
    if config.connections_keyword:
        console.print(f"  [yellow]Generating combinations for:[/yellow] '{config.connections_keyword}'")
    
    console.print(f"  Testing {len(connection_wordlist)} connection names...")
    
    # OPTIMIZATION: Test first connection to detect password grant status
    console.print(f"  [dim]Detecting password grant status...[/dim]")
    password_grant_enabled = await _is_password_grant_enabled(client, config)
    
    if password_grant_enabled:
        console.print(f"  [green]✓ Password grant enabled - using fast method[/green]")
        found_connections = await _enumerate_via_password_grant(client, config, connection_wordlist)
        method_used = "password_grant"
    else:
        console.print(f"  [yellow]⚠️  Password grant disabled - using signup method (database connections only)[/yellow]")
        found_connections = await _enumerate_via_signup(client, config, connection_wordlist)
        method_used = "signup_enumeration"
    
    console.print(f"\n  [bold]Found {len(found_connections)} connection(s)[/bold]")
    
    details = {
        "found_connections": found_connections,
        "total_tested": len(connection_wordlist),
        "method_used": method_used,
        "password_grant_enabled": password_grant_enabled,
    }
    
    if config.connections_keyword:
        details["used_combinations_for"] = config.connections_keyword
    
    return (
        CheckResult(
            check_id="2.1",
            check_name="Connection Enumeration",
            phase="Phase 2: Connection Discovery",
            severity="MEDIUM",
            vulnerable=len(found_connections) > 0,
            details=details,
            risk_description=f"Discovered {len(found_connections)} authentication connection(s)"
        ),
        found_connections
    )


async def _is_password_grant_enabled(
    client: Auth0HttpClient,
    config: ScanConfig
) -> bool:
    """
    Quick check to see if password grant is enabled.
    Tests with a common connection name.
    
    Returns:
        True if password grant is enabled, False otherwise
    """
    try:
        response = await client.post(
            "/oauth/token",
            json={
                "client_id": config.client_id,
                "connection": "Username-Password-Authentication",
                "grant_type": "password",
                "username": "test@test.com",
                "password": "dummy_password_123",
            }
        )
        
        try:
            body = response.json()
            error_description = body.get("error_description", "").lower()
            
            # If we get "grant type not allowed", password grant is disabled
            if "grant type" in error_description and "not allowed" in error_description:
                return False
            
            # Any other error (including "wrong credentials" or "connection not found") means it's enabled
            return True
        
        except ValueError:
            # Non-JSON response, assume enabled
            return True
    
    except Exception:
        # On error, assume enabled (will fallback if needed)
        return True


async def _enumerate_via_password_grant(
    client: Auth0HttpClient,
    config: ScanConfig,
    connection_wordlist: list[str]
) -> list[str]:
    """
    Enumerate connections using the password grant method.
    This works for ALL connection types (database, social, enterprise).
    """
    found_connections = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("  Testing via password grant...", total=len(connection_wordlist))
        
        for connection_name in connection_wordlist:
            try:
                response = await client.post(
                    "/oauth/token",
                    json={
                        "client_id": config.client_id,
                        "connection": connection_name,
                        "grant_type": "password",
                        "username": "test@test.com",
                        "password": "dummy_password_123",
                    }
                )
                
                try:
                    body = response.json()
                    error = body.get("error", "")
                    error_description = body.get("error_description", "").lower()
                    
                    # Connection exists if we get "wrong credentials" error
                    if "invalid_grant" in error or "wrong" in error_description or "incorrect" in error_description:
                        found_connections.append(connection_name)
                        console.print(f"  [green]✓ Found:[/green] {connection_name}")
                
                except ValueError:
                    pass
            
            except Exception:
                pass  # Silently skip errors
            
            progress.update(task, advance=1)
    
    return found_connections


async def _enumerate_via_signup(
    client: Auth0HttpClient,
    config: ScanConfig,
    connection_wordlist: list[str]
) -> list[str]:
    """
    Alternative enumeration method using the signup endpoint.
    
    Tests if connections exist by attempting signup with a dummy email.
    Database connections will respond differently than non-existent ones.
    
    Detection logic:
    - 404 + "connection not found" = Connection doesn't exist
    - 400 + any error = Connection exists (signup might be disabled/misconfigured)
    - 200 + success = Connection exists
    """
    found_connections = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("  Testing signup endpoint...", total=len(connection_wordlist))
        
        for connection_name in connection_wordlist:
            try:
                response = await client.post(
                    "/dbconnections/signup",
                    json={
                        "client_id": config.client_id,
                        "email": "enumtest@test.com",
                        "password": "TestPassword123!",
                        "connection": connection_name,
                    }
                )
                
                # Check status code first
                if response.status_code == 404:
                    # Connection doesn't exist
                    continue
                
                # Any other status code (200, 400, 403) means connection exists
                try:
                    body = response.json()
                    error = body.get("error", "").lower()
                    
                    # 404 with "connection not found" means it doesn't exist
                    if "connection" in error and "not found" in error:
                        continue
                    
                    # Any other response means connection exists
                    found_connections.append(connection_name)
                    console.print(f"  [green]✓ Found:[/green] {connection_name}")
                
                except ValueError:
                    # Non-JSON response with non-404 status = connection exists
                    found_connections.append(connection_name)
                    console.print(f"  [green]✓ Found:[/green] {connection_name}")
            
            except Exception as e:
                pass  # Silently skip errors in alternative method
            
            progress.update(task, advance=1)
    
    return found_connections


async def run_phase2_checks(
    client: Auth0HttpClient,
    config: ScanConfig
) -> tuple[list[CheckResult], list[str]]:
    """
    Run all Phase 2 connection discovery checks.
    
    Returns:
        Tuple of (check_results, discovered_connections)
    """
    console.print("\n[bold magenta]═══ PHASE 2: CONNECTION DISCOVERY ═══[/bold magenta]")
    
    results = []
    
    # Check 2.1: Connection Enumeration
    result, discovered_connections = await check_connection_enumeration(client, config)
    results.append(result)
    
    return results, discovered_connections

