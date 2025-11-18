"""Command-line interface for Auth0 Explorer"""

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console

from . import __version__
from .config import ScanConfig
from .scanner import Auth0Scanner
from .report import generate_reports

console = Console()


@click.command()
@click.version_option(version=__version__, prog_name="auth0-pentest")
@click.option(
    "--domain",
    required=True,
    help="Auth0 tenant domain (e.g., victim.auth0.com)",
)
@click.option(
    "--client-id",
    required=True,
    help="Auth0 application client ID",
)
@click.option(
    "--target-app",
    required=True,
    help="Target application URL (e.g., https://app.victim.com)",
)
@click.option(
    "--connection-wordlist",
    type=click.Path(exists=True, path_type=Path),
    help="Path to connection names wordlist",
)
@click.option(
    "--connections-keyword",
    help="Generate connection name variations (e.g., 'google' creates google-prod, google-dev, etc.)",
)
@click.option(
    "--enumerate-user",
    help="Email address to test for username enumeration (e.g., admin@victim.com). If not provided, enumeration check is skipped.",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    default=Path("./output"),
    help="Output directory for results (default: ./output)",
)
@click.option(
    "--rate-limit-delay",
    type=float,
    default=1.0,
    help="Delay between requests in seconds (default: 1.0)",
)
@click.option(
    "--workers",
    type=int,
    default=5,
    help="Number of concurrent workers (default: 5)",
)
@click.option(
    "--proxy",
    help="HTTP proxy URL (e.g., http://127.0.0.1:8080)",
)
@click.option(
    "--user-agent",
    default="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    help="Custom User-Agent header",
)
@click.option(
    "--cleanup/--no-cleanup",
    default=True,
    help="Delete test accounts after scan (default: cleanup)",
)
@click.option(
    "--phases",
    help=(
        "Comma-separated phases to run (default: all). "
        "1=Recon (OpenID/CORS/redirect), 2=Connections, 3=Per-Connection (enum/policy/signup)"
    ),
)
def main(
    domain: str,
    client_id: str,
    target_app: str,
    connection_wordlist: Path | None,
    connections_keyword: str | None,
    enumerate_user: str | None,
    output: Path,
    rate_limit_delay: float,
    workers: int,
    proxy: str | None,
    user_agent: str,
    cleanup: bool,
    phases: str | None,
):
    """
    Auth0 Explorer v1.0
    
    Security assessment and reconnaissance tool for Auth0 implementations.
    
    Author: Bar Hajby
    Organization: E.V.A Security
    
    \b
    Examples:
      # Basic reconnaissance
      auth0-pentest --domain victim.auth0.com --client-id abc123 --target-app https://app.victim.com
      
      # Custom connection enumeration
      auth0-pentest --domain victim.auth0.com --client-id abc123 --target-app https://app.victim.com --connections-keyword mycompany
      
      # Test specific email for enumeration
      auth0-pentest --domain victim.auth0.com --client-id abc123 --target-app https://app.victim.com --enumerate-user admin@victim.com
      
      # Specific phases only
      auth0-pentest --domain victim.auth0.com --client-id abc123 --target-app https://app.victim.com --phases 1
    """
    
    try:
        # Build configuration
        config = ScanConfig(
            domain=domain,
            client_id=client_id,
            target_app_url=target_app,
            connection_wordlist=connection_wordlist,
            connections_keyword=connections_keyword,
            enumerate_user=enumerate_user,
            output_dir=output,
            rate_limit_delay=rate_limit_delay,
            workers=workers,
            proxy=proxy,
            user_agent=user_agent,
            cleanup_test_accounts=cleanup,
            phases=phases,
        )
        
        # Run scanner
        scanner = Auth0Scanner(config)
        report = asyncio.run(scanner.run())
        
        # Generate reports
        json_path, txt_path = generate_reports(report, output)
        
        console.print("\n[bold green]✓ Scan completed successfully![/bold green]")
        console.print(f"\n[bold]Reports saved to:[/bold] {output}/")
        
        # Exit with appropriate code based on findings
        if report.risk_summary.get("critical_findings", 0) > 0:
            sys.exit(2)  # Critical findings
        elif report.risk_summary.get("high_findings", 0) > 0:
            sys.exit(1)  # High findings
        else:
            sys.exit(0)  # No critical/high findings
    
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠️  Scan interrupted by user[/yellow]")
        sys.exit(130)
    
    except Exception as e:
        console.print(f"\n[red]✗ Error:[/red] {e}")
        if "--debug" in sys.argv:
            raise
        sys.exit(1)


if __name__ == "__main__":
    main()

