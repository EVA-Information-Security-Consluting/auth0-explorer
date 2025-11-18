"""Main scanner orchestration"""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from .config import ScanConfig, ScanReport, CheckResult
from .http_client import Auth0HttpClient
from .checks.phase1_recon import run_phase1_checks
from .checks.phase2_discovery import run_phase2_checks
from .checks.phase3_testing import run_phase3_checks

console = Console()


class Auth0Scanner:
    """Main scanner that orchestrates all security checks"""
    
    def __init__(self, config: ScanConfig):
        """
        Initialize scanner with configuration.
        
        Args:
            config: Scanner configuration
        """
        self.config = config
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.discovered_connections: list[str] = []
        self.all_check_results: list[CheckResult] = []
    
    async def run(self) -> ScanReport:
        """
        Execute the full scan.
        
        Returns:
            ScanReport with all results
        """
        self.start_time = datetime.now()
        
        console.print("\n[bold green]═══════════════════════════════════════════════[/bold green]")
        console.print("[bold green]   Auth0 Explorer v1.0                         [/bold green]")
        console.print("[bold green]═══════════════════════════════════════════════[/bold green]\n")
        
        console.print(f"[bold]Target Domain:[/bold] {self.config.domain}")
        console.print(f"[bold]Client ID:[/bold] {self.config.client_id}")
        console.print(f"[bold]Target App:[/bold] {self.config.target_app_url}")
        
        # Determine which phases to run
        phases_to_run = self._get_phases_to_run()
        console.print(f"[bold]Phases:[/bold] {', '.join(map(str, phases_to_run))}\n")
        
        # Initialize HTTP client
        client = Auth0HttpClient(
            domain=self.config.domain,
            rate_limit_delay=self.config.rate_limit_delay,
            proxy=self.config.proxy,
            user_agent=self.config.user_agent,
        )
        
        try:
            # Phase 1: Reconnaissance
            if 1 in phases_to_run:
                phase1_results = await run_phase1_checks(client, self.config)
                self.all_check_results.extend(phase1_results)
            
            # Phase 2: Connection Discovery
            if 2 in phases_to_run:
                phase2_results, discovered_connections = await run_phase2_checks(client, self.config)
                self.all_check_results.extend(phase2_results)
                self.discovered_connections = discovered_connections
            
            # Phase 3: Per-Connection Testing
            if 3 in phases_to_run:
                if not self.discovered_connections:
                    console.print("\n[yellow]⚠️  No connections discovered, skipping Phase 3[/yellow]")
                else:
                    phase3_results = await run_phase3_checks(
                        client, self.config, self.discovered_connections
                    )
                    self.all_check_results.extend(phase3_results)
        
        finally:
            await client.close()
        
        self.end_time = datetime.now()
        
        # Generate report
        report = self._generate_report(client)
        
        # Display summary
        self._display_summary()
        
        return report
    
    def _get_phases_to_run(self) -> list[int]:
        """Determine which phases to run based on configuration"""
        if self.config.phases:
            # Parse comma-separated phase numbers
            try:
                return sorted([int(p.strip()) for p in self.config.phases.split(",")])
            except ValueError:
                console.print("[yellow]⚠️  Invalid phases format, running all phases[/yellow]")
        
        return [1, 2, 3]  # All phases by default
    
    def _generate_report(self, client: Auth0HttpClient) -> ScanReport:
        """Generate comprehensive scan report"""
        
        duration = (self.end_time - self.start_time).total_seconds()
        
        # Organize results by phase
        phase1_results = [r for r in self.all_check_results if r.phase.startswith("Phase 1")]
        phase2_results = [r for r in self.all_check_results if r.phase.startswith("Phase 2")]
        phase3_results = [r for r in self.all_check_results if r.phase.startswith("Phase 3")]
        
        # Count findings by severity
        critical_findings = len([r for r in self.all_check_results if r.vulnerable and r.severity == "CRITICAL"])
        high_findings = len([r for r in self.all_check_results if r.vulnerable and r.severity == "HIGH"])
        medium_findings = len([r for r in self.all_check_results if r.vulnerable and r.severity == "MEDIUM"])
        low_findings = len([r for r in self.all_check_results if r.vulnerable and r.severity == "LOW"])
        
        # Determine overall risk
        if critical_findings > 0:
            overall_risk = "CRITICAL"
        elif high_findings > 0:
            overall_risk = "HIGH"
        elif medium_findings > 0:
            overall_risk = "MEDIUM"
        elif low_findings > 0:
            overall_risk = "LOW"
        else:
            overall_risk = "INFO"
        
        # Generate recommendations
        recommendations = []
        for result in self.all_check_results:
            if result.vulnerable and result.risk_description:
                recommendations.append(f"{result.severity}: {result.risk_description}")
        
        # Build report
        report = ScanReport(
            scan_metadata={
                "target_domain": self.config.domain,
                "client_id": self.config.client_id,
                "target_app_url": str(self.config.target_app_url),
                "scan_start": self.start_time.isoformat(),
                "scan_end": self.end_time.isoformat(),
                "scan_duration_seconds": duration,
                "total_requests": client.total_requests,
                "rate_limited_count": client.rate_limited_count,
                "error_count": client.error_count,
            },
            phase1_reconnaissance={
                "checks": [r.dict() for r in phase1_results]
            },
            phase2_connections={
                "discovered_connections": self.discovered_connections,
                "total_found": len(self.discovered_connections),
                "checks": [r.dict() for r in phase2_results]
            },
            phase3_per_connection={
                "checks": [r.dict() for r in phase3_results]
            },
            risk_summary={
                "overall_risk": overall_risk,
                "critical_findings": critical_findings,
                "high_findings": high_findings,
                "medium_findings": medium_findings,
                "low_findings": low_findings,
                "total_checks": len(self.all_check_results),
                "vulnerable_checks": len([r for r in self.all_check_results if r.vulnerable]),
                "recommendations": recommendations[:10],  # Top 10
            },
            all_checks=self.all_check_results,
        )
        
        return report
    
    def _display_summary(self):
        """Display scan summary in terminal"""
        
        console.print("\n[bold magenta]═══════════════════════════════════════════════[/bold magenta]")
        console.print("[bold magenta]   SCAN SUMMARY                                [/bold magenta]")
        console.print("[bold magenta]═══════════════════════════════════════════════[/bold magenta]\n")
        
        # Count findings by severity
        findings = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": [],
        }
        
        for result in self.all_check_results:
            if result.vulnerable:
                findings[result.severity].append(result)
        
        # Create summary table
        table = Table(title="Findings by Severity")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("Checks", style="dim")
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = len(findings[severity])
            if count > 0:
                check_names = ", ".join([r.check_name for r in findings[severity][:3]])
                if count > 3:
                    check_names += f", ... (+{count - 3} more)"
                
                # Color coding
                if severity == "CRITICAL":
                    table.add_row(f"[red bold]{severity}[/red bold]", f"[red]{count}[/red]", check_names)
                elif severity == "HIGH":
                    table.add_row(f"[red]{severity}[/red]", f"[red]{count}[/red]", check_names)
                elif severity == "MEDIUM":
                    table.add_row(f"[yellow]{severity}[/yellow]", f"[yellow]{count}[/yellow]", check_names)
                elif severity == "LOW":
                    table.add_row(f"[blue]{severity}[/blue]", f"[blue]{count}[/blue]", check_names)
                else:
                    table.add_row(severity, str(count), check_names)
        
        console.print(table)
        
        # Overall assessment
        total_vulnerable = sum(len(findings[s]) for s in findings)
        
        if total_vulnerable == 0:
            console.print("\n[green bold]✓ No vulnerabilities found![/green bold]")
        else:
            console.print(f"\n[yellow bold]⚠️  Found {total_vulnerable} potential issue(s)[/yellow bold]")
        
        # Discovered connections
        if self.discovered_connections:
            console.print(f"\n[bold]Discovered Connections:[/bold] {', '.join(self.discovered_connections)}")
        
        duration = (self.end_time - self.start_time).total_seconds()
        console.print(f"\n[dim]Scan completed in {duration:.1f} seconds[/dim]")

