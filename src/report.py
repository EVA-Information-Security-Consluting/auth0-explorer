"""Report generation functionality"""

import json
from pathlib import Path
from datetime import datetime

from rich.console import Console
from .config import ScanReport

console = Console()


def save_json_report(report: ScanReport, output_dir: Path) -> Path:
    """
    Save scan report as JSON file.
    
    Args:
        report: Scan report to save
        output_dir: Output directory
    
    Returns:
        Path to saved report file
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = report.scan_metadata.get("target_domain", "unknown").replace(".", "_")
    filename = f"auth0_scan_{domain}_{timestamp}.json"
    
    output_file = output_dir / filename
    
    # Convert report to dict and save
    report_dict = report.dict()
    
    with open(output_file, 'w') as f:
        json.dump(report_dict, f, indent=2, default=str)
    
    console.print(f"\n[green]✓ JSON report saved:[/green] {output_file}")
    
    return output_file


def save_text_summary(report: ScanReport, output_dir: Path) -> Path:
    """
    Save a human-readable text summary.
    
    Args:
        report: Scan report to save
        output_dir: Output directory
    
    Returns:
        Path to saved summary file
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = report.scan_metadata.get("target_domain", "unknown").replace(".", "_")
    filename = f"auth0_summary_{domain}_{timestamp}.txt"
    
    output_file = output_dir / filename
    
    with open(output_file, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("AUTH0 PENETRATION TEST SUMMARY\n")
        f.write("=" * 70 + "\n\n")
        
        # Scan metadata
        f.write(f"Target Domain: {report.scan_metadata.get('target_domain')}\n")
        f.write(f"Client ID: {report.scan_metadata.get('client_id')}\n")
        f.write(f"Scan Start: {report.scan_metadata.get('scan_start')}\n")
        f.write(f"Duration: {report.scan_metadata.get('scan_duration_seconds'):.1f} seconds\n\n")
        
        # Risk summary
        f.write("-" * 70 + "\n")
        f.write("RISK SUMMARY\n")
        f.write("-" * 70 + "\n\n")
        
        risk_summary = report.risk_summary
        f.write(f"Overall Risk Level: {risk_summary.get('overall_risk')}\n\n")
        f.write(f"Critical Findings: {risk_summary.get('critical_findings', 0)}\n")
        f.write(f"High Findings: {risk_summary.get('high_findings', 0)}\n")
        f.write(f"Medium Findings: {risk_summary.get('medium_findings', 0)}\n")
        f.write(f"Low Findings: {risk_summary.get('low_findings', 0)}\n\n")
        
        # Discovered connections
        discovered = report.phase2_connections.get('discovered_connections', [])
        if discovered:
            f.write(f"Discovered Connections: {', '.join(discovered)}\n\n")
        
        # Recommendations
        recommendations = risk_summary.get('recommendations', [])
        if recommendations:
            f.write("-" * 70 + "\n")
            f.write("TOP RECOMMENDATIONS\n")
            f.write("-" * 70 + "\n\n")
            
            for i, rec in enumerate(recommendations, 1):
                f.write(f"{i}. {rec}\n")
            f.write("\n")
        
        # Detailed findings
        f.write("-" * 70 + "\n")
        f.write("DETAILED FINDINGS\n")
        f.write("-" * 70 + "\n\n")
        
        for check in report.all_checks:
            if check.vulnerable:
                f.write(f"[{check.severity}] {check.check_name}\n")
                f.write(f"  Phase: {check.phase}\n")
                if check.risk_description:
                    f.write(f"  Risk: {check.risk_description}\n")
                f.write("\n")
        
        f.write("=" * 70 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 70 + "\n")
    
    console.print(f"[green]✓ Text summary saved:[/green] {output_file}")
    
    return output_file


def generate_reports(report: ScanReport, output_dir: Path) -> tuple[Path, Path]:
    """
    Generate all report formats.
    
    Args:
        report: Scan report
        output_dir: Output directory
    
    Returns:
        Tuple of (json_path, txt_path)
    """
    json_path = save_json_report(report, output_dir)
    txt_path = save_text_summary(report, output_dir)
    
    return json_path, txt_path

