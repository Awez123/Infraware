"""
enhanced_scan.py
Enhanced scanning command that integrates all security features.
"""

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from typing_extensions import Annotated
from typing import Optional
import json
from datetime import datetime
from pathlib import Path

from ..utils.file_handler import load_rules_from_directory, load_ignores_from_directory
from ..utils.vulnerability_scanner import EnhancedVulnerabilityScanner, SeverityLevel
from ..utils.secret_scanner import EnhancedSecretScanner
from ..utils.license_scanner import LicenseScanner
from ..utils.dependency_scanner import EnhancedDependencyScanner
from ..utils.sbom_generator import EnhancedSBOMGenerator

app = typer.Typer()
console = Console()

@app.command("comprehensive")
def comprehensive_scan(
    target: Annotated[str, typer.Argument(help="Path to file or directory to scan")],
    rules_dir: Annotated[str, typer.Option("--rules-dir", help="Path to the directory containing YAML rule files.")] = "rules",
    ignore_dir: Annotated[str, typer.Option("--ignore-dir", help="Path to a directory containing ignore files.")] = None,
    output_format: Annotated[str, typer.Option("--format", help="Output format (table, json, csv)")] = "table",
    include_secrets: Annotated[bool, typer.Option("--secrets", help="Include secret scanning")] = True,
    include_licenses: Annotated[bool, typer.Option("--licenses", help="Include license scanning")] = True,
    include_dependencies: Annotated[bool, typer.Option("--dependencies", help="Include dependency scanning")] = True,
    generate_sbom: Annotated[bool, typer.Option("--sbom", help="Generate SBOM")] = False,
    sbom_format: Annotated[str, typer.Option("--sbom-format", help="SBOM format (cyclone_dx, spdx)")] = "cyclone_dx",
    output_file: Annotated[str, typer.Option("--output", help="Output file path")] = None,
    min_severity: Annotated[float, typer.Option("--min-severity", help="Minimum severity score to report (0.0-10.0)")] = 0.0,
    show_remediation: Annotated[bool, typer.Option("--remediation", help="Show remediation details")] = False
):
    """
    Comprehensive security scan including vulnerabilities, secrets, licenses, and dependencies.
    """
    console.print(f"🔍 Starting comprehensive scan: [cyan]{target}[/cyan]")
    
    target_path = Path(target)
    if not target_path.exists():
        console.print(f"[red]Error: Target not found: {target}[/red]")
        raise typer.Exit(1)
    
    scan_results = {
        'metadata': {
            'scan_timestamp': datetime.now().isoformat(),
            'target': str(target_path),
            'scan_type': 'comprehensive'
        },
        'vulnerabilities': {},
        'secrets': {},
        'licenses': {},
        'dependencies': {},
        'sbom': {}
    }
    
    # 1. Traditional vulnerability scanning (if target is a plan file)
    if target_path.is_file() and target_path.suffix == '.json':
        console.print("📋 Scanning infrastructure vulnerabilities...")
        scan_results['vulnerabilities'] = _scan_infrastructure_vulnerabilities(
            str(target_path), rules_dir, ignore_dir, min_severity
        )
    
    # 2. Secret scanning
    if include_secrets:
        console.print("🔐 Scanning for secrets...")
        scan_results['secrets'] = _scan_secrets(str(target_path))
    
    # 3. License scanning
    if include_licenses:
        console.print("📜 Scanning licenses...")
        scan_results['licenses'] = _scan_licenses(str(target_path))
    
    # 4. Dependency scanning
    if include_dependencies:
        console.print("📦 Scanning dependencies...")
        scan_results['dependencies'] = _scan_dependencies(str(target_path))
    
    # 5. SBOM generation
    if generate_sbom:
        console.print("📊 Generating SBOM...")
        scan_results['sbom'] = _generate_sbom(str(target_path), sbom_format)
    
    # Display results
    if output_format.lower() == "json":
        output = json.dumps(scan_results, indent=2)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            console.print(f"✅ Results saved to {output_file}")
        else:
            console.print_json(data=scan_results)
    else:
        _display_comprehensive_results(scan_results, show_remediation)
        if output_file:
            # Save JSON version to file
            with open(output_file, 'w') as f:
                json.dump(scan_results, f, indent=2)
            console.print(f"✅ Results saved to {output_file}")

@app.command("secrets")
def scan_secrets(
    target: Annotated[str, typer.Argument(help="Path to file or directory to scan")],
    output_format: Annotated[str, typer.Option("--format", help="Output format (table, json)")] = "table",
    min_entropy: Annotated[float, typer.Option("--min-entropy", help="Minimum entropy for detection")] = 4.5,
    include_entropy: Annotated[bool, typer.Option("--entropy", help="Include entropy-based detection")] = True,
    output_file: Annotated[str, typer.Option("--output", help="Output file path")] = None
):
    """Scan for hardcoded secrets and high-entropy strings."""
    console.print(f"🔐 Scanning for secrets: [cyan]{target}[/cyan]")
    
    scanner = EnhancedSecretScanner()
    
    if Path(target).is_file():
        if include_entropy:
            findings = scanner.scan_with_entropy(
                open(target, 'r', encoding='utf-8', errors='ignore').read(),
                target, min_entropy
            )
        else:
            findings = scanner.scan_file(target)
    else:
        findings = scanner.scan_directory(target)
    
    report = scanner.generate_report(findings)
    
    if output_format.lower() == "json":
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            console.print(f"✅ Results saved to {output_file}")
        else:
            console.print_json(data=report)
    else:
        _display_secret_results(report)

@app.command("licenses")
def scan_licenses(
    target: Annotated[str, typer.Argument(help="Path to directory to scan")],
    output_format: Annotated[str, typer.Option("--format", help="Output format (table, json)")] = "table",
    policy_file: Annotated[str, typer.Option("--policy", help="License policy configuration file")] = None,
    output_file: Annotated[str, typer.Option("--output", help="Output file path")] = None
):
    """Scan for license compliance issues."""
    console.print(f"📜 Scanning licenses: [cyan]{target}[/cyan]")
    
    # Load policy if provided
    policy = None
    if policy_file:
        try:
            with open(policy_file, 'r') as f:
                policy = json.load(f)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load policy file: {e}[/yellow]")
    
    scanner = LicenseScanner(policy)
    findings = scanner.scan_directory(target)
    report = scanner.generate_compliance_report(findings)
    
    if output_format.lower() == "json":
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            console.print(f"✅ Results saved to {output_file}")
        else:
            console.print_json(data=report)
    else:
        _display_license_results(report)

@app.command("dependencies")
def scan_dependencies(
    target: Annotated[str, typer.Argument(help="Path to directory to scan")],
    output_format: Annotated[str, typer.Option("--format", help="Output format (table, json)")] = "table",
    include_licenses: Annotated[bool, typer.Option("--include-licenses", help="Include license analysis")] = True,
    output_file: Annotated[str, typer.Option("--output", help="Output file path")] = None
):
    """Scan dependencies for vulnerabilities."""
    console.print(f"📦 Scanning dependencies: [cyan]{target}[/cyan]")
    
    if include_licenses:
        scanner = EnhancedDependencyScanner()
        report = scanner.scan_with_full_analysis(target)
    else:
        scanner = EnhancedDependencyScanner()
        report = {'dependencies': scanner.scan_directory(target)}
    
    if output_format.lower() == "json":
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            console.print(f"✅ Results saved to {output_file}")
        else:
            console.print_json(data=report)
    else:
        _display_dependency_results(report)

@app.command("sbom")
def generate_sbom_command(
    target: Annotated[str, typer.Argument(help="Path to directory to scan")],
    format_type: Annotated[str, typer.Option("--format", help="SBOM format (cyclone_dx, spdx)")] = "cyclone_dx",
    output_format: Annotated[str, typer.Option("--output-format", help="Output format (json, xml)")] = "json",
    output_file: Annotated[str, typer.Option("--output", help="Output file path")] = None,
    include_vulns: Annotated[bool, typer.Option("--include-vulns", help="Include vulnerability data")] = False
):
    """Generate Software Bill of Materials (SBOM)."""
    console.print(f"📊 Generating SBOM: [cyan]{target}[/cyan]")
    
    generator = EnhancedSBOMGenerator()
    
    # Scan for components
    generator.scan_directory_for_sbom(target)
    
    # Include vulnerabilities if requested
    if include_vulns:
        # This would integrate with vulnerability scanning results
        console.print("🔍 Including vulnerability data...")
        # Implementation would correlate vulnerabilities with components
    
    # Generate SBOM
    if format_type.lower() == 'cyclone_dx':
        sbom_content = generator.generate_cyclone_dx(output_format)
    elif format_type.lower() == 'spdx':
        sbom_content = generator.generate_spdx(output_format)
    else:
        console.print(f"[red]Error: Unsupported format: {format_type}[/red]")
        raise typer.Exit(1)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(sbom_content)
        console.print(f"✅ SBOM saved to {output_file}")
    else:
        console.print(sbom_content)

def _scan_infrastructure_vulnerabilities(plan_file: str, rules_dir: str, ignore_dir: str, min_severity: float) -> dict:
    """Scan infrastructure for vulnerabilities."""
    # Load rules and ignores
    rules = load_rules_from_directory(rules_dir)
    ignored_findings = []
    if ignore_dir:
        ignored_findings = load_ignores_from_directory(ignore_dir)

    # Load plan file
    try:
        with open(plan_file, 'r') as f: 
            plan_data = json.load(f)
    except Exception as e:
        return {"error": f"Error reading plan file: {e}"}

    # Initialize scanner
    scanner = EnhancedVulnerabilityScanner()
    
    # Perform scan
    scan_results = scanner.scan_resources(plan_data, rules, ignored_findings)
    scan_results['metadata']['scan_timestamp'] = datetime.now().isoformat()
    scan_results['metadata']['rules_applied'] = len(rules)
    scan_results['metadata']['resources_scanned'] = len(plan_data.get('planned_values', {}).get('root_module', {}).get('resources', []))

    # Apply severity filter
    if min_severity > 0.0:
        filtered_vulns = [v for v in scanner.vulnerabilities_found if v.severity_score >= min_severity]
        scan_results['vulnerabilities'] = [v.to_dict() for v in filtered_vulns]
        scan_results['summary']['total_vulnerabilities'] = len(filtered_vulns)

    return scan_results

def _scan_secrets(target: str) -> dict:
    """Scan for secrets."""
    scanner = EnhancedSecretScanner()
    
    if Path(target).is_file():
        findings = scanner.scan_file(target)
    else:
        findings = scanner.scan_directory(target)
    
    return scanner.generate_report(findings)

def _scan_licenses(target: str) -> dict:
    """Scan for license compliance."""
    scanner = LicenseScanner()
    findings = scanner.scan_directory(target)
    return scanner.generate_compliance_report(findings)

def _scan_dependencies(target: str) -> dict:
    """Scan dependencies."""
    scanner = EnhancedDependencyScanner()
    return scanner.scan_with_full_analysis(target)

def _generate_sbom(target: str, format_type: str) -> dict:
    """Generate SBOM."""
    generator = EnhancedSBOMGenerator()
    return generator.scan_directory_for_sbom(target)

def _display_comprehensive_results(results: dict, show_remediation: bool):
    """Display comprehensive scan results."""
    console.print("\\n[bold green]🛡️ Comprehensive Security Scan Results[/bold green]")
    
    # Summary panel
    metadata = results.get('metadata', {})
    console.print(f"\\n📊 [bold]Scan Summary[/bold]")
    console.print(f"Target: [cyan]{metadata.get('target', 'unknown')}[/cyan]")
    console.print(f"Timestamp: [cyan]{metadata.get('scan_timestamp', 'unknown')}[/cyan]")
    
    # Vulnerabilities
    vuln_data = results.get('vulnerabilities', {})
    if vuln_data:
        vuln_summary = vuln_data.get('summary', {})
        console.print(f"\\n🚨 [bold]Infrastructure Vulnerabilities: {vuln_summary.get('total_vulnerabilities', 0)}[/bold]")
        if vuln_summary.get('total_vulnerabilities', 0) > 0:
            console.print(f"Risk Score: [red]{vuln_summary.get('risk_score', 0)}[/red]")
    
    # Secrets
    secret_data = results.get('secrets', {})
    if secret_data:
        secret_summary = secret_data.get('summary', {})
        console.print(f"\\n🔐 [bold]Secrets Found: {secret_summary.get('total_secrets', 0)}[/bold]")
        if secret_summary.get('total_secrets', 0) > 0:
            console.print(f"Risk Score: [red]{secret_summary.get('risk_score', 0)}[/red]")
    
    # Licenses
    license_data = results.get('licenses', {})
    if license_data:
        license_summary = license_data.get('summary', {})
        console.print(f"\\n📜 [bold]License Issues: {license_summary.get('violations', 0)}[/bold]")
        console.print(f"Compliance Score: [green]{license_summary.get('compliance_score', 0)}%[/green]")
    
    # Dependencies
    dep_data = results.get('dependencies', {})
    if dep_data:
        dep_summary = dep_data.get('dependencies', {}).get('summary', {})
        console.print(f"\\n📦 [bold]Vulnerable Dependencies: {dep_summary.get('vulnerable_dependencies', 0)}[/bold]")
        console.print(f"Total Dependencies: [cyan]{dep_summary.get('total_dependencies', 0)}[/cyan]")

def _display_secret_results(report: dict):
    """Display secret scan results."""
    summary = report.get('summary', {})
    findings = report.get('findings', [])
    
    console.print(f"\\n[bold green]🔐 Secret Scan Results[/bold green]")
    console.print(f"Total Secrets Found: [red]{summary.get('total_secrets', 0)}[/red]")
    console.print(f"Risk Score: [red]{summary.get('risk_score', 0)}[/red]")
    
    if findings:
        table = Table(title="🚨 Secrets Found", box=box.ROUNDED)
        table.add_column("Type", style="cyan")
        table.add_column("Severity", style="bold")
        table.add_column("File", style="magenta")
        table.add_column("Line", style="yellow")
        table.add_column("Context", style="white")
        
        for finding in findings[:10]:  # Show first 10
            table.add_row(
                finding.get('type', 'unknown'),
                finding.get('severity', 'unknown'),
                finding.get('file_path', 'unknown'),
                str(finding.get('line_number', 0)),
                finding.get('context', '')[:50] + "..." if len(finding.get('context', '')) > 50 else finding.get('context', '')
            )
        
        console.print(table)
        
        if len(findings) > 10:
            console.print(f"\\n[yellow]... and {len(findings) - 10} more findings[/yellow]")

def _display_license_results(report: dict):
    """Display license scan results."""
    summary = report.get('summary', {})
    violations = report.get('violations', [])
    
    console.print(f"\\n[bold green]📜 License Compliance Results[/bold green]")
    console.print(f"Compliance Score: [green]{summary.get('compliance_score', 0)}%[/green]")
    console.print(f"Total Packages: [cyan]{summary.get('total_packages', 0)}[/cyan]")
    console.print(f"Violations: [red]{len(violations)}[/red]")
    
    if violations:
        table = Table(title="⚠️ License Violations", box=box.ROUNDED)
        table.add_column("Type", style="cyan")
        table.add_column("Package", style="magenta")
        table.add_column("License", style="yellow")
        table.add_column("Severity", style="bold")
        
        for violation in violations:
            severity_color = "red" if violation.get('severity') == 'HIGH' else "yellow"
            table.add_row(
                violation.get('type', 'unknown'),
                violation.get('package', 'unknown'),
                violation.get('license', 'unknown'),
                f"[{severity_color}]{violation.get('severity', 'unknown')}[/{severity_color}]"
            )
        
        console.print(table)

def _display_dependency_results(report: dict):
    """Display dependency scan results."""
    dep_data = report.get('dependencies', {})
    summary = dep_data.get('summary', {})
    vulnerable_deps = dep_data.get('vulnerable_dependencies', [])
    
    console.print(f"\\n[bold green]📦 Dependency Scan Results[/bold green]")
    console.print(f"Total Dependencies: [cyan]{summary.get('total_dependencies', 0)}[/cyan]")
    console.print(f"Vulnerable Dependencies: [red]{summary.get('vulnerable_dependencies', 0)}[/red]")
    console.print(f"Risk Score: [red]{summary.get('risk_score', 0)}[/red]")
    
    if vulnerable_deps:
        table = Table(title="⚠️ Vulnerable Dependencies", box=box.ROUNDED)
        table.add_column("Package", style="cyan")
        table.add_column("Version", style="magenta")
        table.add_column("Ecosystem", style="green")
        table.add_column("Vulnerabilities", style="red")
        table.add_column("Highest Severity", style="bold")
        
        for dep in vulnerable_deps[:10]:  # Show first 10
            vulns = dep.get('vulnerabilities', [])
            highest_severity = max([v.get('severity', 'LOW') for v in vulns], default='LOW')
            
            severity_color = {
                'CRITICAL': 'red',
                'HIGH': 'orange3',
                'MEDIUM': 'yellow',
                'LOW': 'blue'
            }.get(highest_severity, 'white')
            
            table.add_row(
                dep.get('name', 'unknown'),
                dep.get('version', 'unknown'),
                dep.get('ecosystem', 'unknown'),
                str(len(vulns)),
                f"[{severity_color}]{highest_severity}[/{severity_color}]"
            )
        
        console.print(table)
        
        if len(vulnerable_deps) > 10:
            console.print(f"\\n[yellow]... and {len(vulnerable_deps) - 10} more vulnerable dependencies[/yellow]")