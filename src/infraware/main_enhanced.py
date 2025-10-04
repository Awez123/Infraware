#!/usr/bin/env python3
"""
InfraWare CLI - Enterprise-Grade Infrastructure Security Scanner
Enhanced with CVE Database and Container Security Scanning
"""

import typer
from pathlib import Path
from rich.console import Console
from typing import Optional

# Import specific commands instead of the problematic apps
from infraware.commands.scan import scan

app = typer.Typer(
    help="InfraWare: An IaC Security and Quality Scanner with CVE Database and Container Security.",
    add_completion=False
)

@app.command("welcome")
def welcome():
    """Show InfraWare branding and available commands."""
    print("""
    ██ ███   ██ ███████ ██████   █████  ██    ██  █████  ██████  ███████
    ██ ████  ██ ██      ██   ██ ██   ██ ██    ██ ██   ██ ██   ██ ██     
    ██ ██ ██ ██ █████   ██████  ███████ ██ █  ██ ███████ ██████  █████  
    ██ ██  ████ ██      ██   ██ ██   ██ ██████ ██ ██   ██ ██   ██ ██     
    ██ ██   ███ ██      ██   ██ ██   ██  ███████  ██   ██ ██   ██ ███████
    """)
    print("\n InfraWare - Enterprise-Grade Infrastructure Security Scanner")
    print("\n Enhanced Features:")
    print("  - Secret Detection (API keys, passwords, tokens)")
    print("  - License Compliance (SPDX, CycloneDX compatible)")
    print("  - Dependency Vulnerability Scanning")
    print("  - SBOM Generation (CycloneDX, SPDX formats)")
    print("  - Enhanced CloudFormation Support")
    print("  - Multi-language Support (Node.js, Python, Go)")
    print("  - Enterprise-grade CVE Database (180K+ vulnerabilities)")
    print("  - Container Security Scanning (Images, Dockerfiles, Runtime)")
    print("  - Real-time Vulnerability Intelligence")

# Add the existing scan command
app.command("scan")(scan)

# Add cost analysis command directly
@app.command("cost-analysis")
def cost_analysis_cmd(
    plan_file: str = typer.Argument(help="Path to the Terraform plan or CloudFormation template"),
    provider: str = typer.Option("aws", "--provider", help="Cloud provider (aws, gcp, azure)"),
    region: str = typer.Option("us-east-1", "--region", help="Cloud region"),
    hours: int = typer.Option(730, "--hours", help="Hours to calculate costs for"),
    output_format: str = typer.Option("table", "--format", help="Output format (table, json)")
):
    """Analyze cloud infrastructure costs."""
    console = Console()
    console.print(f"Analyzing costs for: [cyan]{plan_file}[/cyan]")
    
    try:
        from infraware.commands.cost_analysis import CostAnalyzer
        
        # Analyze infrastructure costs
        analyzer = CostAnalyzer()
        cost_data = analyzer.analyze_file_costs(plan_file, provider, region)
        
        if output_format.lower() == "json":
            console.print_json(data=cost_data)
        else:
            console.print(f"\n[bold green]Cost Analysis Results[/bold green]")
            console.print(f"Provider: [cyan]{provider.upper()}[/cyan]")
            console.print(f"Region: [cyan]{region}[/cyan]")
            console.print(f"Duration: [cyan]{hours} hours[/cyan]")
            
            if 'resources' in cost_data:
                console.print(f"\nTotal Resources: [yellow]{len(cost_data['resources'])}[/yellow]")
                total_cost = sum(r.get('cost', 0) for r in cost_data['resources'])
                console.print(f"Estimated Total Cost: [green]${total_cost:.2f}[/green]")
            
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)

# Add the enhanced scanning commands
@app.command("secrets")
def secrets_cmd(
    target: str = typer.Argument(help="Path to file or directory to scan"),
    output_format: str = typer.Option("table", "--format", help="Output format (table, json)")
):
    """Scan for hardcoded secrets and high-entropy strings."""
    console = Console()
    console.print(f"Scanning for secrets: [cyan]{target}[/cyan]")
    
    try:
        from infraware.utils.secret_scanner import EnhancedSecretScanner
        scanner = EnhancedSecretScanner()
        
        if Path(target).is_file():
            findings = scanner.scan_file(target)
        else:
            findings = scanner.scan_directory(target)
        
        report = scanner.generate_report(findings)
        
        if output_format.lower() == "json":
            console.print_json(data=report)
        else:
            summary = report.get('summary', {})
            console.print(f"\n[bold green]Secret Scan Results[/bold green]")
            console.print(f"Total Secrets Found: [red]{summary.get('total_secrets', 0)}[/red]")
            console.print(f"Risk Score: [red]{summary.get('risk_score', 0)}[/red]")
            
            # Show details of first few findings
            findings_list = report.get('findings', [])
            if findings_list:
                from rich.table import Table
                table = Table(title="Secrets Found")
                table.add_column("Type", style="cyan")
                table.add_column("Severity", style="bold")
                table.add_column("File", style="magenta")
                table.add_column("Line", style="yellow")
                
                for finding in findings_list[:10]:  # Show first 10
                    table.add_row(
                        finding.get('type', 'unknown'),
                        finding.get('severity', 'unknown'),
                        str(Path(finding.get('file_path', 'unknown')).name),
                        str(finding.get('line_number', 0))
                    )
                
                console.print(table)
                
                if len(findings_list) > 10:
                    console.print(f"\n[yellow]... and {len(findings_list) - 10} more findings[/yellow]")
            
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)

@app.command("comprehensive")
def comprehensive_cmd(
    target: str = typer.Argument(help="Path to file or directory to scan"),
    output_format: str = typer.Option("table", "--format", help="Output format (table, json)")
):
    """Comprehensive security scan including vulnerabilities, secrets, and more."""
    console = Console()
    console.print(f"Starting comprehensive scan: [cyan]{target}[/cyan]")
    
    results = {
        'target': target,
        'secrets': {},
        'summary': {}
    }
    
    # Secret scanning
    try:
        console.print("Scanning for secrets...")
        from infraware.utils.secret_scanner import EnhancedSecretScanner
        
        scanner = EnhancedSecretScanner()
        
        if Path(target).is_file():
            findings = scanner.scan_file(target)
        else:
            findings = scanner.scan_directory(target)
        
        results['secrets'] = scanner.generate_report(findings)
        
    except Exception as e:
        console.print(f"[yellow]Warning: Secret scanning failed: {e}[/yellow]")
    
    # Display results
    if output_format.lower() == "json":
        console.print_json(data=results)
    else:
        console.print("\n[bold green]Comprehensive Security Scan Results[/bold green]")
        
        if results.get('secrets'):
            secret_summary = results['secrets'].get('summary', {})
            console.print(f"\n[bold]Secrets Found: {secret_summary.get('total_secrets', 0)}[/bold]")
            if secret_summary.get('total_secrets', 0) > 0:
                console.print(f"Risk Score: [red]{secret_summary.get('risk_score', 0)}[/red]")
        
        console.print("\nScan completed!")

# CVE Database Commands
@app.command("cve-update")
def cve_update_cmd(
    force: bool = typer.Option(False, "--force", help="Force database update even if recent")
):
    """Update CVE vulnerability database."""
    console = Console()
    console.print("Updating CVE database...")
    
    try:
        from infraware.utils.cve_database import CVEDatabase
        import asyncio
        
        db = CVEDatabase()
        
        async def update():
            return await db.update_database(force_update=force)
            
        stats = asyncio.run(update())
        
        console.print(f"\n[bold green]CVE Database Update Complete[/bold green]")
        console.print(f"New CVEs: [green]{stats.get('new_cves', 0)}[/green]")
        console.print(f"Updated CVEs: [yellow]{stats.get('updated_cves', 0)}[/yellow]")
        console.print(f"Total Processed: [cyan]{stats.get('total_processed', 0)}[/cyan]")
        
    except Exception as e:
        console.print(f"[red]Error updating CVE database: {e}[/red]")
        raise typer.Exit(1)

@app.command("cve-search")
def cve_search_cmd(
    query: str = typer.Argument(help="Search query for CVEs"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    limit: int = typer.Option(10, "--limit", help="Maximum number of results"),
    output_format: str = typer.Option("table", "--format", help="Output format (table, json)")
):
    """Search CVE database."""
    console = Console()
    
    try:
        from infraware.utils.cve_database import CVEDatabase
        from rich.table import Table
        
        db = CVEDatabase()
        cves = db.search_cves(query, severity, limit)
        
        if output_format.lower() == "json":
            console.print_json(data=[cve.to_dict() for cve in cves])
        else:
            table = Table(title=f"CVE Search Results for '{query}'")
            table.add_column("CVE ID", style="cyan")
            table.add_column("Severity", style="bold")
            table.add_column("Score", style="yellow")
            table.add_column("Description", style="white", max_width=50)
            
            for cve in cves:
                table.add_row(
                    cve.cve_id,
                    cve.severity,
                    str(cve.cvss_score),
                    cve.description[:100] + "..." if len(cve.description) > 100 else cve.description
                )
                
            console.print(table)
            console.print(f"\nFound {len(cves)} CVEs matching '{query}'")
            
    except Exception as e:
        console.print(f"[red]Error searching CVE database: {e}[/red]")
        raise typer.Exit(1)

@app.command("cve-stats")
def cve_stats_cmd():
    """Show CVE database statistics."""
    console = Console()
    
    try:
        from infraware.utils.cve_database import CVEDatabase
        from rich.table import Table
        
        db = CVEDatabase()
        stats = db.get_database_stats()
        
        console.print(f"\n[bold green]CVE Database Statistics[/bold green]")
        console.print(f"Total CVEs: [cyan]{stats['total_cves']:,}[/cyan]")
        console.print(f"Recent CVEs (30 days): [yellow]{stats['recent_cves_30_days']:,}[/yellow]")
        console.print(f"Database Size: [green]{stats['database_size_mb']:.1f} MB[/green]")
        console.print(f"Last Update: [magenta]{stats.get('last_update', 'Never')}[/magenta]")
        
        # Severity distribution table
        table = Table(title="Severity Distribution")
        table.add_column("Severity", style="bold")
        table.add_column("Count", style="cyan")
        table.add_column("Percentage", style="yellow")
        
        total = stats['total_cves']
        for severity, count in stats['severity_distribution'].items():
            percentage = (count / total * 100) if total > 0 else 0
            table.add_row(severity, f"{count:,}", f"{percentage:.1f}%")
            
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Error getting CVE stats: {e}[/red]")
        raise typer.Exit(1)

# Container Security Commands
@app.command("container-scan")
def container_scan_cmd(
    image: str = typer.Argument(help="Container image name or ID"),
    include_layers: bool = typer.Option(True, "--layers/--no-layers", help="Include layer analysis"),
    output_format: str = typer.Option("table", "--format", help="Output format (table, json)")
):
    """Comprehensive container security scan."""
    console = Console()
    console.print(f"Scanning container image: [cyan]{image}[/cyan]")
    
    try:
        from infraware.utils.container_scanner import ContainerSecurityScanner
        from rich.table import Table
        import asyncio
        
        scanner = ContainerSecurityScanner()
        
        async def scan():
            return await scanner.scan_image(image, include_layers)
            
        result = asyncio.run(scan())
        
        if output_format.lower() == "json":
            console.print_json(data=result.to_dict())
        else:
            # Display scan results
            console.print(f"\n[bold green]Container Security Scan Results[/bold green]")
            console.print(f"Image: [cyan]{result.image_name}[/cyan]")
            console.print(f"Size: [yellow]{result.size_mb} MB[/yellow]")
            console.print(f"Security Score: [{'green' if result.security_score > 80 else 'yellow' if result.security_score > 60 else 'red'}]{result.security_score:.1f}/100[/]")
            
            # Vulnerabilities table
            if result.vulnerabilities:
                vuln_table = Table(title="Vulnerabilities Found")
                vuln_table.add_column("CVE ID", style="cyan")
                vuln_table.add_column("Package", style="magenta")
                vuln_table.add_column("Severity", style="bold")
                vuln_table.add_column("Score", style="yellow")
                
                for vuln in result.vulnerabilities[:10]:  # Show first 10
                    vuln_table.add_row(
                        vuln.cve_id,
                        vuln.package_name,
                        vuln.severity,
                        str(vuln.cvss_score)
                    )
                    
                console.print(vuln_table)
                
                if len(result.vulnerabilities) > 10:
                    console.print(f"... and {len(result.vulnerabilities) - 10} more vulnerabilities")
                    
            # Secrets table
            if result.secrets:
                secrets_table = Table(title="Secrets Found")
                secrets_table.add_column("Type", style="cyan")
                secrets_table.add_column("File", style="magenta")
                secrets_table.add_column("Severity", style="bold")
                
                for secret in result.secrets[:5]:  # Show first 5
                    secrets_table.add_row(
                        secret['type'],
                        secret['file_path'],
                        secret['severity']
                    )
                    
                console.print(secrets_table)
                
            # Recommendations
            if result.recommendations:
                console.print(f"\n[bold blue]Security Recommendations:[/bold blue]")
                for i, rec in enumerate(result.recommendations[:5], 1):
                    console.print(f"  {i}. {rec}")
                    
    except Exception as e:
        console.print(f"[red]Error scanning container: {e}[/red]")
        raise typer.Exit(1)

@app.command("dockerfile-scan")
def dockerfile_scan_cmd(
    dockerfile: str = typer.Argument(help="Path to Dockerfile"),
    output_format: str = typer.Option("table", "--format", help="Output format (table, json)")
):
    """Scan Dockerfile for security issues."""
    console = Console()
    console.print(f"Scanning Dockerfile: [cyan]{dockerfile}[/cyan]")
    
    try:
        from infraware.utils.container_scanner import ContainerSecurityScanner
        from rich.table import Table
        import asyncio
        
        scanner = ContainerSecurityScanner()
        
        async def scan():
            return await scanner.scan_dockerfile(dockerfile)
            
        issues = asyncio.run(scan())
        
        if output_format.lower() == "json":
            console.print_json(data=[issue.to_dict() for issue in issues])
        else:
            if issues:
                table = Table(title="Dockerfile Security Issues")
                table.add_column("Rule ID", style="cyan")
                table.add_column("Line", style="yellow")
                table.add_column("Severity", style="bold")
                table.add_column("Issue", style="white", max_width=40)
                table.add_column("Remediation", style="green", max_width=40)
                
                for issue in issues:
                    table.add_row(
                        issue.rule_id,
                        str(issue.line_number),
                        issue.severity,
                        issue.issue,
                        issue.remediation
                    )
                    
                console.print(table)
                console.print(f"\nFound {len(issues)} security issues in Dockerfile")
            else:
                console.print("[green]No security issues found in Dockerfile![/green]")
                
    except Exception as e:
        console.print(f"[red]Error scanning Dockerfile: {e}[/red]")
        raise typer.Exit(1)

@app.command("container-runtime")
def container_runtime_cmd(
    container_id: str = typer.Argument(help="Running container ID or name"),
    output_format: str = typer.Option("table", "--format", help="Output format (table, json)")
):
    """Scan running container for security issues."""
    console = Console()
    console.print(f"Scanning running container: [cyan]{container_id}[/cyan]")
    
    try:
        from infraware.utils.container_scanner import ContainerSecurityScanner
        from rich.table import Table
        import asyncio
        
        scanner = ContainerSecurityScanner()
        
        async def scan():
            return await scanner.scan_container_runtime(container_id)
            
        result = asyncio.run(scan())
        
        if output_format.lower() == "json":
            console.print_json(data=result)
        else:
            console.print(f"\n[bold green]Container Runtime Security Analysis[/bold green]")
            console.print(f"Container ID: [cyan]{result['container_id']}[/cyan]")
            console.print(f"Image: [magenta]{result['image']}[/magenta]")
            console.print(f"Status: [yellow]{result['status']}[/yellow]")
            console.print(f"Security Score: [{'green' if result['security_score'] > 80 else 'yellow' if result['security_score'] > 60 else 'red'}]{result['security_score']:.1f}/100[/]")
            
            if result['security_issues']:
                table = Table(title="Runtime Security Issues")
                table.add_column("Type", style="cyan")
                table.add_column("Severity", style="bold")
                table.add_column("Description", style="white")
                table.add_column("Remediation", style="green")
                
                for issue in result['security_issues']:
                    table.add_row(
                        issue['type'],
                        issue['severity'],
                        issue['description'],
                        issue['remediation']
                    )
                    
                console.print(table)
            else:
                console.print("[green]No runtime security issues detected![/green]")
                
    except Exception as e:
        console.print(f"[red]Error scanning container runtime: {e}[/red]")
        raise typer.Exit(1)

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        welcome()
        print("\nUsage: infraware [OPTIONS] COMMAND [ARGS]...")
        print("Try 'infraware --help' for help.")
        sys.exit(0)
    app()