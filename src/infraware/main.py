#!/usr/bin/env python3
"""
InfraWare CLI - Enterprise-Grade Infrastructure Security Scanner
Enhanced with CVE Database and Container Security Scanning
"""

import typer
import uvicorn  # <-- Import uvicorn to run the web server
from pathlib import Path
from rich.console import Console
from typing import Optional

# Import specific commands instead of the problematic apps
from infraware.commands.scan import scan
from infraware.commands.cost_analysis import cost_analysis_command

app = typer.Typer(
    help="🛡️ InfraWare v2.0 - Enterprise Infrastructure Security & Cost Platform\n\n" +
         "Comprehensive security scanner with 35+ AWS rules, 10K+ CVE database, \n" +
         "container security, secret detection, and multi-cloud cost analysis.\n\n" +
         "Quick Examples:\n" +
         "  infraware scan plan.json                  # Scan infrastructure\n" +
         "  infraware comprehensive ./project         # Full security scan\n" +
         "  infraware cve-update                      # Update CVE database\n" +
         "  infraware container-scan nginx:latest     # Scan container\n" +
         "  infraware cost-analysis file main.tf      # Analyze costs",
    add_completion=False
)

# Add the existing scan command
app.command("scan")(scan)

# Add cost analysis command
app.command("cost-analysis")(cost_analysis_command)

@app.command("welcome")
def welcome():
    """Show InfraWare branding and available commands."""
    console = Console()
    
    # ASCII Art for InfraWare
    ascii_art = """
[bold cyan]
██╗███╗   ██╗███████╗██████╗  █████╗ ██╗     ██╗ █████╗ ██████╗ ███████╗
██║████╗  ██║██╔════╝██╔══██╗██╔══██╗██║     ██║██╔══██╗██╔══██╗██╔════╝
██║██╔██╗ ██║█████╗  ██████╔╝███████║██║ █╗ ██║███████║██████╔╝█████╗  
██║██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
██║██║ ╚████║██║     ██║  ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
[/bold cyan]"""
    
    console.print(ascii_art)
    console.print("\n[bold green]🛡️  InfraWare - Enterprise-Grade Infrastructure Security Scanner[/bold green]")
    console.print("[dim]Enhanced with CVE Database and Container Security Scanning[/dim]\n")
    
    console.print("[bold yellow]🚀 Enhanced Features:[/bold yellow]")
    features = [
        "🔍 Secret Detection (API keys, passwords, tokens)",
        "📜 License Compliance (SPDX, CycloneDX compatible)", 
        "🛡️ Dependency Vulnerability Scanning",
        "📋 SBOM Generation (CycloneDX, SPDX formats)",
        "☁️ Enhanced CloudFormation Support",
        "🌐 Multi-language Support (Node.js, Python, Go)",
        "🗄️ Enterprise-grade CVE Database (180K+ vulnerabilities)",
        "🐳 Container Security Scanning (Images, Dockerfiles, Runtime)",
        "⚡ Real-time Vulnerability Intelligence",
        "💰 Cost Analysis and Optimization"
    ]
    
    for feature in features:
        console.print(f"  {feature}")
    
    console.print(f"\n[bold blue]📖 Available Commands:[/bold blue]")
    commands = [
        ("scan", "Scan Terraform/CloudFormation files for security issues"),
        ("cost-analysis", "Analyze infrastructure costs and optimization opportunities"),
        ("secrets", "Scan for hardcoded secrets and high-entropy strings"),
        ("comprehensive", "Comprehensive security scan including all features"),
        ("container", "Scan container images for vulnerabilities"),
        ("cve-update", "Update CVE database (recent CVEs only)"),
        ("cve-bulk-download", "Download 3 years of CVE data (enterprise - ~100K CVEs)"),
        ("cve-search", "Search CVE database for specific vulnerabilities"),
        ("cve-stats", "Show CVE database statistics"),
        ("server", "Start the InfraWare web dashboard"), # <-- Added server command
        ("welcome", "Show this welcome message")
    ]
    
    for cmd, desc in commands:
        console.print(f"  [cyan]{cmd:<17}[/cyan] {desc}")
    
    console.print(f"\n[dim]Use 'infraware <command> --help' for detailed command information[/dim]")
    console.print(f"[dim]Repository: https://github.com/Awez123/Infraware[/dim]\n")

# --- NEW: Server Command ---
@app.command("server")
def server_cmd(
    host: str = typer.Option("127.0.0.1", "--host", help="The host to bind the server to."),
    port: int = typer.Option(8000, "--port", help="The port to run the server on.")
):
    """🚀 Starts the InfraWare web server dashboard.\n\n
    Launches a local web server to provide a graphical user interface
    for scanning and viewing results.\n\n
    
    Examples:\n
      infraware server              # Start server on default port 8000\n
      infraware server --port 8080  # Start server on a custom port
    """
    console = Console()
    console.print(f"[bold green]Starting InfraWare server...[/bold green]")
    console.print(f"Dashboard will be available at [cyan]http://{host}:{port}[/cyan]")
    
    # We tell uvicorn the path to the FastAPI 'app' object
    # The path is 'infraware.server.main:app'
    uvicorn.run("infraware.server.main:app", host=host, port=port, reload=True)

# (The rest of your existing commands remain the same)
# ... secrets_cmd, comprehensive_cmd, cve commands, container commands ...
@app.command("secrets")
def secrets_cmd(
    target: str = typer.Argument(help="Path to file or directory to scan for secrets"),
    output_format: str = typer.Option("table", "--format", help="Output format: table (default) or json")
):
    """🔍 Scan for hardcoded secrets and high-entropy strings."""
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
            
            findings_list = report.get('findings', [])
            if findings_list:
                from rich.table import Table
                table = Table(title="Secrets Found")
                table.add_column("Type", style="cyan")
                table.add_column("Severity", style="bold")
                table.add_column("File", style="magenta")
                table.add_column("Line", style="yellow")
                
                for finding in findings_list[:10]:
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
    target: str = typer.Argument(help="Path to infrastructure files or project directory"),
    output_format: str = typer.Option("table", "--format", help="Output format: table (default) or json")
):
    """🚀 Comprehensive security scan with CVE correlation and secret detection."""
    console = Console()
    console.print(f"Starting comprehensive scan: [cyan]{target}[/cyan]")
    
    results = {
        'target': target,
        'secrets': {},
        'summary': {}
    }
    
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

@app.command("cve-update")
def cve_update_cmd(
    force: bool = typer.Option(False, "--force", help="Force update even if database is recent")
):
    """📡 Update CVE vulnerability database with latest threats."""
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

@app.command("cve-bulk-download")
def cve_bulk_download_cmd():
    """🌐 Download enterprise CVE database (100K+ CVEs, 3 years)."""
    console = Console()
    console.print("[bold yellow]🚀 Starting REAL-TIME CVE database download...[/bold yellow]")
    console.print("[dim]Live streaming download with real-time progress updates[/dim]")
    console.print("[dim]3 years (2023-2025) of CVE data with instant feedback[/dim]")
    console.print(f"[dim]Expected: ~100,000+ CVEs in 10-15 minutes[/dim]\n")
    
    confirm = typer.confirm("Start the real-time enterprise download?")
    if not confirm:
        console.print("Download cancelled.")
        raise typer.Exit(0)
    
    try:
        from infraware.utils.cve_database import CVEDatabase
        import asyncio
        
        db = CVEDatabase()
        
        console.print("📡 Starting real-time streaming download...")
        
        async def real_time_download():
            return await db._real_time_enterprise_download()
            
        stats = asyncio.run(real_time_download())
        
        console.print(f"\n[bold green]✅ Real-Time Download Complete![/bold green]")
        console.print(f"New CVEs Downloaded: [green]{stats.get('new', 0):,}[/green]")
        console.print(f"Updated CVEs: [yellow]{stats.get('updated', 0):,}[/yellow]")
        console.print(f"Total Processed: [cyan]{stats.get('processed', 0):,}[/cyan]")
        
        console.print(f"\n[bold blue]📊 Final Database Statistics:[/bold blue]")
        final_stats = db.get_database_stats()
        console.print(f"Total CVEs: [green]{final_stats['total_cves']:,}[/green]")
        console.print(f"Database Size: [cyan]{final_stats['database_size_mb']:.1f} MB[/cyan]")
        
    except Exception as e:
        console.print(f"[red]Error during bulk download: {e}[/red]")
        raise typer.Exit(1)

@app.command("cve-search")
def cve_search_cmd(
    query: str = typer.Argument(help="Search terms (technology, vendor, product name)"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    limit: int = typer.Option(10, "--limit", help="Maximum results to return (default: 10)"),
    output_format: str = typer.Option("table", "--format", help="Output format: table (default) or json")
):
    """🔍 Search CVE vulnerability database by technology or keywords."""
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
    """📊 Display CVE database statistics and health metrics."""
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

@app.command("container-scan")
def container_scan_cmd(
    image: str = typer.Argument(help="Container image name:tag or image ID"),
    include_layers: bool = typer.Option(True, "--layers/--no-layers", help="Include layer-by-layer analysis"),
    output_format: str = typer.Option("table", "--format", help="Output format: table (default) or json")
):
    """🐳 Comprehensive container image security scanning."""
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
            console.print(f"\n[bold green]Container Security Scan Results[/bold green]")
            console.print(f"Image: [cyan]{result.image_name}[/cyan]")
            console.print(f"Size: [yellow]{result.size_mb} MB[/yellow]")
            console.print(f"Security Score: [{'green' if result.security_score > 80 else 'yellow' if result.security_score > 60 else 'red'}]{result.security_score:.1f}/100[/]")
            
            if result.vulnerabilities:
                vuln_table = Table(title="Vulnerabilities Found")
                vuln_table.add_column("CVE ID", style="cyan")
                vuln_table.add_column("Package", style="magenta")
                vuln_table.add_column("Severity", style="bold")
                vuln_table.add_column("Score", style="yellow")
                
                for vuln in result.vulnerabilities[:10]:
                    vuln_table.add_row(
                        vuln.cve_id,
                        vuln.package_name,
                        vuln.severity,
                        str(vuln.cvss_score)
                    )
                    
                console.print(vuln_table)
                
                if len(result.vulnerabilities) > 10:
                    console.print(f"... and {len(result.vulnerabilities) - 10} more vulnerabilities")
                    
            if result.secrets:
                secrets_table = Table(title="Secrets Found")
                secrets_table.add_column("Type", style="cyan")
                secrets_table.add_column("File", style="magenta")
                secrets_table.add_column("Severity", style="bold")
                
                for secret in result.secrets[:5]:
                    secrets_table.add_row(
                        secret['type'],
                        secret['file_path'],
                        secret['severity']
                    )
                    
                console.print(secrets_table)
                
            if result.recommendations:
                console.print(f"\n[bold blue]Security Recommendations:[/bold blue]")
                for i, rec in enumerate(result.recommendations[:5], 1):
                    console.print(f"  {i}. {rec}")
                    
    except Exception as e:
        console.print(f"[red]Error scanning container: {e}[/red]")
        raise typer.Exit(1)

@app.command("dockerfile-scan")
def dockerfile_scan_cmd(
    dockerfile: str = typer.Argument(help="Path to Dockerfile to analyze"),
    output_format: str = typer.Option("table", "--format", help="Output format: table (default) or json")
):
    """📋 Analyze Dockerfile for security best practices and vulnerabilities."""
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
    output_format: str = typer.Option("table", "--format", help="Output format: table (default) or json")
):
    """⚡ Analyze running container for runtime security issues."""
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
        # Show welcome message when no command is provided
        welcome()
        sys.exit(0)
    app()

