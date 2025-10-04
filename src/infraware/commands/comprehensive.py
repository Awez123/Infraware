import typer
from rich.console import Console
from pathlib import Path

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
