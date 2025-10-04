from rich.console import Console
from pathlib import Path
import typer

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
