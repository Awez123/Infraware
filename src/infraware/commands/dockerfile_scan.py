import typer
from rich.console import Console

def dockerfile_scan_cmd(
    dockerfile: str = typer.Argument(help="Path to Dockerfile to analyze"),
    output_format: str = typer.Option("table", "--format", help="Output format: table (default) or json")
):
    console = Console()
    console.print(f"Scanning Dockerfile: [cyan]{dockerfile}[/cyan]")

    try:
        from infraware.utils.container_scanner import ContainerSecurityScanner
        from rich.table import Table
        import asyncio

        scanner = ContainerSecurityScanner()
        issues = scanner.scan_dockerfile(dockerfile)

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
