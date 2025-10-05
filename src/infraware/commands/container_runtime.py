import typer
from rich.console import Console

def container_runtime_cmd(
    container_id: str = typer.Argument(help="Running container ID or name"),
    output_format: str = typer.Option("table", "--format", help="Output format: table (default) or json")
):
    console = Console()
    console.print(f"Scanning running container: [cyan]{container_id}[/cyan]")

    try:
        from infraware.utils.container_scanner import ContainerSecurityScanner
        from rich.table import Table

        scanner = ContainerSecurityScanner()
        result = scanner.scan_container_runtime(container_id)

        if output_format.lower() == "json":
            console.print_json(data=result)
        else:
            console.print(f"\n[bold green]Container Runtime Security Analysis[/bold green]")
            console.print(f"Container ID: [cyan]{result.get('container_id')}[/cyan]")
            console.print(f"Security Score: [{'green' if result.get('security_score', 100) > 80 else 'yellow' if result.get('security_score', 100) > 60 else 'red'}]{result.get('security_score', 100):.1f}/100[/]")

            issues = result.get('issues', [])
            if issues:
                table = Table(title="Runtime Security Issues")
                table.add_column("Type", style="cyan")
                table.add_column("Severity", style="bold")
                table.add_column("Description", style="white")

                for issue in issues:
                    table.add_row(
                        issue.get('type', 'N/A'),
                        issue.get('severity', 'N/A'),
                        issue.get('description', '')
                    )

                console.print(table)
            else:
                console.print("[green]No runtime security issues detected![/green]")

    except Exception as e:
        console.print(f"[red]Error scanning container runtime: {e}[/red]")
        raise typer.Exit(1)
