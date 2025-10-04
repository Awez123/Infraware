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
