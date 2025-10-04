import typer
from rich.console import Console

def container_scan_cmd(
    image: str = typer.Argument(help="Container image name:tag or image ID"),
    include_layers: bool = typer.Option(True, "--layers/--no-layers", help="Include layer-by-layer analysis"),
    output_format: str = typer.Option("table", "--format", help="Output format: table (default) or json")
):
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
