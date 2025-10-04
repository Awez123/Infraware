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
        # Normalize result to dict for JSON output and programmatic consumption
        result_dict = result.to_dict() if hasattr(result, 'to_dict') else (result if isinstance(result, dict) else {})

        if output_format.lower() == "json":
            console.print_json(data=result_dict)
        else:
            console.print(f"\n[bold green]Container Security Scan Results[/bold green]")
            console.print(f"Image: [cyan]{result.image_name}[/cyan]")
            console.print(f"Size: [yellow]{result.size_mb} MB[/yellow]")
            score = getattr(result, 'security_score', result_dict.get('security_score', 100.0))
            console.print(f"Security Score: [{'green' if score > 80 else 'yellow' if score > 60 else 'red'}]{score:.1f}/100[/]")

            if result_dict.get('vulnerabilities'):
                vuln_table = Table(title="Vulnerabilities Found")
                vuln_table.add_column("CVE ID", style="cyan")
                vuln_table.add_column("Package", style="magenta")
                vuln_table.add_column("Severity", style="bold")
                vuln_table.add_column("Score", style="yellow")

                # vulnerabilities might be dataclasses or dicts
                for vuln in result_dict.get('vulnerabilities', [])[:10]:
                    if hasattr(vuln, 'to_dict'):
                        v = vuln.to_dict()
                    elif isinstance(vuln, dict):
                        v = vuln
                    else:
                        # best-effort conversion
                        v = {k: getattr(vuln, k, '') for k in ['cve_id', 'package_name', 'severity', 'cvss_score']}

                    vuln_table.add_row(
                        str(v.get('cve_id', 'N/A')),
                        str(v.get('package_name', 'N/A')),
                        str(v.get('severity', 'N/A')),
                        str(v.get('cvss_score', 'N/A'))
                    )

                console.print(vuln_table)

                if len(result.vulnerabilities) > 10:
                    console.print(f"... and {len(result.vulnerabilities) - 10} more vulnerabilities")

            if result_dict.get('secrets'):
                secrets_table = Table(title="Secrets Found")
                secrets_table.add_column("Type", style="cyan")
                secrets_table.add_column("File", style="magenta")
                secrets_table.add_column("Severity", style="bold")

                for secret in result_dict.get('secrets', [])[:5]:
                    secrets_table.add_row(
                        secret.get('type', 'N/A'),
                        secret.get('file_path', 'N/A'),
                        secret.get('severity', 'N/A')
                    )

                console.print(secrets_table)

            if result.recommendations:
                console.print(f"\n[bold blue]Security Recommendations:[/bold blue]")
                for i, rec in enumerate(result.recommendations[:5], 1):
                    console.print(f"  {i}. {rec}")

    except Exception as e:
        console.print(f"[red]Error scanning container: {e}[/red]")
        raise typer.Exit(1)
