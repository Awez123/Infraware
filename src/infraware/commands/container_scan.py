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

        scanner = ContainerSecurityScanner()
        # new scanner provides a synchronous scan_image
        result = scanner.scan_image(image)
        # Normalize result to dict for JSON output and programmatic consumption
        result_dict = result.to_dict() if hasattr(result, 'to_dict') else (result if isinstance(result, dict) else {})

        if output_format.lower() == "json":
            console.print_json(data=result_dict)
        else:
            console.print(f"\n[bold green]Container Security Scan Results[/bold green]")
            # image name
            img_display = result_dict.get('image_name') or getattr(result, 'image_name', image)
            console.print(f"Image: [cyan]{img_display}[/cyan]")

            # size and score are optional in the simplified scanner
            size_mb = result_dict.get('size_mb') or getattr(result, 'size_mb', None)
            if size_mb is not None:
                console.print(f"Size: [yellow]{size_mb} MB[/yellow]")

            score = result_dict.get('security_score') or getattr(result, 'security_score', result_dict.get('summary', {}))
            try:
                # try to coerce
                score_val = float(result_dict.get('security_score', getattr(result, 'security_score', 100.0)))
            except Exception:
                score_val = 100.0
            console.print(f"Security Score: [{'green' if score_val > 80 else 'yellow' if score_val > 60 else 'red'}]{score_val:.1f}/100[/]")

            vulns = result_dict.get('vulnerabilities') or []
            if vulns:
                vuln_table = Table(title="Vulnerabilities Found")
                vuln_table.add_column("CVE ID", style="cyan")
                vuln_table.add_column("Package", style="magenta")
                vuln_table.add_column("Severity", style="bold")
                vuln_table.add_column("Info", style="yellow")

                # vulnerabilities might be dataclasses or dicts
                for vuln in vulns[:10]:
                    if hasattr(vuln, 'to_dict'):
                        v = vuln.to_dict()
                    elif isinstance(vuln, dict):
                        v = vuln
                    else:
                        # best-effort conversion
                        v = {k: getattr(vuln, k, '') for k in ['cve_id', 'pkg_name', 'package_name', 'severity', 'cvss_score', 'title', 'installed_version']}

                    cve = v.get('cve_id') or v.get('id') or 'N/A'
                    package = v.get('pkg_name') or v.get('package_name') or v.get('installed_package') or v.get('installed_version') or 'N/A'
                    severity = v.get('severity', 'N/A')
                    info = v.get('title') or v.get('description') or v.get('cvss_score') or ''

                    vuln_table.add_row(str(cve), str(package), str(severity), str(info))

                console.print(vuln_table)

                total_vulns = len(vulns)
                if total_vulns > 10:
                    console.print(f"... and {total_vulns - 10} more vulnerabilities")

            secrets = result_dict.get('secrets') or []
            if secrets:
                secrets_table = Table(title="Secrets Found")
                secrets_table.add_column("Type", style="cyan")
                secrets_table.add_column("File", style="magenta")
                secrets_table.add_column("Severity", style="bold")

                for secret in secrets[:5]:
                    secrets_table.add_row(
                        secret.get('type', 'N/A'),
                        secret.get('file_path', 'N/A'),
                        secret.get('severity', 'N/A')
                    )

                console.print(secrets_table)

            recs = result_dict.get('recommendations') or getattr(result, 'recommendations', None) or []
            if recs:
                console.print(f"\n[bold blue]Security Recommendations:[/bold blue]")
                for i, rec in enumerate(recs[:5], 1):
                    console.print(f"  {i}. {rec}")

            notes = result_dict.get('notes') or getattr(result, 'notes', None)
            if notes:
                console.print(f"\n[bold yellow]Notes:[/bold yellow] {notes}")

    except Exception as e:
        console.print(f"[red]Error scanning container: {e}[/red]")
        raise typer.Exit(1)
