import typer
from typing import Optional
from rich.console import Console

def cve_search_cmd(
    query: str = typer.Argument(help="Search terms (technology, vendor, product name)"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    limit: int = typer.Option(10, "--limit", help="Maximum results to return (default: 10)"),
    output_format: str = typer.Option("table", "--format", help="Output format: table (default) or json")
):
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
