"""
CVE Commands Module - Centralized CVE database management
"""
import typer
from rich.console import Console
from typing_extensions import Annotated

app = typer.Typer(help="🔍 CVE database management and vulnerability research")
console = Console()

@app.command("download")
def download(
    force: Annotated[bool, typer.Option("--force", help="Force re-download even if database exists")] = False,
    limit: Annotated[int, typer.Option("--limit", help="Limit number of CVEs to download")] = None
):
    """Download and initialize CVE database"""
    from infraware.commands.cve_bulk_download import cve_bulk_download_cmd
    console.print("🔄 [bold blue]Downloading CVE database...[/bold blue]")
    cve_bulk_download_cmd()

@app.command("update")
def update():
    """Update existing CVE database with latest entries"""
    from infraware.commands.cve_update import cve_update_cmd
    console.print("🔄 [bold blue]Updating CVE database...[/bold blue]")
    cve_update_cmd()

@app.command("stats")
def stats():
    """Display CVE database statistics and metrics"""
    from infraware.commands.cve_stats import cve_stats_cmd
    console.print("📊 [bold blue]CVE Database Statistics:[/bold blue]")
    cve_stats_cmd()

@app.command("search")
def search(
    query: Annotated[str, typer.Argument(help="Search term or CVE ID")],
    severity: Annotated[str, typer.Option("--severity", help="Filter by severity")] = None,
    limit: Annotated[int, typer.Option("--limit", help="Maximum results to return")] = 10,
    format: Annotated[str, typer.Option("--format", help="Output format: table, json")] = "table"
):
    """Search CVE database for vulnerabilities"""
    from infraware.commands.cve_search import cve_search_cmd
    console.print(f"🔍 [bold blue]Searching for: {query}[/bold blue]")
    cve_search_cmd(query=query, severity=severity, limit=limit, output_format=format)

@app.command("research")
def research(
    cve_id: Annotated[str, typer.Argument(help="CVE ID to research (e.g., CVE-2023-1234)")]
):
    """Get detailed information about a specific CVE"""
    console.print(f"🔬 [bold blue]Researching CVE: {cve_id}[/bold blue]")
    # Implementation for detailed CVE research
    console.print("🚧 [yellow]Feature coming soon - detailed CVE research[/yellow]")

@app.command("trends")
def trends(
    timeframe: Annotated[str, typer.Option("--timeframe", help="Time period: week, month, year")] = "month"
):
    """Show vulnerability trends and statistics"""
    console.print(f"📈 [bold blue]CVE Trends - Last {timeframe}:[/bold blue]")
    # Implementation for CVE trends
    console.print("🚧 [yellow]Feature coming soon - vulnerability trends[/yellow]")