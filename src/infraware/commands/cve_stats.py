import typer
from rich.console import Console

def cve_stats_cmd():
    console = Console()

    try:
        from infraware.utils.cve_database import CVEDatabase
        from rich.table import Table

        db = CVEDatabase()
        stats = db.get_database_stats()

        console.print(f"\n[bold green]CVE Database Statistics[/bold green]")
        console.print(f"Total CVEs: [cyan]{stats['total_cves']:,}[/cyan]")
        console.print(f"Recent CVEs (30 days): [yellow]{stats['recent_cves_30_days']:,}[/yellow]")
        console.print(f"Database Size: [green]{stats['database_size_mb']:.1f} MB[/green]")
        console.print(f"Last Update: [magenta]{stats.get('last_update', 'Never')}[/magenta]")

        table = Table(title="Severity Distribution")
        table.add_column("Severity", style="bold")
        table.add_column("Count", style="cyan")
        table.add_column("Percentage", style="yellow")

        total = stats['total_cves']
        for severity, count in stats['severity_distribution'].items():
            percentage = (count / total * 100) if total > 0 else 0
            table.add_row(severity, f"{count:,}", f"{percentage:.1f}%")

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error getting CVE stats: {e}[/red]")
        raise typer.Exit(1)
