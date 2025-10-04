import typer
from rich.console import Console

def cve_update_cmd(force: bool = typer.Option(False, "--force", help="Force update even if database is recent")):
    console = Console()
    console.print("Updating CVE database...")

    try:
        from infraware.utils.cve_database import CVEDatabase
        import asyncio

        db = CVEDatabase()

        async def update():
            return await db.update_database(force_update=force)

        stats = asyncio.run(update())

        console.print(f"\n[bold green]CVE Database Update Complete[/bold green]")
        console.print(f"New CVEs: [green]{stats.get('new_cves', 0)}[/green]")
        console.print(f"Updated CVEs: [yellow]{stats.get('updated_cves', 0)}[/yellow]")
        console.print(f"Total Processed: [cyan]{stats.get('total_processed', 0)}[/cyan]")

    except Exception as e:
        console.print(f"[red]Error updating CVE database: {e}[/red]")
        raise typer.Exit(1)
