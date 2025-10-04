import typer
from rich.console import Console

def cve_bulk_download_cmd():
    console = Console()
    console.print("[bold yellow]🚀 Starting REAL-TIME CVE database download...[/bold yellow]")
    console.print("[dim]Live streaming download with real-time progress updates[/dim]")
    console.print("[dim]3 years (2023-2025) of CVE data with instant feedback[/dim]")
    console.print(f"[dim]Expected: ~100,000+ CVEs in 10-15 minutes[/dim]\n")

    confirm = typer.confirm("Start the real-time enterprise download?")
    if not confirm:
        console.print("Download cancelled.")
        raise typer.Exit(0)

    try:
        from infraware.utils.cve_database import CVEDatabase
        import asyncio

        db = CVEDatabase()

        console.print("📡 Starting real-time streaming download...")

        async def real_time_download():
            return await db._real_time_enterprise_download()

        stats = asyncio.run(real_time_download())

        console.print(f"\n[bold green]✅ Real-Time Download Complete![/bold green]")
        console.print(f"New CVEs Downloaded: [green]{stats.get('new', 0):,}[/green]")
        console.print(f"Updated CVEs: [yellow]{stats.get('updated', 0):,}[/yellow]")
        console.print(f"Total Processed: [cyan]{stats.get('processed', 0):,}[/cyan]")

        console.print(f"\n[bold blue]📊 Final Database Statistics:[/bold blue]")
        final_stats = db.get_database_stats()
        console.print(f"Total CVEs: [green]{final_stats['total_cves']:,}[/green]")
        console.print(f"Database Size: [cyan]{final_stats['database_size_mb']:.1f} MB[/cyan]")

    except Exception as e:
        console.print(f"[red]Error during bulk download: {e}[/red]")
        raise typer.Exit(1)
