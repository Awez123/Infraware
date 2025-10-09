"""
Server Commands Module - Web interface and API management
"""
import typer
import uvicorn
from rich.console import Console
from typing_extensions import Annotated

app = typer.Typer(help="🌐 Web interface and API server")
console = Console()

@app.command("start")
def start(
    host: Annotated[str, typer.Option("--host", help="Host to bind server to")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Port to run server on")] = 8003,
    reload: Annotated[bool, typer.Option("--reload", help="Enable auto-reload")] = False
):
    """Start the InfraWare web dashboard and API server"""
    console.print(f"🚀 [bold green]Starting InfraWare Server...[/bold green]")
    console.print(f"📊 Dashboard: [cyan]http://{host}:{port}[/cyan]")
    console.print(f"🔌 API Base: [cyan]http://{host}:{port}/api[/cyan]")
    console.print("\n[bold yellow]Available Endpoints:[/bold yellow]")
    console.print("• [cyan]/api/scan[/cyan] - Security scanning")
    console.print("• [cyan]/api/cost[/cyan] - Cost analysis") 
    console.print("• [cyan]/api/secrets[/cyan] - Secret detection")
    console.print("• [cyan]/api/cve[/cyan] - CVE operations")
    console.print()
    
    try:
        uvicorn.run("infraware.server.main:app", host=host, port=port, reload=reload)
    except Exception as e:
        console.print(f"❌ [red]Server startup failed: {e}[/red]")

@app.command("api")
def api_only(
    host: Annotated[str, typer.Option("--host", help="Host to bind API to")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Port to run API on")] = 8003
):
    """Start API server only (no web interface)"""
    console.print(f"🔌 [bold green]Starting InfraWare API Server...[/bold green]")
    console.print(f"API: [cyan]http://{host}:{port}/api[/cyan]")
    uvicorn.run("infraware.server.main:app", host=host, port=port)

@app.command("status")
def status():
    """Check server health and status"""
    console.print("🔍 [bold blue]Checking server status...[/bold blue]")
    # Implementation for server health check
    console.print("🚧 [yellow]Feature coming soon - server status check[/yellow]")