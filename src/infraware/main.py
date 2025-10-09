#!/usr/bin/env python3
"""
InfraWare CLI entrypoint. Registers commands implemented in src/infraware/commands.
"""

import typer
import uvicorn
from rich.console import Console
from typing import List, Tuple

# --- Shared constants -----------------------------------------------------
CLI_HELP = (
    "🛡️ InfraWare v2.0 - Enterprise Infrastructure Security & Cost Platform\n"
    "Comprehensive security scanner with 35+ AWS rules, 10K+ CVE database, \n"
    "container security, secret detection, and multi-cloud cost analysis.\n"
    "Quick Examples:\n"
    "  infraware scan plan.json                  # Scan infrastructure\n"
    "  infraware comprehensive ./project         # Full security scan\n"
    "  infraware cve-update                      # Update CVE database\n"
    "  infraware container-scan nginx:latest     # Scan container\n"
    "  infraware cost-analysis file main.tf      # Analyze costs"
)

ASCII_ART = r"""
[bold cyan]
██╗███╗   ██╗███████╗██████╗  █████╗ ██╗     ██╗ █████╗ ██████╗ ███████╗
██║████╗  ██║██╔════╝██╔══██╗██╔══██╗██║     ██║██╔══██╗██╔══██╗██╔════╝
██║██╔██╗ ██║█████╗  ██████╔╝███████║██║ █╗ ██║███████║██████╔╝█████╗  
██║██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
██║██║ ╚████║██║     ██║  ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
[/bold cyan]
"""

FEATURES = [
    "🔍 Secret Detection (API keys, passwords, tokens)",
    "📜 License Compliance (SPDX, CycloneDX compatible)",
    "🛡️ Dependency Vulnerability Scanning",
    "📋 SBOM Generation (CycloneDX, SPDX formats)",
    "☁️ Enhanced CloudFormation Support",
    "🌐 Multi-language Support (Node.js, Python, Go)",
    "🗄️ Enterprise-grade CVE Database (180K+ vulnerabilities)",
    "🐳 Container Security Scanning (Images, Dockerfiles, Runtime)",
    "⚡ Real-time Vulnerability Intelligence",
    "💰 Cost Analysis and Optimization",
]

AVAILABLE_COMMANDS: List[Tuple[str, str]] = [
    ("scan", "Scan Terraform/CloudFormation files for security issues"),
    ("cost-analysis", "Analyze infrastructure costs and optimization opportunities"),
    ("secrets", "Scan for hardcoded secrets and high-entropy strings"),
    ("comprehensive", "Comprehensive security scan including all features"),
    ("container", "Scan container images for vulnerabilities"),
    ("cve-update", "Update CVE database (recent CVEs only)"),
    ("cve-bulk-download", "Download 3 years of CVE data (enterprise - ~100K CVEs)"),
    ("cve-search", "Search CVE database for specific vulnerabilities"),
    ("cve-stats", "Show CVE database statistics"),
    ("server", "Start the InfraWare web dashboard"),
    ("welcome", "Show this welcome message"),
]

# --- Import commands (each command lives in its own module) ---------------
from infraware.commands.scan import scan
from infraware.commands.cost_analysis import cost_analysis_command
from infraware.commands.secrets import secrets_cmd
from infraware.commands.comprehensive import comprehensive_cmd
from infraware.commands.cve_update import cve_update_cmd
from infraware.commands.cve_bulk_download import cve_bulk_download_cmd
from infraware.commands.cve_search import cve_search_cmd
from infraware.commands.cve_stats import cve_stats_cmd


def create_app(help_text: str = CLI_HELP) -> typer.Typer:
    app = typer.Typer(help=help_text, add_completion=False)

    # Register commands
    app.command("scan")(scan)
    app.command("cost-analysis")(cost_analysis_command)
    app.command("secrets")(secrets_cmd)
    app.command("comprehensive")(comprehensive_cmd)
    app.command("cve-update")(cve_update_cmd)
    app.command("cve-bulk-download")(cve_bulk_download_cmd)
    app.command("cve-search")(cve_search_cmd)
    app.command("cve-stats")(cve_stats_cmd)

    return app


def print_welcome(console: Console) -> None:
    console.print(ASCII_ART)
    console.print("\n[bold green]🛡️  InfraWare - Enterprise-Grade Infrastructure Security Scanner[/bold green]")
    console.print("[dim]Enhanced with CVE Database and Container Security Scanning[/dim]\n")

    console.print("[bold yellow]🚀 Enhanced Features:[/bold yellow]")
    for feature in FEATURES:
        console.print(f"  {feature}")

    console.print(f"\n[bold blue]📖 Available Commands:[/bold blue]")
    for cmd, desc in AVAILABLE_COMMANDS:
        console.print(f"  [cyan]{cmd:<17}[/cyan] {desc}")

    console.print(f"\n[dim]Use 'infraware <command> --help' for detailed command information[/dim]")
    console.print(f"[dim]Repository: https://github.com/Awez123/Infraware[/dim]\n")


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    console = Console()
    console.print(f"[bold green]Starting InfraWare server...[/bold green]")
    console.print(f"Dashboard will be available at [cyan]http://{host}:{port}[/cyan]")
    uvicorn.run("infraware.server.main:app", host=host, port=port, reload=True)


# Create the app instance used by entry points
app = create_app()


@app.command("welcome")
def welcome() -> None:
    console = Console()
    print_welcome(console)


@app.command("server")
def server_cmd(host: str = typer.Option("127.0.0.1", "--host", help="The host to bind the server to."),
               port: int = typer.Option(8000, "--port", help="The port to run the server on.")) -> None:
    run_server(host, port)


