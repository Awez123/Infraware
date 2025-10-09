#!/usr/bin/env python3

import typer
from rich.console import Console
from rich.panel import Panel

# Import command modules
from infraware.commands.scan import scan, preview
from infraware.commands.cost_analysis import app as cost_app

console = Console()

# Create main application
app = typer.Typer(
    name="infraware",
    help="🛡️ InfraWare v2.0 - Enterprise Infrastructure Security & Cost Platform",
    rich_markup_mode="rich"
)

# Register main commands directly
app.command("scan")(scan)
app.command("preview")(preview)

# Add cost analysis as subcommand group  
app.add_typer(cost_app, name="cost-analysis", help="💰 Real-time multi-cloud infrastructure cost analysis")

# Try to import optional commands
try:
    from infraware.commands.secrets import secrets_scan
    app.command("secrets")(secrets_scan)
except ImportError:
    pass

try:
    from infraware.commands.enhanced_scan import comprehensive_scan
    app.command("comprehensive")(comprehensive_scan)
except ImportError:
    pass

try:
    from infraware.commands.cve_commands import app as cve_app
    app.add_typer(cve_app, name="cve", help="🔍 CVE database management")
except ImportError:
    pass

try:
    from infraware.commands.server_commands import app as server_app  
    app.add_typer(server_app, name="server", help="🌐 Web interface and API server")
except ImportError:
    pass

@app.command()
def welcome():
    """
    🎉 Welcome to InfraWare - Display main features and capabilities
    """
    console.print("\n")
    
    # ASCII Art for InfraWare
    ascii_art = """
[bold cyan]
██╗███╗   ██╗███████╗██████╗  █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
██║████╗  ██║██╔════╝██╔══██╗██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
██║██╔██╗ ██║█████╗  ██████╔╝███████║██║ █╗ ██║███████║██████╔╝█████╗  
██║██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
██║██║ ╚████║██║     ██║  ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
[/bold cyan]"""
    
    console.print(ascii_art)
    console.print(Panel.fit(
        "[bold cyan]🛡️ InfraWare v2.0[/bold cyan]\n"
        "[bold white]Enterprise Infrastructure Security & Cost Platform[/bold white]\n\n"
        "Real-time security scanning, cost analysis, and vulnerability management\n"
        "for multi-cloud infrastructure across AWS, Azure, and GCP.",
        title="Welcome to InfraWare",
        border_style="cyan",
        padding=(1, 2)
    ))
    
    console.print("\n[bold green]🚀 Main Features:[/bold green]\n")
    
    # Scan Features
    console.print(Panel(
        "[bold cyan]infraware scan[/bold cyan] - Infrastructure Security Scanning\n\n"
        "• [yellow]infraware scan <file>[/yellow] - Basic security scan\n"
        "• [yellow]infraware scan <file> --comprehensive[/yellow] - Full security analysis\n"
        "• [yellow]infraware scan <file> --secrets[/yellow] - Secret detection scan\n"
        "• [yellow]infraware scan <file> --format json[/yellow] - JSON output\n"
        "• [yellow]infraware scan <dir> --quick[/yellow] - Fast directory scan\n"
        "• [yellow]infraware scan <file> --rules-dir custom/[/yellow] - Custom rules\n"
        "• [yellow]infraware scan <file> --ignore-dir ignores/[/yellow] - Ignore patterns\n"
        "• [yellow]infraware scan preview <dir>[/yellow] - Preview scannable files",
        title="🛡️ Security Scanning",
        border_style="green"
    ))
    
    # Cost Analysis Features  
    console.print(Panel(
        "[bold cyan]infraware cost-analysis[/bold cyan] - Real-time Cost Analysis\n\n"
        "• [yellow]infraware cost-analysis <file> --realtime[/yellow] - Live pricing\n"
        "• [yellow]infraware cost-analysis <file> --region us-west-2[/yellow] - Regional costs\n"
        "• [yellow]infraware cost-analysis <file> --hours 8760[/yellow] - Annual costs\n"
        "• [yellow]infraware cost-analysis <file> --breakdown[/yellow] - Detailed breakdown\n"
        "• [yellow]infraware cost-analysis <file> --optimize[/yellow] - Cost optimization\n"
        "• [yellow]infraware cost-analysis <file> --compare[/yellow] - Multi-cloud comparison",
        title="💰 Cost Analysis",
        border_style="blue"
    ))
    
    # CVE Features
    console.print(Panel(
        "[bold cyan]infraware cve[/bold cyan] - Vulnerability Database Management\n\n"
        "• [yellow]infraware cve download[/yellow] - Download CVE database\n"
        "• [yellow]infraware cve stats[/yellow] - Database statistics\n"
        "• [yellow]infraware cve search <query>[/yellow] - Search vulnerabilities\n"
        "• [yellow]infraware cve update[/yellow] - Update database\n"
        "• [yellow]infraware cve research <cve-id>[/yellow] - Detailed CVE info\n"
        "• [yellow]infraware cve trends[/yellow] - Vulnerability trends",
        title="🔍 CVE Management",
        border_style="red"
    ))
    
    # Server Features
    console.print(Panel(
        "[bold cyan]infraware server[/bold cyan] - Web Interface & API\n\n"
        "• [yellow]infraware server start[/yellow] - Start web dashboard\n"
        "• [yellow]infraware server start --port 8080[/yellow] - Custom port\n"
        "• [yellow]infraware server api[/yellow] - API-only mode\n"
        "• [yellow]infraware server status[/yellow] - Server health check",
        title="🌐 Web Interface",
        border_style="magenta"
    ))
    
    console.print("\n[dim]💡 Tip: Use [yellow]infraware <command> --help[/yellow] for detailed options[/dim]\n")

if __name__ == "__main__":
    app()