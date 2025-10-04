# in infraware/main.py

import typer
from infraware.commands import scan, rules, cost_analysis

app = typer.Typer(
    help="InfraWare: An IaC Security and Quality Scanner.",
    add_completion=False
)

@app.command("welcome")
def welcome():
        """Show Infraware branding and available commands."""
        ascii_art = r"""
            ██╗███╗   ██╗███████╗██████╗  █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
            ██║████╗  ██║██╔════╝██╔══██╗██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
            ██║██╔██╗ ██║█████╗  ██████╔╝███████║██║ █╗ ██║███████║██████╔╝█████╗  
            ██║██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
            ██║██║ ╚████║██║     ██║  ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
            ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ 
        """
        print(ascii_art)
        print("\nAvailable commands:")
        print("  scan           Scan a Terraform plan JSON file for vulnerabilities")
        print("  rules          Manage and validate rules")
        print("  cost-analysis  Analyze cloud resource costs")
        print("    --aws          Show AWS pricing information")
        print("    --gcp          Show GCP pricing information") 
        print("    --azure        Show Azure pricing information")
        print("    --providers    List supported providers and regions")
        print("    --metadata     Show metadata for specific provider")
        print("    --confidence   Show pricing data confidence report")

# Add the 'scan' command to the main app
app.command("scan")(scan.scan)

# Add the 'rules' subcommand suite to the main app
app.add_typer(rules.app, name="rules")

# Add the 'cost-analysis' single command to the main app
app.command("cost-analysis")(cost_analysis.cost_analysis_command)

if __name__ == "__main__":
    app()






