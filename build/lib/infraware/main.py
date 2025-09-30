# in infraware/main.py

import typer

# Import the Typer "apps" from your command files
from infraware.commands import scan, rules, cost_analysis

app = typer.Typer(
    help="InfraWare: An IaC Security and Quality Scanner.",
    add_completion=False
)

# Add the 'scan' command to the main app
# Typer is smart enough to find the @app.command() inside scan.py
app.command("scan")(scan.scan)

# Add the 'rules' subcommand suite to the main app
app.add_typer(rules.app, name="rules")

# Add the 'cost-analysis' subcommand suite to the main app
app.add_typer(cost_analysis.app, name="cost-analysis")

# Add the 'cost-analysis' subcommand suite to the main app
app.add_typer(cost_analysis.app, name="cost-analysis")


if __name__ == "__main__":
    app()