import json
import yaml
import typer
from typing_extensions import Annotated

# Create the Typer application with the new name
app = typer.Typer(help="InfraWare: An IaC Security and Quality Scanner.")

@app.command()
def scan(
    plan_file: Annotated[str, typer.Argument(help="Path to the terraform plan JSON file.")],
    rules_file: Annotated[str, typer.Argument(help="Path to the YAML rule file.")]
):
    """
    Scans a Terraform plan file for vulnerabilities based on a set of rules.
    """
    typer.echo(f"Scanning plan: {plan_file}")
    typer.echo(f"Using rules: {rules_file}\n")

    # --- 1. Load Files ---
    try:
        with open(plan_file, 'r') as f:
            plan_data = json.load(f)
    except Exception as e:
        typer.secho(f"Error reading plan file: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    try:
        with open(rules_file, 'r') as f:
            rules = yaml.safe_load(f)
    except Exception as e:
        typer.secho(f"Error reading rule file: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    # --- 2. The Scanning Engine ---
    vulnerabilities_found = 0
    resources = plan_data.get('planned_values', {}).get('root_module', {}).get('resources', [])
    
    for rule in rules:
        for resource in resources:
            if resource.get('type') == rule['resource']:
                attributes = resource.get('values', {})
                if rule['attribute'] in attributes and attributes[rule['attribute']] == rule['value']:
                    typer.secho("--- VULNERABILITY FOUND! ---", fg=typer.colors.RED, bold=True)
                    typer.echo(f"  Rule ID:      {rule['id']}")
                    typer.secho(f"  Severity:     {rule['severity']}", fg=typer.colors.YELLOW)
                    typer.echo(f"  Description:  {rule['description']}")
                    typer.echo(f"  Resource:     {resource.get('type')} '{resource.get('name')}'\n")
                    vulnerabilities_found += 1

    # --- 3. Report Summary ---
    if vulnerabilities_found > 0:
        typer.secho(f"Scan Complete. Found {vulnerabilities_found} vulnerability(s).", fg=typer.colors.RED)
    else:
        typer.secho("Scan Complete. No vulnerabilities found. Good job!", fg=typer.colors.GREEN)

if __name__ == "__main__":
    app()