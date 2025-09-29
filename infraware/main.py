import json
import yaml
import typer
import os
from typing_extensions import Annotated

app = typer.Typer(help="InfraWare: An IaC Security and Quality Scanner.")

# (load_rules_from_directory function is unchanged)
def load_rules_from_directory(rules_dir: str) -> list:
    all_rules = []
    typer.echo(f"Loading rules from: {rules_dir}")
    try:
        for filename in os.listdir(rules_dir):
            if filename.endswith((".yaml", ".yml")):
                filepath = os.path.join(rules_dir, filename)
                with open(filepath, 'r') as f:
                    rules = yaml.safe_load(f)
                    if isinstance(rules, list):
                        all_rules.extend(rules)
        return all_rules
    except Exception as e:
        typer.secho(f"Error loading rules: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

# (load_ignores_from_directory function is unchanged)
def load_ignores_from_directory(ignore_dir: str) -> list:
    all_ignores = []
    typer.echo(f"Loading ignores from: {ignore_dir}")
    try:
        for filename in os.listdir(ignore_dir):
            if filename.endswith((".yaml", ".yml")):
                filepath = os.path.join(ignore_dir, filename)
                with open(filepath, 'r') as f:
                    ignores = yaml.safe_load(f)
                    if ignores and 'ignore' in ignores and isinstance(ignores['ignore'], list):
                        all_ignores.extend(ignores['ignore'])
        return all_ignores
    except Exception as e:
        typer.secho(f"Error loading ignores: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)


@app.command()
def scan(
    plan_file: Annotated[str, typer.Argument(help="Path to the terraform plan JSON file.")],
    rules_dir: Annotated[str, typer.Option("--rules-dir", help="Path to the directory containing YAML rule files.")] = "rules",
    ignore_dir: Annotated[str, typer.Option("--ignore-dir", help="Path to a directory containing ignore files.")] = None
):
    """
    Scans a Terraform plan file for vulnerabilities based on a set of rules.
    """
    typer.echo(f"Scanning plan: {plan_file}")
    rules = load_rules_from_directory(rules_dir)
    ignored_findings = []
    if ignore_dir and os.path.isdir(ignore_dir):
        ignored_findings = load_ignores_from_directory(ignore_dir)

    try:
        with open(plan_file, 'r') as f: plan_data = json.load(f)
    except Exception as e:
        typer.secho(f"Error reading plan file: {e}", fg=typer.colors.RED, err=True); raise typer.Exit(code=1)

    vulnerabilities_found = 0
    ignored_count = 0
    resources = plan_data.get('planned_values', {}).get('root_module', {}).get('resources', [])
    
    for rule in rules:
        for resource in resources:
            if resource.get('type') == rule['resource']:
                attributes = resource.get('values', {})
                if rule['attribute'] in attributes and attributes[rule['attribute']] == rule['value']:
                    resource_full_name = f"{resource.get('type')}.{resource.get('name')}"
                    is_ignored = False
                    for ignored in ignored_findings:
                        # --- THIS IS THE CHANGED LOGIC ---
                        # We now only check if the resource name matches.
                        if ignored['resource_name'] == resource.get('name'):
                            is_ignored = True
                            ignored_count += 1
                            break
                    
                    if not is_ignored:
                        vulnerabilities_found += 1
                        typer.secho("--- VULNERABILITY FOUND! ---", fg=typer.colors.RED, bold=True)
                        typer.echo(f"  Rule ID:      {rule['id']}")
                        typer.secho(f"  Severity:     {rule['severity']}", fg=typer.colors.YELLOW)
                        typer.echo(f"  Description:  {rule['description']}")
                        typer.echo(f"  Resource:     {resource_full_name}\n")

    typer.secho("--- Scan Summary ---", bold=True)
    if vulnerabilities_found > 0:
        typer.secho(f"Found {vulnerabilities_found} vulnerability(s).", fg=typer.colors.RED)
    else:
        typer.secho("No new vulnerabilities found. Good job!", fg=typer.colors.GREEN)
    
    if ignored_count > 0:
        typer.secho(f"Ignored {ignored_count} finding(s) based on ignore files.", fg=typer.colors.BLUE)

if __name__ == "__main__":
    app()