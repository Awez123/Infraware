# in src/infraware/commands/scan.py

import json
import typer
from typing_extensions import Annotated

# Import our helper functions from the utils module
from infraware.utils.file_handler import load_rules_from_directory, load_ignores_from_directory

app = typer.Typer()

@app.command()
def scan(
    plan_file: Annotated[str, typer.Argument(help="Path to the terraform plan JSON file.")],
    rules_dir: Annotated[str, typer.Option("--rules-dir", help="Path to the directory containing YAML rule files.")] = "rules",
    ignore_dir: Annotated[str, typer.Option("--ignore-dir", help="Path to a directory containing ignore files.")] = None,
    # --- New option for output format ---
    output: Annotated[str, typer.Option("--output", help="Output format ('console' or 'json').")] = "console"
):
    """
    Scans a Terraform plan file for vulnerabilities based on a set of rules.
    """
    if output == 'console':
        typer.echo(f"Scanning plan: {plan_file}")

    rules = load_rules_from_directory(rules_dir)
    ignored_findings = []
    if ignore_dir:
        ignored_findings = load_ignores_from_directory(ignore_dir)

    try:
        with open(plan_file, 'r') as f: plan_data = json.load(f)
    except Exception as e:
        typer.secho(f"Error reading plan file: {e}", fg=typer.colors.RED, err=True); raise typer.Exit(code=1)

    # --- New list to collect findings before printing ---
    vulnerabilities = []
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
                        if ignored['resource_name'] == resource.get('name'):
                            is_ignored = True
                            break
                    
                    if is_ignored:
                        ignored_count += 1
                    else:
                        # --- Instead of printing, add the finding to our list ---
                        finding = {
                            "rule_id": rule['id'],
                            "severity": rule['severity'],
                            "description": rule['description'],
                            "resource_name": resource_full_name
                        }
                        vulnerabilities.append(finding)

    # --- New section to handle output at the end ---
    if output == "json":
        # Print the findings as a JSON array
        print(json.dumps(vulnerabilities, indent=2))
    else: # Default to console output
        for finding in vulnerabilities:
            typer.secho("--- VULNERABILITY FOUND! ---", fg=typer.colors.RED, bold=True)
            typer.echo(f"  Rule ID:      {finding['rule_id']}")
            typer.secho(f"  Severity:     {finding['severity']}", fg=typer.colors.YELLOW)
            typer.echo(f"  Description:  {finding['description']}")
            typer.echo(f"  Resource:     {finding['resource_name']}\n")
        
        typer.secho("--- Scan Summary ---", bold=True)
        if vulnerabilities:
            typer.secho(f"Found {len(vulnerabilities)} vulnerability(s).", fg=typer.colors.RED)
        else:
            typer.secho("No new vulnerabilities found. Good job!", fg=typer.colors.GREEN)
        
        if ignored_count > 0:
            typer.secho(f"Ignored {ignored_count} finding(s) based on ignore files.", fg=typer.colors.BLUE)