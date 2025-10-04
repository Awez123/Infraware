# in src/infraware/commands/cost.py

import typer
import json
import yaml
from typing_extensions import Annotated
from rich.console import Console
from rich.table import Table

app = typer.Typer()
console = Console()

@app.command("analysis")
def cost_analysis(
    plan_file: Annotated[str, typer.Argument(help="Path to the Terraform plan JSON file.")],
    pricing_file: Annotated[str, typer.Option(help="Path to the custom pricing YAML file.")],
    # --- New option for output format ---
    output: Annotated[str, typer.Option("--output", help="Output format ('console' or 'json').")] = "console"
):
    """
    Analyzes a Terraform plan JSON to estimate resource costs using a local pricing file.
    """
    if output == "console":
        typer.echo(f"Analyzing costs for plan: {plan_file}...\n")

    # --- Load Plan and Pricing Files ---
    try:
        with open(plan_file, 'r') as f:
            plan_data = json.load(f)
        with open(pricing_file, 'r') as f:
            pricing_data = yaml.safe_load(f)
    except FileNotFoundError as e:
        typer.secho(f"Error: File not found - {e.filename}", fg=typer.colors.RED); raise typer.Exit(code=1)
    except (json.JSONDecodeError, yaml.YAMLError) as e:
        typer.secho(f"Error: Could not parse file. Please check for syntax errors: {e}", fg=typer.colors.RED); raise typer.Exit(code=1)

    # --- The Cost Analysis Engine ---
    cost_results = [] # <-- New list to collect results before printing
    total_monthly_cost = 0.0

    provider_configs = plan_data.get('configuration', {}).get('provider_config', {})
    aws_region = provider_configs.get('aws', {}).get('expressions', {}).get('region', {}).get('constant_value', 'us-east-1')

    resources = plan_data.get('planned_values', {}).get('root_module', {}).get('resources', [])
    for resource in resources:
        resource_type = resource.get('type')
        resource_name = resource.get('name')
        attributes = resource.get('values', {})
        hourly_cost = 0.0
        
        # --- Logic for AWS EC2 Instances ---
        if resource_type == 'aws_instance':
            instance_type = attributes.get('instance_type', 'unknown')
            prices = pricing_data.get('aws', {}).get('aws_instance', {}).get('region_prices', {}).get(aws_region, {})
            hourly_cost = prices.get(instance_type, {}).get('hourly', 0.0)

        # --- Logic for AWS EBS Volumes ---
        elif resource_type == 'aws_ebs_volume':
            volume_type = attributes.get('type', 'gp3')
            volume_size = attributes.get('size', 0)
            prices = pricing_data.get('aws', {}).get('aws_ebs_volume', {}).get('region_prices', {}).get(aws_region, {})
            monthly_per_gb = prices.get(volume_type, {}).get('monthly_per_gb', 0.0)
            hourly_cost = (monthly_per_gb * volume_size) / 730 if volume_size else 0.0

        monthly_cost = hourly_cost * 730
        total_monthly_cost += monthly_cost
        
        # --- Add the result to our list instead of printing ---
        cost_results.append({
            "resource": f"{resource_type}.{resource_name}",
            "type": attributes.get('instance_type') or attributes.get('type', '-'),
            "hourly_cost": round(hourly_cost, 4),
            "monthly_cost": round(monthly_cost, 2)
        })

    # --- New conditional output logic at the end ---
    if output == "json":
        # Create a final JSON object with resources and a summary
        final_output = {
            "resources": cost_results,
            "summary": {
                "total_monthly_cost": round(total_monthly_cost, 2)
            }
        }
        print(json.dumps(final_output, indent=2))
    else: # Default to console output
        table = Table("Resource", "Type", "Hourly Cost", "Monthly Cost")
        for result in cost_results:
            cost_display = f"${result['hourly_cost']:.4f}" if result['hourly_cost'] > 0 else "N/A"
            table.add_row(result['resource'], result['type'], cost_display, f"${result['monthly_cost']:.2f}")

        console.print(table)
        typer.secho(f"\nEstimated Total Monthly Cost: ${total_monthly_cost:.2f}", fg=typer.colors.GREEN, bold=True)