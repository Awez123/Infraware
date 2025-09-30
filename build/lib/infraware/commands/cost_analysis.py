"""
cost_analysis.py
Module for analyzing cloud resource costs.
"""

import typer
from rich.console import Console
import boto3
from google.cloud import billing_v1
from azure.mgmt.costmanagement import CostManagementClient
import pandas as pd

app = typer.Typer()
console = Console()

def analyze_aws_costs():
    """
    Analyze AWS costs using boto3 (placeholder).
    """
    client = boto3.client('ce')
    return {'provider': 'AWS', 'costs': 'Not implemented'}

def analyze_gcp_costs():
    """
    Analyze GCP costs using google-cloud-billing (placeholder).
    """
    client = billing_v1.CloudBillingClient()
    return {'provider': 'GCP', 'costs': 'Not implemented'}

def analyze_azure_costs():
    """
    Analyze Azure costs using azure-mgmt-costmanagement (placeholder).
    """
    # client = CostManagementClient(credentials, subscription_id)
    return {'provider': 'Azure', 'costs': 'Not implemented'}

def analyze_costs_with_pandas(resource_data):
    """
    Analyze costs using pandas for tabular data.
    """
    df = pd.DataFrame(resource_data)
    total_cost = df['cost'].sum() if 'cost' in df.columns else 0
    return {
        'total_cost': total_cost,
        'details': df.to_dict(orient='records')
    }

@app.command("aws")
def aws_cost():
    """Analyze AWS costs."""
    result = analyze_aws_costs()
    console.print(result)

@app.command("gcp")
def gcp_cost():
    """Analyze GCP costs."""
    result = analyze_gcp_costs()
    console.print(result)

@app.command("azure")
def azure_cost():
    """Analyze Azure costs."""
    result = analyze_azure_costs()
    console.print(result)

@app.command("pandas")
def pandas_cost():
    """Analyze costs with pandas (example data)."""
    sample_data = [
        {'resource': 'EC2', 'cost': 10},
        {'resource': 'S3', 'cost': 5}
    ]
    result = analyze_costs_with_pandas(sample_data)
    console.print(result)


# New subcommand: tf
@app.command("tf")
def tf_cost(file: str = typer.Option(..., help="Path to the Terraform .tf file.")):
    """Analyze costs from a Terraform .tf file."""
    import re
    resource_costs = {
        'aws_s3_bucket': 0.023,  # Example: $0.023 per GB-month
        'aws_ebs_volume': 0.10,  # Example: $0.10 per GB-month
    }
    resources = []
    try:
        with open(file, 'r') as f:
            content = f.read()
    except Exception as e:
        console.print(f"Error reading file: {e}", style="bold red")
        raise typer.Exit(code=1)

    # Simple regex to find resource blocks
    matches = re.findall(r'resource\s+"(\w+_\w+)"\s+"([^"]+)"', content)
    for res_type, res_name in matches:
        cost = resource_costs.get(res_type, 0.05)  # Default cost if unknown
        resources.append({'resource': res_type, 'name': res_name, 'cost': cost})

    result = analyze_costs_with_pandas(resources)
    console.print(result)

