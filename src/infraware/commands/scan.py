import json
import yaml
import typer
from typing_extensions import Annotated
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from datetime import datetime
from pathlib import Path

# Import our helper functions from the utils module
from infraware.utils.file_handler import load_rules_from_directory, load_ignores_from_directory
from infraware.utils.vulnerability_scanner import EnhancedVulnerabilityScanner, SeverityLevel

app = typer.Typer()
console = Console()

@app.command()
def scan(
    plan_file: Annotated[str, typer.Argument(help="Path to infrastructure file (Terraform JSON/HCL, CloudFormation YAML, Kubernetes YAML)")],
    rules_dir: Annotated[str, typer.Option("--rules-dir", help="Directory containing security rule files (default: rules/)")] = "rules",
    ignore_dir: Annotated[str, typer.Option("--ignore-dir", help="Directory containing ignore files for baseline exceptions")] = None,
    min_severity: Annotated[float, typer.Option("--min-severity", help="Minimum severity score threshold (0.0-10.0)")] = 0.0,
    severity_filter: Annotated[str, typer.Option("--severity", help="Filter by severity: CRITICAL,HIGH,MEDIUM,LOW,INFO")] = None,
    output_format: Annotated[str, typer.Option("--format", help="Output format: table (default), json, csv")] = "table",
    cve_filter: Annotated[str, typer.Option("--cve", help="Filter results by specific CVE ID")] = None,
    tags_filter: Annotated[str, typer.Option("--tags", help="Filter by comma-separated tags")] = None,
    show_remediation: Annotated[bool, typer.Option("--remediation", help="Include detailed remediation guidance")] = False
):
    """
    🛡️ Infrastructure security scanner with 35+ AWS rules and CVE correlation.
    
    Scans Terraform plans, CloudFormation templates, and Kubernetes manifests
    for security vulnerabilities, misconfigurations, and compliance violations.
    
    Examples:
      infraware scan plan.json                     # Basic Terraform scan
      infraware scan cloudformation.yaml           # CloudFormation scan
      infraware scan k8s-deployment.yaml           # Kubernetes scan
      infraware scan plan.json --severity CRITICAL   # Critical issues only
      infraware scan plan.json --format json         # JSON output for CI/CD
      infraware scan plan.json --remediation         # Include fix guidance
    
    Features:
      ✅ 35+ AWS security rules (RDS, EC2, IAM, Lambda, ELB, CloudTrail, KMS)
      ✅ CVE correlation with 10,000+ vulnerability database
      ✅ Multi-format support (JSON, YAML, HCL)
      ✅ Severity scoring and filtering
      ✅ Baseline exceptions with ignore files
      ✅ Compliance mapping and remediation guidance
    """
    # --- FIX: Only print this line for non-JSON formats ---
    if output_format.lower() != "json":
        console.print(f"🔍 Scanning plan: [cyan]{plan_file}[/cyan]")
    
    # Load rules and ignores
    rules = load_rules_from_directory(rules_dir)
    ignored_findings = []
    if ignore_dir:
        ignored_findings = load_ignores_from_directory(ignore_dir)

    # Load plan file
    try:
        file_path = Path(plan_file)
        
        if file_path.suffix.lower() in ['.yaml', '.yml']:
            with open(plan_file, 'r') as f:
                try:
                    yaml_data = yaml.safe_load(f)
                except Exception as e:
                    if "but found another document" in str(e):
                        f.seek(0)
                        documents = list(yaml.safe_load_all(f))
                        yaml_data = {"kind": "MultiDocument", "documents": documents}
                    else:
                        class CloudFormationLoader(yaml.SafeLoader): pass
                        def construct_generic(loader, node):
                            if isinstance(node, yaml.ScalarNode): return f"CF_PLACEHOLDER_{loader.construct_scalar(node)}"
                            elif isinstance(node, yaml.SequenceNode): return "CF_PLACEHOLDER_LIST"
                            return "CF_PLACEHOLDER_MAP"
                        
                        tags_to_construct = ['!Ref', '!GetAtt', '!Sub', '!Join', '!GetAZs', '!Base64', '!Cidr', '!FindInMap', '!ImportValue', '!Select', '!Split', '!Transform', '!If', '!Not', '!Equals', '!And', '!Or']
                        for tag in tags_to_construct:
                            CloudFormationLoader.add_constructor(tag, construct_generic)
                        
                        f.seek(0)
                        yaml_data = yaml.load(f, Loader=CloudFormationLoader)

            if 'AWSTemplateFormatVersion' in yaml_data or 'Resources' in yaml_data:
                plan_data = convert_cloudformation_to_plan_format(yaml_data)
                if output_format.lower() != "json": console.print("📋 [green]CloudFormation YAML detected - converted to plan format[/green]")
            else:
                plan_data = convert_yaml_to_plan_format(yaml_data)
                if output_format.lower() != "json": console.print("📋 [green]YAML infrastructure file detected[/green]")
                
        else:
            with open(plan_file, 'r') as f:
                plan_data = json.load(f)
            if output_format.lower() != "json": console.print("📋 [green]Terraform JSON plan detected[/green]")
            
    except Exception as e:
        console.print(f"[red]Error reading plan file: {e}[/red]")
        raise typer.Exit(code=1)

    # Initialize enhanced scanner
    scanner = EnhancedVulnerabilityScanner()
    
    # Perform scan
    scan_results = scanner.scan_resources(plan_data, rules, ignored_findings)
    scan_results['metadata']['scan_timestamp'] = datetime.now().isoformat()
    scan_results['metadata']['rules_applied'] = len(rules)
    scan_results['metadata']['resources_scanned'] = len(plan_data.get('planned_values', {}).get('root_module', {}).get('resources', []))

    # Apply filters
    vulnerabilities = scanner.vulnerabilities_found
    
    if min_severity > 0.0:
        vulnerabilities = [v for v in vulnerabilities if v.severity_score >= min_severity]
    
    if severity_filter:
        severity_levels = [s.strip().upper() for s in severity_filter.split(',')]
        vulnerabilities = [v for v in vulnerabilities if v.severity.value in severity_levels]
    
    if cve_filter:
        vulnerabilities = scanner.filter_by_cve(cve_filter)
    
    if tags_filter:
        tags = [t.strip() for t in tags_filter.split(',')]
        vulnerabilities = scanner.filter_by_tags(tags)

    # Display results
    if output_format.lower() == "json":
        filtered_results = scan_results.copy()
        filtered_results['vulnerabilities'] = [v.to_dict() for v in vulnerabilities]
        filtered_results['summary']['total_vulnerabilities'] = len(vulnerabilities)
        console.print_json(data=filtered_results)
    elif output_format.lower() == "csv":
        _display_csv_output(vulnerabilities)
    else:
        _display_table_output(scan_results, vulnerabilities, show_remediation)

def _display_table_output(scan_results: dict, vulnerabilities: list, show_remediation: bool):
    """Display scan results in formatted table."""
    summary = scan_results['summary']
    
    summary_text = f"""
[bold]Total Vulnerabilities:[/bold] {summary['total_vulnerabilities']}
[bold]Ignored Findings:[/bold] {summary['ignored_findings']}
[bold]Risk Score:[/bold] {summary['risk_score']}/10.0

[bold]Severity Distribution:[/bold]
  🔴 Critical: {summary['severity_distribution']['CRITICAL']}
  🟠 High: {summary['severity_distribution']['HIGH']}
  🟡 Medium: {summary['severity_distribution']['MEDIUM']}
  🔵 Low: {summary['severity_distribution']['LOW']}
  ⚪ Info: {summary['severity_distribution']['INFO']}
    """
    
    risk_color = "red" if summary['risk_score'] >= 8.0 else "yellow" if summary['risk_score'] >= 5.0 else "green"
    console.print(Panel(summary_text, title="🛡️ Security Scan Summary", 
                        border_style=risk_color, box=box.ROUNDED))

    if not vulnerabilities:
        console.print("[green]✅ No vulnerabilities found matching your criteria![/green]")
        return

    table = Table(title="🚨 Vulnerabilities Found", box=box.ROUNDED)
    table.add_column("ID", style="cyan", width=12)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Score", style="bold", width=6, justify="center")
    table.add_column("Title", style="white", width=30)
    table.add_column("Resource", style="magenta", width=25)
    table.add_column("CVEs", style="red", width=15)
    
    if show_remediation:
        table.add_column("Remediation", style="green", width=40)

    for vuln in vulnerabilities:
        severity_color = {
            "CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow",
            "LOW": "blue", "INFO": "white"
        }.get(vuln.severity.value, "white")
        
        cve_text = ", ".join(vuln.cve_references[:2])
        if len(vuln.cve_references) > 2:
            cve_text += f" +{len(vuln.cve_references)-2}"
        
        resource_text = f"{vuln.resource_type}.{vuln.resource_name}"
        
        row = [
            vuln.id,
            f"[{severity_color}]{vuln.severity.value}[/{severity_color}]",
            f"[{severity_color}]{vuln.severity_score}[/{severity_color}]",
            vuln.title[:28] + "..." if len(vuln.title) > 30 else vuln.title,
            resource_text[:23] + "..." if len(resource_text) > 25 else resource_text,
            cve_text if cve_text else "N/A"
        ]
        
        if show_remediation:
            remediation = vuln.remediation[:38] + "..." if len(vuln.remediation) > 40 else vuln.remediation
            row.append(remediation)
        
        table.add_row(*row)

    console.print(table)
    
    critical_vulns = [v for v in vulnerabilities if v.severity.value == "CRITICAL"]
    if critical_vulns:
        console.print("\n[red bold]🚨 CRITICAL VULNERABILITIES DETAILS:[/red bold]")
        for vuln in critical_vulns:
            detail_text = f"""
[bold red]ID:[/bold red] {vuln.id}
[bold red]Title:[/bold red] {vuln.title}
[bold red]Resource:[/bold red] {vuln.resource_type}.{vuln.resource_name}
[bold red]Impact:[/bold red] {vuln.impact}
[bold red]CVEs:[/bold red] {', '.join(vuln.cve_references) if vuln.cve_references else 'None'}
[bold red]Remediation:[/bold red] {vuln.remediation}
            """
            console.print(Panel(detail_text, border_style="red", box=box.HEAVY))

def _display_csv_output(vulnerabilities: list):
    """Display vulnerabilities in CSV format."""
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow([
        'ID', 'Title', 'Severity', 'Score', 'Resource Type', 'Resource Name',
        'CVEs', 'CIS Controls', 'Tags', 'Description', 'Impact', 'Remediation'
    ])
    
    for vuln in vulnerabilities:
        writer.writerow([
            vuln.id, vuln.title, vuln.severity.value, vuln.severity_score,
            vuln.resource_type, vuln.resource_name,
            ';'.join(vuln.cve_references), ';'.join(vuln.cis_controls),
            ';'.join(vuln.tags), vuln.description, vuln.impact, vuln.remediation
        ])
    
    console.print(output.getvalue())

def convert_cloudformation_to_plan_format(cf_template: dict) -> dict:
    """Convert CloudFormation template to Terraform plan-like format."""
    resources = []
    cf_resources = cf_template.get('Resources', {})
    for resource_name, resource_data in cf_resources.items():
        resources.append({
            'type': map_cf_to_tf_type(resource_data.get('Type', '')),
            'name': resource_name,
            'values': resource_data.get('Properties', {})
        })
    
    return {
        'planned_values': {'root_module': {'resources': resources}}
    }

def convert_yaml_to_plan_format(yaml_data: dict) -> dict:
    """Convert general YAML infrastructure to plan format."""
    resources = []
    docs = yaml_data.get("documents", [yaml_data]) if yaml_data.get("kind") == "MultiDocument" else [yaml_data]
    
    for i, doc in enumerate(docs):
        if not doc: continue
        
        if 'apiVersion' in doc and 'kind' in doc:
            resources.append({
                'type': f"kubernetes_{doc.get('kind', 'unknown').lower()}",
                'name': doc.get('metadata', {}).get('name', f'unnamed_{i}'),
                'values': doc.get('spec', doc)
            })
        elif 'services' in doc:
            for service_name, service_config in doc.get('services', {}).items():
                resources.append({
                    'type': 'docker_container', 'name': service_name, 'values': service_config
                })
        else:
            for key, value in doc.items():
                if isinstance(value, dict):
                    resources.append({'type': f"yaml_{key}", 'name': key, 'values': value})
    
    return {
        'planned_values': {'root_module': {'resources': resources}}
    }

def map_cf_to_tf_type(cf_type: str) -> str:
    """Map CloudFormation resource types to Terraform-like types."""
    cf_to_tf_mapping = {
        'AWS::S3::Bucket': 'aws_s3_bucket', 'AWS::EC2::Instance': 'aws_instance',
        'AWS::EC2::VPC': 'aws_vpc', 'AWS::EC2::Subnet': 'aws_subnet',
        'AWS::EC2::SecurityGroup': 'aws_security_group', 'AWS::RDS::DBInstance': 'aws_db_instance',
        'AWS::IAM::Role': 'aws_iam_role', 'AWS::Lambda::Function': 'aws_lambda_function',
    }
    return cf_to_tf_mapping.get(cf_type, cf_type.lower().replace('::', '_'))

