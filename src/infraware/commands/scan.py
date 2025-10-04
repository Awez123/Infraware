# in src/infraware/commands/scan.py

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
<<<<<<< HEAD
    plan_file: Annotated[str, typer.Argument(help="Path to the terraform plan JSON file.")],
    rules_dir: Annotated[str, typer.Option("--rules-dir", help="Path to the directory containing YAML rule files.")] = "rules",
    ignore_dir: Annotated[str, typer.Option("--ignore-dir", help="Path to a directory containing ignore files.")] = None,
    # --- New option for output format ---
    output: Annotated[str, typer.Option("--output", help="Output format ('console' or 'json').")] = "console"
=======
    plan_file: Annotated[str, typer.Argument(help="Path to infrastructure file (Terraform JSON/HCL, CloudFormation YAML, Kubernetes YAML)")],
    rules_dir: Annotated[str, typer.Option("--rules-dir", help="Directory containing security rule files (default: rules/)")] = "rules",
    ignore_dir: Annotated[str, typer.Option("--ignore-dir", help="Directory containing ignore files for baseline exceptions")] = None,
    min_severity: Annotated[float, typer.Option("--min-severity", help="Minimum severity score threshold (0.0-10.0)")] = 0.0,
    severity_filter: Annotated[str, typer.Option("--severity", help="Filter by severity: CRITICAL,HIGH,MEDIUM,LOW,INFO")] = None,
    output_format: Annotated[str, typer.Option("--format", help="Output format: table (default), json, csv")] = "table",
    cve_filter: Annotated[str, typer.Option("--cve", help="Filter results by specific CVE ID")] = None,
    tags_filter: Annotated[str, typer.Option("--tags", help="Filter by comma-separated tags")] = None,
    show_remediation: Annotated[bool, typer.Option("--remediation", help="Include detailed remediation guidance")] = False
>>>>>>> c676e1f815d5e5856289fd851740c8bcfcff0065
):
    """
    🛡️ Infrastructure security scanner with 35+ AWS rules and CVE correlation.
    
    Scans Terraform plans, CloudFormation templates, and Kubernetes manifests
    for security vulnerabilities, misconfigurations, and compliance violations.
    
    Examples:
      infraware scan plan.json                          # Basic Terraform scan
      infraware scan cloudformation.yaml                # CloudFormation scan
      infraware scan k8s-deployment.yaml               # Kubernetes scan
      infraware scan plan.json --severity CRITICAL     # Critical issues only
      infraware scan plan.json --format json           # JSON output for CI/CD
      infraware scan plan.json --remediation           # Include fix guidance
    
    Features:
      ✅ 35+ AWS security rules (RDS, EC2, IAM, Lambda, ELB, CloudTrail, KMS)
      ✅ CVE correlation with 10,000+ vulnerability database
      ✅ Multi-format support (JSON, YAML, HCL)
      ✅ Severity scoring and filtering
      ✅ Baseline exceptions with ignore files
      ✅ Compliance mapping and remediation guidance
    """
<<<<<<< HEAD
    if output == 'console':
        typer.echo(f"Scanning plan: {plan_file}")

=======
    console.print(f"🔍 Scanning plan: [cyan]{plan_file}[/cyan]")
    
    # Load rules and ignores
>>>>>>> c676e1f815d5e5856289fd851740c8bcfcff0065
    rules = load_rules_from_directory(rules_dir)
    ignored_findings = []
    if ignore_dir:
        ignored_findings = load_ignores_from_directory(ignore_dir)

    # Load plan file
    try:
<<<<<<< HEAD
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
=======
        file_path = Path(plan_file)
        
        if file_path.suffix.lower() in ['.yaml', '.yml']:
            # Load YAML file (CloudFormation, Kubernetes, etc.)
            with open(plan_file, 'r') as f:
                try:
                    # Try to load as standard YAML first (single document)
                    yaml_data = yaml.safe_load(f)
                except Exception as e:
                    console.print(f"[yellow]⚠️ Standard YAML parsing failed: {e}[/yellow]")
                    
                    # Check if it's a multi-document YAML (Kubernetes style)
                    if "but found another document" in str(e):
                        console.print("[yellow]Detected multi-document YAML (Kubernetes/Docker Compose)[/yellow]")
                        f.seek(0)
                        try:
                            # Load all documents and combine them
                            documents = list(yaml.safe_load_all(f))
                            # Create a wrapper structure for multiple docs
                            yaml_data = {
                                "kind": "MultiDocument",
                                "documents": documents
                            }
                        except Exception as e2:
                            console.print(f"[yellow]Multi-document parsing also failed: {e2}[/yellow]")
                            console.print("[yellow]Attempting CloudFormation-specific parsing...[/yellow]")
                            
                            # Try CloudFormation parsing as fallback
                            class CloudFormationLoader(yaml.SafeLoader):
                                pass
                            
                            def construct_ref(loader, node):
                                value = loader.construct_scalar(node)
                                return f"REF_PLACEHOLDER_{value}"
                            
                            def construct_getatt(loader, node):
                                if isinstance(node, yaml.ScalarNode):
                                    value = loader.construct_scalar(node)
                                    return f"GETATT_PLACEHOLDER_{value}"
                                else:
                                    values = loader.construct_sequence(node)
                                    return f"GETATT_PLACEHOLDER_{'.'.join(map(str, values))}"
                            
                            def construct_sub(loader, node):
                                if isinstance(node, yaml.ScalarNode):
                                    value = loader.construct_scalar(node)
                                    return f"SUB_PLACEHOLDER_{value}"
                                else:
                                    values = loader.construct_sequence(node)
                                    return f"SUB_PLACEHOLDER_{values[0] if values else 'unknown'}"
                            
                            def construct_join(loader, node):
                                values = loader.construct_sequence(node)
                                return f"JOIN_PLACEHOLDER_{len(values)}_items"
                            
                            def construct_getazs(loader, node):
                                if isinstance(node, yaml.ScalarNode):
                                    value = loader.construct_scalar(node)
                                    return f"GETAZS_PLACEHOLDER_{value}"
                                else:
                                    return "GETAZS_PLACEHOLDER_region"
                            
                            def construct_generic(loader, node):
                                if isinstance(node, yaml.ScalarNode):
                                    return f"CF_PLACEHOLDER_{loader.construct_scalar(node)}"
                                elif isinstance(node, yaml.SequenceNode):
                                    return f"CF_PLACEHOLDER_LIST"
                                elif isinstance(node, yaml.MappingNode):
                                    return f"CF_PLACEHOLDER_MAP"
                                else:
                                    return "CF_PLACEHOLDER_UNKNOWN"
                            
                            # Register all CloudFormation intrinsic functions
                            CloudFormationLoader.add_constructor('!Ref', construct_ref)
                            CloudFormationLoader.add_constructor('!GetAtt', construct_getatt)
                            CloudFormationLoader.add_constructor('!Sub', construct_sub)
                            CloudFormationLoader.add_constructor('!Join', construct_join)
                            CloudFormationLoader.add_constructor('!GetAZs', construct_getazs)
                            CloudFormationLoader.add_constructor('!Base64', construct_generic)
                            CloudFormationLoader.add_constructor('!Cidr', construct_generic)
                            CloudFormationLoader.add_constructor('!FindInMap', construct_generic)
                            CloudFormationLoader.add_constructor('!ImportValue', construct_generic)
                            CloudFormationLoader.add_constructor('!Select', construct_generic)
                            CloudFormationLoader.add_constructor('!Split', construct_generic)
                            CloudFormationLoader.add_constructor('!Transform', construct_generic)
                            CloudFormationLoader.add_constructor('!If', construct_generic)
                            CloudFormationLoader.add_constructor('!Not', construct_generic)
                            CloudFormationLoader.add_constructor('!Equals', construct_generic)
                            CloudFormationLoader.add_constructor('!And', construct_generic)
                            CloudFormationLoader.add_constructor('!Or', construct_generic)
                            
                            f.seek(0)
                            try:
                                yaml_data = yaml.load(f, Loader=CloudFormationLoader)
                            except Exception as e3:
                                console.print(f"[red]Failed to parse CloudFormation YAML: {e3}[/red]")
                                console.print("[red]This may be a complex template with unsupported syntax[/red]")
                                raise typer.Exit(code=1)
                    else:
                        console.print("[yellow]Attempting CloudFormation-specific parsing...[/yellow]")
                        
                        # Create CloudFormation-aware YAML loader
                        class CloudFormationLoader(yaml.SafeLoader):
                            pass
                        
                        def construct_ref(loader, node):
                            value = loader.construct_scalar(node)
                            return f"REF_PLACEHOLDER_{value}"
                        
                        def construct_getatt(loader, node):
                            if isinstance(node, yaml.ScalarNode):
                                value = loader.construct_scalar(node)
                                return f"GETATT_PLACEHOLDER_{value}"
                            else:
                                values = loader.construct_sequence(node)
                                return f"GETATT_PLACEHOLDER_{'.'.join(map(str, values))}"
                        
                        def construct_sub(loader, node):
                            if isinstance(node, yaml.ScalarNode):
                                value = loader.construct_scalar(node)
                                return f"SUB_PLACEHOLDER_{value}"
                            else:
                                values = loader.construct_sequence(node)
                                return f"SUB_PLACEHOLDER_{values[0] if values else 'unknown'}"
                        
                        def construct_join(loader, node):
                            values = loader.construct_sequence(node)
                            return f"JOIN_PLACEHOLDER_{len(values)}_items"
                        
                        def construct_getazs(loader, node):
                            if isinstance(node, yaml.ScalarNode):
                                value = loader.construct_scalar(node)
                                return f"GETAZS_PLACEHOLDER_{value}"
                            else:
                                return "GETAZS_PLACEHOLDER_region"
                        
                        def construct_generic(loader, node):
                            if isinstance(node, yaml.ScalarNode):
                                return f"CF_PLACEHOLDER_{loader.construct_scalar(node)}"
                            elif isinstance(node, yaml.SequenceNode):
                                return f"CF_PLACEHOLDER_LIST"
                            elif isinstance(node, yaml.MappingNode):
                                return f"CF_PLACEHOLDER_MAP"
                            else:
                                return "CF_PLACEHOLDER_UNKNOWN"
                        
                        # Register all CloudFormation intrinsic functions
                        CloudFormationLoader.add_constructor('!Ref', construct_ref)
                        CloudFormationLoader.add_constructor('!GetAtt', construct_getatt)
                        CloudFormationLoader.add_constructor('!Sub', construct_sub)
                        CloudFormationLoader.add_constructor('!Join', construct_join)
                        CloudFormationLoader.add_constructor('!GetAZs', construct_getazs)
                        CloudFormationLoader.add_constructor('!Base64', construct_generic)
                        CloudFormationLoader.add_constructor('!Cidr', construct_generic)
                        CloudFormationLoader.add_constructor('!FindInMap', construct_generic)
                        CloudFormationLoader.add_constructor('!ImportValue', construct_generic)
                        CloudFormationLoader.add_constructor('!Select', construct_generic)
                        CloudFormationLoader.add_constructor('!Split', construct_generic)
                        CloudFormationLoader.add_constructor('!Transform', construct_generic)
                        CloudFormationLoader.add_constructor('!If', construct_generic)
                        CloudFormationLoader.add_constructor('!Not', construct_generic)
                        CloudFormationLoader.add_constructor('!Equals', construct_generic)
                        CloudFormationLoader.add_constructor('!And', construct_generic)
                        CloudFormationLoader.add_constructor('!Or', construct_generic)
                        
                        f.seek(0)
                        try:
                            yaml_data = yaml.load(f, Loader=CloudFormationLoader)
                        except Exception as e2:
                            console.print(f"[red]Failed to parse CloudFormation YAML: {e2}[/red]")
                            console.print("[red]This may be a complex CloudFormation template with unsupported syntax[/red]")
                            raise typer.Exit(code=1)
            
            # Convert CloudFormation YAML to compatible format
            if 'AWSTemplateFormatVersion' in yaml_data or 'Resources' in yaml_data:
                plan_data = convert_cloudformation_to_plan_format(yaml_data)
                console.print("📋 [green]CloudFormation YAML detected - converted to plan format[/green]")
            else:
                # Handle other YAML types (Kubernetes, Docker Compose, etc.)
                plan_data = convert_yaml_to_plan_format(yaml_data)
                console.print("📋 [green]YAML infrastructure file detected[/green]")
                
        else:
            # Load JSON file (Terraform plan)
            with open(plan_file, 'r') as f:
                plan_data = json.load(f)
            console.print("📋 [green]Terraform JSON plan detected[/green]")
            
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
        # Update scan results with filtered vulnerabilities
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
    
    # Summary panel
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

    # Vulnerabilities table
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
        # Color code severity
        severity_color = {
            "CRITICAL": "red",
            "HIGH": "orange3", 
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "white"
        }.get(vuln.severity.value, "white")
        
        cve_text = ", ".join(vuln.cve_references[:2])  # Show first 2 CVEs
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
    
    # Show detailed view for critical vulnerabilities
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
    
    # Header
    writer.writerow([
        'ID', 'Title', 'Severity', 'Score', 'Resource Type', 'Resource Name',
        'CVEs', 'CIS Controls', 'Tags', 'Description', 'Impact', 'Remediation'
    ])
    
    # Data
    for vuln in vulnerabilities:
        writer.writerow([
            vuln.id,
            vuln.title,
            vuln.severity.value,
            vuln.severity_score,
            vuln.resource_type,
            vuln.resource_name,
            ';'.join(vuln.cve_references),
            ';'.join(vuln.cis_controls),
            ';'.join(vuln.tags),
            vuln.description,
            vuln.impact,
            vuln.remediation
        ])
    
    console.print(output.getvalue())

def convert_cloudformation_to_plan_format(cf_template: dict) -> dict:
    """Convert CloudFormation template to Terraform plan-like format."""
    resources = []
    
    cf_resources = cf_template.get('Resources', {})
    for resource_name, resource_data in cf_resources.items():
        resource_type = resource_data.get('Type', '')
        resource_properties = resource_data.get('Properties', {})
        
        # Map CloudFormation resource types to Terraform-like types
        tf_type = map_cf_to_tf_type(resource_type)
        
        # Create Terraform plan-like resource
        tf_resource = {
            'type': tf_type,
            'name': resource_name,
            'values': resource_properties
        }
        resources.append(tf_resource)
    
    # Create plan-like structure
    plan_data = {
        'planned_values': {
            'root_module': {
                'resources': resources
            }
        }
    }
    
    return plan_data

def convert_yaml_to_plan_format(yaml_data: dict) -> dict:
    """Convert general YAML infrastructure to plan format."""
    resources = []
    
    # Handle multi-document YAML (Kubernetes)
    if isinstance(yaml_data, dict) and yaml_data.get("kind") == "MultiDocument":
        for i, doc in enumerate(yaml_data.get("documents", [])):
            if doc is None:
                continue
            
            # Handle Kubernetes documents
            if 'apiVersion' in doc and 'kind' in doc:
                resource = {
                    'type': f"kubernetes_{doc.get('kind', 'unknown').lower()}",
                    'name': doc.get('metadata', {}).get('name', f'unnamed_{i}'),
                    'values': doc.get('spec', doc)  # Use spec or full document
                }
                resources.append(resource)
            
            # Handle other document types
            else:
                for key, value in doc.items():
                    if isinstance(value, dict):
                        resource = {
                            'type': f"yaml_{key}",
                            'name': f"{key}_{i}",
                            'values': value
                        }
                        resources.append(resource)
    
    # Handle Kubernetes YAML (single document)
    elif 'apiVersion' in yaml_data and 'kind' in yaml_data:
        resource = {
            'type': f"kubernetes_{yaml_data.get('kind', 'unknown').lower()}",
            'name': yaml_data.get('metadata', {}).get('name', 'unnamed'),
            'values': yaml_data.get('spec', yaml_data)  # Use spec or full document
        }
        resources.append(resource)
    
    # Handle Docker Compose
    elif 'services' in yaml_data:
        for service_name, service_config in yaml_data.get('services', {}).items():
            resource = {
                'type': 'docker_container',
                'name': service_name,
                'values': service_config
            }
            resources.append(resource)
    
    # Handle other YAML formats
    else:
        # Generic handling
        for key, value in yaml_data.items():
            if isinstance(value, dict):
                resource = {
                    'type': f"yaml_{key}",
                    'name': key,
                    'values': value
                }
                resources.append(resource)
    
    # Create plan-like structure
    resource_changes = []
    for resource in resources:
        resource_change = {
            'address': f"{resource['type']}.{resource['name']}",
            'change': {
                'actions': ['create'],
                'after': resource['values']
            },
            'mode': 'managed',
            'type': resource['type'],
            'name': resource['name']
        }
        resource_changes.append(resource_change)
    
    plan_data = {
        'resource_changes': resource_changes,
        'planned_values': {
            'root_module': {
                'resources': resources
            }
        }
    }
    
    return plan_data

def map_cf_to_tf_type(cf_type: str) -> str:
    """Map CloudFormation resource types to Terraform-like types."""
    cf_to_tf_mapping = {
        'AWS::S3::Bucket': 'aws_s3_bucket',
        'AWS::EC2::Instance': 'aws_instance',
        'AWS::EC2::VPC': 'aws_vpc',
        'AWS::EC2::Subnet': 'aws_subnet',
        'AWS::EC2::SecurityGroup': 'aws_security_group',
        'AWS::RDS::DBInstance': 'aws_db_instance',
        'AWS::EBS::Volume': 'aws_ebs_volume',
        'AWS::IAM::Role': 'aws_iam_role',
        'AWS::IAM::Policy': 'aws_iam_policy',
        'AWS::Lambda::Function': 'aws_lambda_function',
        'AWS::EC2::InternetGateway': 'aws_internet_gateway',
        'AWS::EC2::RouteTable': 'aws_route_table',
        'AWS::AutoScaling::AutoScalingGroup': 'aws_autoscaling_group',
        'AWS::ElasticLoadBalancing::LoadBalancer': 'aws_lb',
        'AWS::CloudFormation::Stack': 'aws_cloudformation_stack'
    }
    
    return cf_to_tf_mapping.get(cf_type, cf_type.lower().replace('::', '_'))
>>>>>>> c676e1f815d5e5856289fd851740c8bcfcff0065
