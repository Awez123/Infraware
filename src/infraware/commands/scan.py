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
from infraware.utils.file_handler import (
    load_rules_from_directory, 
    load_ignores_from_directory, 
    get_scannable_files, 
    get_directory_summary
)
from infraware.utils.vulnerability_scanner import EnhancedVulnerabilityScanner, SeverityLevel

app = typer.Typer(help="🛡️ Infrastructure security scanning with comprehensive analysis")
console = Console()

@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="File or directory to scan")],
    comprehensive: Annotated[bool, typer.Option("--comprehensive", help="Enable comprehensive analysis with all features")] = False,
    secrets: Annotated[bool, typer.Option("--secrets", help="Enable secret detection scanning")] = False,
    rules_dir: Annotated[str, typer.Option("--rules-dir", help="Directory containing security rule files")] = "rules",
    ignore_dir: Annotated[str, typer.Option("--ignore-dir", help="Directory containing ignore files for baseline exceptions")] = None,
    min_severity: Annotated[float, typer.Option("--min-severity", help="Minimum severity score threshold (0.0-10.0)")] = 0.0,
    severity: Annotated[str, typer.Option("--severity", help="Filter by severity: CRITICAL,HIGH,MEDIUM,LOW,INFO")] = None,
    format: Annotated[str, typer.Option("--format", help="Output format: table (default), json, csv")] = "table",
    cve: Annotated[str, typer.Option("--cve", help="Filter results by specific CVE ID")] = None,
    tags: Annotated[str, typer.Option("--tags", help="Filter by comma-separated tags")] = None,
    remediation: Annotated[bool, typer.Option("--remediation", help="Include detailed remediation guidance")] = False,
    quick: Annotated[bool, typer.Option("--quick", help="Fast scan mode - limits files processed for performance")] = False,
    max_files: Annotated[int, typer.Option("--max-files", help="Maximum number of files to scan in directory mode")] = 100
):
    """
    �️ Scan infrastructure files for security vulnerabilities and misconfigurations.
    
    Supports .json files (Terraform plans, CloudFormation templates).
    Use --comprehensive for full analysis including secrets and CVE correlation.
    """
    
    # Show scan configuration
    if comprehensive:
        console.print("🔍 [bold cyan]Comprehensive Security Analysis[/bold cyan]")
    elif secrets:
        console.print("🔐 [bold yellow]Secret Detection Scan[/bold yellow]") 
    else:
        console.print("🛡️ [bold green]Security Vulnerability Scan[/bold green]")
    
    console.print(f"📂 Target: [cyan]{target}[/cyan]")
    
    # Check if target exists
    target_path = Path(target)
    if not target_path.exists():
        console.print(f"❌ [red]Error: Target '{target}' not found[/red]")
        raise typer.Exit(code=1)
    
    # Handle directory vs file
    if target_path.is_dir():
        console.print(f"📁 [blue]Directory scan mode[/blue]")
        files_to_scan = get_scannable_files(str(target_path), max_files if quick else 1000)
        console.print(f"📋 Found {len(files_to_scan)} scannable files")
    else:
        # Verify file extension
        if target_path.suffix.lower() not in ['.json']:
            console.print(f"⚠️ [yellow]Warning: File extension '{target_path.suffix}' may not be supported[/yellow]")
            console.print("💡 [dim]Supported formats: .json (Terraform plans, CloudFormation)[/dim]")
        files_to_scan = [str(target_path)]
    
    if not files_to_scan:
        console.print("❌ [red]No scannable files found[/red]")
        raise typer.Exit(code=1)
    
    # Load security rules
    try:
        security_rules = load_rules_from_directory(rules_dir)
        console.print(f"📜 Loaded {len(security_rules)} security rules")
    except Exception as e:
        console.print(f"⚠️ [yellow]Warning: Rules directory '{rules_dir}' not found.[/yellow]")
        security_rules = []
    
    # Load ignore patterns if specified
    ignore_patterns = []
    if ignore_dir:
        try:
            ignore_patterns = load_ignores_from_directory(ignore_dir)
            console.print(f"🚫 Loaded {len(ignore_patterns)} ignore patterns")
        except Exception as e:
            console.print(f"⚠️ [yellow]Warning: Could not load ignore patterns: {e}[/yellow]")
    
    # Initialize scanner
    scanner = EnhancedVulnerabilityScanner(security_rules)
    
    all_vulnerabilities = []
    total_resources = 0
    
    # Scan each file
    for file_path in files_to_scan:
        try:
            console.print(f"🔍 Scanning: [cyan]{file_path}[/cyan]")
            
            # Perform the scan
            if comprehensive:
                # Full comprehensive scan with all features
                result = scanner.comprehensive_scan(file_path)
            elif secrets:
                # Secrets-only scan
                from infraware.commands.secrets import secrets_scan_file
                result = secrets_scan_file(file_path)
            else:
                # Standard security scan
                result = scanner.scan_file(file_path)
            
            if "vulnerabilities" in result:
                vulnerabilities = result["vulnerabilities"]
                
                # Apply filters
                if min_severity > 0:
                    vulnerabilities = [v for v in vulnerabilities if v.get("severity_score", 0) >= min_severity]
                
                if severity:
                    severity_filter = severity.upper().split(',')
                    vulnerabilities = [v for v in vulnerabilities if v.get("severity", "").upper() in severity_filter]
                
                if cve:
                    vulnerabilities = [v for v in vulnerabilities 
                                    if cve.upper() in [c.upper() for c in v.get("references", {}).get("cve", [])]]
                
                if tags:
                    tag_filter = [t.strip().lower() for t in tags.split(',')]
                    vulnerabilities = [v for v in vulnerabilities 
                                    if any(tag in [t.lower() for t in v.get("tags", [])] for tag in tag_filter)]
                
                all_vulnerabilities.extend(vulnerabilities)
                total_resources += result.get("metadata", {}).get("resources_scanned", 0)
                
        except Exception as e:
            console.print(f"❌ [red]Error scanning {file_path}: {e}[/red]")
    
    # Generate output
    scan_result = {
        "summary": {
            "total_vulnerabilities": len(all_vulnerabilities),
            "ignored_findings": 0,  # TODO: Implement ignore logic
            "risk_score": sum(v.get("severity_score", 0) for v in all_vulnerabilities) / max(len(all_vulnerabilities), 1),
            "severity_distribution": {
                "CRITICAL": len([v for v in all_vulnerabilities if v.get("severity") == "CRITICAL"]),
                "HIGH": len([v for v in all_vulnerabilities if v.get("severity") == "HIGH"]),
                "MEDIUM": len([v for v in all_vulnerabilities if v.get("severity") == "MEDIUM"]),
                "LOW": len([v for v in all_vulnerabilities if v.get("severity") == "LOW"]),
                "INFO": len([v for v in all_vulnerabilities if v.get("severity") == "INFO"])
            }
        },
        "vulnerabilities": all_vulnerabilities,
        "metadata": {
            "scan_timestamp": datetime.now().isoformat(),
            "rules_applied": len(security_rules),
            "resources_scanned": total_resources,
            "scan_type": "comprehensive" if comprehensive else ("secrets" if secrets else "security")
        }
    }
    
    # Output results
    if format.lower() == "json":
        console.print(json.dumps(scan_result, indent=2))
    elif format.lower() == "csv":
        # CSV output implementation
        console.print("📄 [blue]CSV output format coming soon[/blue]")
    else:
        # Table output (default)
        _display_scan_results_table(scan_result, remediation)

def _display_scan_results_table(scan_result: dict, show_remediation: bool = False):
    """Display scan results in a formatted table"""
    summary = scan_result["summary"]
    vulnerabilities = scan_result["vulnerabilities"]
    
    # Summary panel
    console.print(Panel(
        f"🔍 [bold]Scan Summary[/bold]\n\n"
        f"Total Vulnerabilities: [red]{summary['total_vulnerabilities']}[/red]\n"
        f"Risk Score: [yellow]{summary['risk_score']:.1f}/10[/yellow]\n"
        f"Critical: [red]{summary['severity_distribution']['CRITICAL']}[/red] | "
        f"High: [red]{summary['severity_distribution']['HIGH']}[/red] | "
        f"Medium: [yellow]{summary['severity_distribution']['MEDIUM']}[/yellow] | "
        f"Low: [green]{summary['severity_distribution']['LOW']}[/green]",
        title="Scan Results",
        border_style="cyan"
    ))
    
    if vulnerabilities:
        table = Table(title="🛡️ Security Vulnerabilities", box=box.ROUNDED)
        table.add_column("ID", style="cyan")
        table.add_column("Severity", style="bold")
        table.add_column("Title", style="white")
        table.add_column("Resource", style="blue")
        if show_remediation:
            table.add_column("Remediation", style="green")
        
        for vuln in vulnerabilities[:20]:  # Limit to first 20 for readability
            severity = vuln.get("severity", "UNKNOWN")
            severity_style = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow", 
                "LOW": "green",
                "INFO": "blue"
            }.get(severity, "white")
            
            resource = vuln.get("resource", {})
            resource_name = f"{resource.get('type', 'unknown')}.{resource.get('name', 'unknown')}"
            
            row = [
                vuln.get("id", "N/A"),
                f"[{severity_style}]{severity}[/{severity_style}]",
                vuln.get("title", "No title"),
                resource_name
            ]
            
            if show_remediation:
                row.append(vuln.get("remediation", "No guidance available")[:50] + "...")
            
            table.add_row(*row)
        
        console.print(table)
        
        if len(vulnerabilities) > 20:
            console.print(f"... and {len(vulnerabilities) - 20} more vulnerabilities")
    
    console.print(f"\n[dim]Scan completed at {scan_result['metadata']['scan_timestamp']}[/dim]")

@app.command()
def preview(
    directory: Annotated[str, typer.Argument(help="Directory to preview")],
    max_files: Annotated[int, typer.Option("--max-files", help="Maximum files to list")] = 50
):
    """
    📋 Preview files that would be scanned in a directory.
    
    Use this to see what files InfraWare will process before running a full scan.
    """
    console.print(f"🗂️ Previewing directory: [cyan]{directory}[/cyan]")
    
    # Get directory summary
    summary = get_directory_summary(directory)
    
    if "error" in summary:
        console.print(f"[red]Error: {summary['error']}[/red]")
        raise typer.Exit(code=1)
    
    # Display summary
    table = Table(title="Directory Summary", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="green")
    
    table.add_row("Total Files", str(summary['total_files']))
    table.add_row("Scannable Files", str(summary['scannable_files']))
    table.add_row("Ignored Files", str(summary['ignored_files']))
    table.add_row("Directories", str(summary['directories']))
    
    console.print(table)
    
    # Display file types found
    if summary['file_types']:
        console.print("\n[bold blue]📊 File Types Found:[/bold blue]")
        for ext, count in summary['file_types'].items():
            if ext in ['.tf', '.json', '.yaml', '.yml', '.hcl']:
                console.print(f"  ✅ {ext}: {count} files")
            else:
                console.print(f"  ⏭️ {ext}: {count} files")
    
    # Display scannable files (limited)
    scannable_files = get_scannable_files(directory, max_files)
    if scannable_files:
        console.print(f"\n[bold green]🎯 Files to be scanned (showing first {min(len(scannable_files), max_files)}):[/bold green]")
        for i, file_path in enumerate(scannable_files[:max_files], 1):
            file_ext = Path(file_path).suffix
            console.print(f"   {i}. {Path(file_path).name} ({file_ext})")
        
        if len(scannable_files) > max_files:
            console.print(f"   ... and {len(scannable_files) - max_files} more files")
    else:
        console.print("\n[yellow]⚠️ No scannable files found in directory[/yellow]")
    table.add_row("Directories", str(summary['directories']))
    
    console.print(table)
    
    # Show file types
    if summary['file_types']:
        console.print("\n📊 File Types Found:")
        for ext, count in sorted(summary['file_types'].items()):
            icon = "✅" if ext in {'.tf', '.json', '.yaml', '.yml', '.hcl'} else "⏭️"
            console.print(f"  {icon} {ext or 'no extension'}: {count} files")
    
    # Show scannable files list
    scannable_files = get_scannable_files(directory, max_files)
    
    if scannable_files:
        console.print(f"\n🎯 Files to be scanned (showing first {len(scannable_files)}):")
        for i, file_path in enumerate(scannable_files[:20], 1):
            console.print(f"  {i:2d}. {Path(file_path).name} ({Path(file_path).suffix})")
        
        if len(scannable_files) > 20:
            console.print(f"  ... and {len(scannable_files) - 20} more files")
    else:
        console.print("\n[yellow]No scannable infrastructure files found![/yellow]")

def scan_single_file(file_path: str, rules: list, ignored_findings: list) -> dict:
    """Scan a single file and return results."""
    try:
        file_path_obj = Path(file_path)
        
        if file_path_obj.suffix.lower() in ['.yaml', '.yml']:
            with open(file_path, 'r') as f:
                try:
                    yaml_data = yaml.safe_load(f)
                except Exception as e:
                    if "but found another document" in str(e):
                        f.seek(0)
                        documents = list(yaml.safe_load_all(f))
                        yaml_data = {"kind": "MultiDocument", "documents": documents}
                    else:
                        return None
            
            if 'AWSTemplateFormatVersion' in yaml_data or 'Resources' in yaml_data:
                plan_data = convert_cloudformation_to_plan_format(yaml_data)
            else:
                plan_data = convert_yaml_to_plan_format(yaml_data)
        else:
            with open(file_path, 'r') as f:
                plan_data = json.load(f)
        
        # Initialize scanner and scan
        scanner = EnhancedVulnerabilityScanner()
        scan_results = scanner.scan_resources(plan_data, rules, ignored_findings)
        scan_results['metadata']['file_path'] = file_path
        
        return scan_results
        
    except Exception as e:
        return None

def aggregate_scan_results(results_list: list) -> dict:
    """Aggregate results from multiple file scans."""
    if not results_list:
        return {
            "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "findings": [],
            "metadata": {"scan_type": "directory"}
        }
    
    aggregated = {
        "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "findings": [],
        "metadata": {
            "scan_type": "directory",
            "scan_timestamp": datetime.now().isoformat(),
            "files_processed": len(results_list)
        }
    }
    
    for result in results_list:
        # Aggregate findings
        aggregated["findings"].extend(result.get("findings", []))
        
        # Aggregate summary counts
        summary = result.get("summary", {})
        for severity in ["critical", "high", "medium", "low", "info"]:
            aggregated["summary"][severity] += summary.get(severity, 0)
        aggregated["summary"]["total_findings"] += summary.get("total_findings", 0)
    
    return aggregated

@app.command()
def scan(
    plan_file: Annotated[str, typer.Argument(help="Path to infrastructure file/directory (Terraform JSON/HCL, CloudFormation YAML, Kubernetes YAML)")],
    rules_dir: Annotated[str, typer.Option("--rules-dir", help="Directory containing security rule files (default: rules/)")] = "rules",
    ignore_dir: Annotated[str, typer.Option("--ignore-dir", help="Directory containing ignore files for baseline exceptions")] = None,
    min_severity: Annotated[float, typer.Option("--min-severity", help="Minimum severity score threshold (0.0-10.0)")] = 0.0,
    severity_filter: Annotated[str, typer.Option("--severity", help="Filter by severity: CRITICAL,HIGH,MEDIUM,LOW,INFO")] = None,
    output_format: Annotated[str, typer.Option("--format", help="Output format: table (default), json, csv")] = "table",
    cve_filter: Annotated[str, typer.Option("--cve", help="Filter results by specific CVE ID")] = None,
    tags_filter: Annotated[str, typer.Option("--tags", help="Filter by comma-separated tags")] = None,
    show_remediation: Annotated[bool, typer.Option("--remediation", help="Include detailed remediation guidance")] = False,
    quick_scan: Annotated[bool, typer.Option("--quick", help="Fast scan mode - limits files processed for performance")] = False,
    max_files: Annotated[int, typer.Option("--max-files", help="Maximum number of files to scan in directory mode")] = 100
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

    # Load plan file or directory
    try:
        file_path = Path(plan_file)
        
        # Handle directory scanning with performance optimization
        if file_path.is_dir():
            if output_format.lower() != "json":
                console.print(f"🗂️ Directory scan: [cyan]{plan_file}[/cyan]")
                
                # Get directory summary first
                summary = get_directory_summary(plan_file)
                console.print(f"📊 Found {summary['scannable_files']} scannable files, ignoring {summary['ignored_files']} files")
                
                if summary['scannable_files'] == 0:
                    console.print("[yellow]No scannable infrastructure files found in directory![/yellow]")
                    raise typer.Exit(code=1)
                
                if summary['scannable_files'] > 100:
                    console.print(f"[yellow]Warning: {summary['scannable_files']} files found. This may take some time...[/yellow]")
            
            # Get filtered list of files to scan
            file_limit = 10 if quick_scan else min(max_files, 500)
            scannable_files = get_scannable_files(plan_file, max_files=file_limit)
            
            if output_format.lower() != "json":
                console.print(f"🚀 Scanning {len(scannable_files)} files {'(quick mode)' if quick_scan else ''}")
            
            # For directories, we'll scan multiple files and aggregate results
            all_scan_results = []
            for file_to_scan in scannable_files:
                try:
                    single_result = scan_single_file(file_to_scan, rules, ignored_findings)
                    if single_result:
                        all_scan_results.append(single_result)
                except Exception as e:
                    if output_format.lower() != "json":
                        console.print(f"[yellow]Warning: Skipped {file_to_scan}: {e}[/yellow]")
            
            # Aggregate results from multiple files
            scan_results = aggregate_scan_results(all_scan_results)
            scan_results['metadata']['files_scanned'] = len(all_scan_results)
            
        else:
            # Handle single file scanning (existing logic)
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
                
            # Initialize enhanced scanner and scan single file
            scanner = EnhancedVulnerabilityScanner()
            scan_results = scanner.scan_resources(plan_data, rules, ignored_findings)
            scan_results['metadata']['scan_timestamp'] = datetime.now().isoformat()
            scan_results['metadata']['rules_applied'] = len(rules)
            scan_results['metadata']['resources_scanned'] = len(plan_data.get('planned_values', {}).get('root_module', {}).get('resources', []))
            
    except Exception as e:
        console.print(f"[red]Error reading plan file: {e}[/red]")
        raise typer.Exit(code=1)

    # Apply filters (common for both directory and single file scans)
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

