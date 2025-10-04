"""
Cost analysis command: extension-style flags with a single entry point.
"""

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
import pandas as pd
from pathlib import Path
from typing import Dict, List, Any

from infraware.utils.pricing_config import PricingConfig
from infraware.utils.file_parsers import FileParserFactory

console = Console()

class CostAnalyzer:
    def __init__(self):
        try:
            self.pricing_config = PricingConfig()
        except FileNotFoundError as e:
            console.print(f"[red]Warning: {e}[/red]")
            console.print("[yellow]Using fallback pricing data[/yellow]")
            self.pricing_config = None

    def analyze_file_costs(self, file_path: str, region: str | None = None, usage_hours: float = 730) -> Dict[str, Any]:
        parsed_data = FileParserFactory.parse_file(file_path)
        if "error" in parsed_data:
            return parsed_data

        total_cost = 0.0
        resource_costs: List[Dict[str, Any]] = []
        for resource in parsed_data.get("resources", []):
            est = self._estimate_resource_cost(resource, region, usage_hours)
            resource_costs.append(est)
            total_cost += float(est.get("monthly_cost", 0.0))

        return {
            "file_path": file_path,
            "file_type": parsed_data.get("file_type", "unknown"),
            "total_monthly_cost": round(total_cost, 2),
            "resource_count": len(resource_costs),
            "resources": resource_costs,
            "region": region,
            "usage_hours": usage_hours,
        }

    def _estimate_resource_cost(self, resource: Dict[str, Any], region: str | None, usage_hours: float) -> Dict[str, Any]:
        if not self.pricing_config:
            return {
                "resource_type": resource.get("type"),
                "resource_name": resource.get("name"),
                "monthly_cost": 0.05,
                "provider": resource.get("provider", "unknown"),
                "error": "No pricing configuration available",
            }

        provider = resource.get("provider", "unknown")
        resource_type = resource.get("type")
        resource_config = resource.get("config", {})
        est = self.pricing_config.estimate_monthly_cost(provider, resource_type, resource_config, region, usage_hours)
        return {
            "resource_type": resource_type,
            "resource_name": resource.get("name"),
            "provider": provider,
            "monthly_cost": est.get("total_monthly_cost", 0.0),
            "cost_breakdown": est.get("cost_breakdown", {}),
            "pricing_details": est.get("pricing_details", {}),
            "region": region,
        }

    def display_cost_analysis(self, analysis: Dict[str, Any]) -> None:
        if "error" in analysis:
            console.print(f"[red]Error: {analysis['error']}[/red]")
            return

        summary = f"""
[bold]File:[/bold] {analysis['file_path']}
[bold]File Type:[/bold] {analysis['file_type']}
[bold]Total Monthly Cost:[/bold] ${analysis['total_monthly_cost']:.2f}
[bold]Resource Count:[/bold] {analysis['resource_count']}
[bold]Region:[/bold] {analysis.get('region', 'default')}
[bold]Usage Hours/Month:[/bold] {analysis['usage_hours']}
        """
        console.print(Panel(summary, title="💰 Cost Analysis Summary", border_style="green", box=box.ROUNDED))

        resources = analysis.get("resources", [])
        if not resources:
            return

        table = Table(title="Resource Cost Breakdown", box=box.ROUNDED)
        table.add_column("Resource Type", style="cyan")
        table.add_column("Name", style="magenta")
        table.add_column("Provider", style="yellow")
        table.add_column("Monthly Cost", style="green", justify="right")
        for r in resources:
            table.add_row(
                r.get("resource_type", "unknown"),
                r.get("resource_name", "unnamed"),
                r.get("provider", "unknown"),
                f"${float(r.get('monthly_cost', 0.0)):.2f}",
            )
        console.print(table)

    def display_json_output(self, analysis: Dict[str, Any]) -> None:
        import json
        console.print(json.dumps(analysis, indent=2))

    def display_csv_output(self, analysis: Dict[str, Any]) -> None:
        resources = analysis.get("resources") or []
        if resources:
            df = pd.DataFrame(resources)
            console.print(df.to_csv(index=False))
        else:
            console.print("No resources found")

    def show_providers(self) -> None:
        if not self.pricing_config:
            console.print("[red]No pricing configuration available[/red]")
            return
        providers = self.pricing_config.get_supported_providers()
        for provider in providers:
            regions = self.pricing_config.get_supported_regions(provider)
            console.print(f"\n[bold cyan]{provider.upper()}[/bold cyan]")
            table = Table(box=box.SIMPLE)
            table.add_column("Region Code", style="yellow")
            table.add_column("Region Name", style="green")
            for code, name in regions.items():
                table.add_row(code, name)
            console.print(table)

    def show_metadata(self, provider: str) -> None:
        if not self.pricing_config:
            console.print("[red]No pricing configuration available[/red]")
            return
        if provider not in self.pricing_config.get_supported_providers():
            console.print(f"[red]Provider '{provider}' not supported[/red]")
            return
        meta = self.pricing_config.get_provider_metadata(provider)
        info = f"""
[bold]Provider:[/bold] {provider.upper()}
[bold]Last Updated:[/bold] {meta.get('last_updated', 'Unknown')}
[bold]Source:[/bold] {meta.get('source', 'Unknown')}
[bold]Currency:[/bold] {meta.get('currency', 'USD')}
[bold]Confidence Scale:[/bold] {meta.get('confidence_scale', 'N/A')}
[bold]Reference URL:[/bold] {meta.get('reference_url', 'N/A')}
[bold]Notes:[/bold] {meta.get('notes', 'N/A')}
        """
        console.print(Panel(info, title=f"📊 {provider.upper()} Pricing Metadata", border_style="blue", box=box.ROUNDED))

    def show_confidence_report(self, provider_filter: str | None = None, min_confidence: int = 0) -> None:
        if not self.pricing_config:
            console.print("[red]No pricing configuration available[/red]")
            return
        providers = [provider_filter] if provider_filter else self.pricing_config.get_supported_providers()
        table = Table(title="🎯 Pricing Data Confidence Report", box=box.ROUNDED)
        table.add_column("Provider", style="cyan")
        table.add_column("Resource Type", style="yellow")
        table.add_column("Confidence", style="blue", justify="center")
        table.add_column("Impact Level", style="red")
        table.add_column("Last Verified", style="dim")
        table.add_column("Tags", style="green")
        sample_resources = [
            'aws_instance', 'aws_ebs_volume', 'aws_s3_bucket',
            'google_compute_instance', 'google_compute_disk',
            'azurerm_virtual_machine', 'azurerm_managed_disk'
        ]
        for prov in providers:
            for rtype in sample_resources:
                if prov.lower() in rtype.lower():
                    ci = self.pricing_config.get_pricing_confidence(prov, rtype)
                    score = ci.get('confidence_score', 5)
                    if score >= min_confidence:
                        table.add_row(
                            prov.upper(),
                            rtype,
                            f"{score}/10",
                            ci.get('impact_level', 'unknown'),
                            ci.get('last_verified', 'unknown'),
                            ', '.join(ci.get('tags', []))
                        )
        console.print(table)

cost_analyzer = CostAnalyzer()

def cost_analysis_command(
    file_path: str = typer.Argument(None, help="Path to infrastructure file (.tf, .json, .yaml)"),
    aws: bool = typer.Option(False, "--aws", help="Show AWS pricing information"),
    gcp: bool = typer.Option(False, "--gcp", help="Show GCP pricing information"),
    azure: bool = typer.Option(False, "--azure", help="Show Azure pricing information"),
    providers: bool = typer.Option(False, "--providers", help="List supported providers and regions"),
    metadata: str = typer.Option(None, "--metadata", help="Show metadata for provider (aws, gcp, azure)"),
    confidence: bool = typer.Option(False, "--confidence", help="Show pricing data confidence report"),
    region: str = typer.Option(None, "--region", "-r", help="Target region for pricing"),
    usage_hours: float = typer.Option(730, "--hours", "-h", help="Monthly usage hours [default: 730]"),
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, json, csv) [default: table]"),
    provider_filter: str = typer.Option(None, "--provider", "-p", help="Filter confidence report by provider"),
    min_confidence: int = typer.Option(0, "--min-confidence", help="Minimum confidence score (0-10) [default: 0]")
):
    """Analyze cloud infrastructure costs and show provider metadata via flags."""
    action_flags = [bool(file_path), providers, bool(metadata), confidence, aws, gcp, azure]
    active_actions = sum(action_flags)
    if active_actions == 0:
        console.print("[yellow]No action specified. Use --help for available options.[/yellow]")
        return
    if active_actions > 1 and file_path and (providers or metadata or confidence or aws or gcp or azure):
        console.print("[red]Cannot combine file analysis with information flags[/red]")
        return

    if providers:
        cost_analyzer.show_providers(); return
    if metadata:
        if metadata.lower() not in ["aws", "gcp", "azure"]:
            console.print("[red]Metadata provider must be: aws, gcp, or azure[/red]")
            return
        cost_analyzer.show_metadata(metadata.lower()); return
    if confidence:
        cost_analyzer.show_confidence_report(provider_filter, min_confidence); return
    if aws:
        cost_analyzer.show_metadata('aws'); return
    if gcp:
        cost_analyzer.show_metadata('gcp'); return
    if azure:
        cost_analyzer.show_metadata('azure'); return

    if file_path:
        if not Path(file_path).exists():
            console.print(f"[red]Error: File not found: {file_path}[/red]")
            return
        result = cost_analyzer.analyze_file_costs(file_path, region, usage_hours)
        if format.lower() == "json":
            cost_analyzer.display_json_output(result)
        elif format.lower() == "csv":
            cost_analyzer.display_csv_output(result)
        else:
            cost_analyzer.display_cost_analysis(result)
    else:
        console.print("[yellow]Please specify a file to analyze or use an information flag[/yellow]")

