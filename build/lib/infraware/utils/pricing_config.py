"""
pricing_config.py
Module for loading and managing cloud provider pricing configurations.
"""

import yaml
import os
from typing import Dict, Any, Optional
from pathlib import Path

class PricingConfig:
    """Class to manage pricing configurations for different cloud providers."""
    
    def __init__(self, config_dir: Optional[str] = None):
        """Initialize with config directory path."""
        if config_dir is None:
            # Default to config/pricing directory relative to the project root
            current_dir = Path(__file__).parent.parent.parent.parent
            config_dir = current_dir / "config" / "pricing"
        
        self.config_dir = Path(config_dir)
        self._pricing_data = {}
        self._load_all_configs()
    
    def _load_all_configs(self):
        """Load all pricing configuration files."""
        if not self.config_dir.exists():
            raise FileNotFoundError(f"Pricing config directory not found: {self.config_dir}")
        
        # Load AWS pricing
        aws_config_path = self.config_dir / "aws_pricing.yaml"
        if aws_config_path.exists():
            self._pricing_data["aws"] = self._load_yaml_config(aws_config_path)
        
        # Load GCP pricing
        gcp_config_path = self.config_dir / "gcp_pricing.yaml"
        if gcp_config_path.exists():
            self._pricing_data["gcp"] = self._load_yaml_config(gcp_config_path)
        
        # Load Azure pricing
        azure_config_path = self.config_dir / "azure_pricing.yaml"
        if azure_config_path.exists():
            self._pricing_data["azure"] = self._load_yaml_config(azure_config_path)
    
    def _load_yaml_config(self, file_path: Path) -> Dict[str, Any]:
        """Load YAML configuration file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return yaml.safe_load(file)
        except Exception as e:
            print(f"Error loading config file {file_path}: {e}")
            return {}
    
    def get_provider_pricing(self, provider: str) -> Dict[str, Any]:
        """Get pricing data for a specific provider."""
        return self._pricing_data.get(provider.lower(), {})
    
    def get_resource_price(self, provider: str, resource_type: str, 
                          resource_config: Dict[str, Any] = None,
                          region: str = None) -> Dict[str, Any]:
        """
        Get pricing information for a specific resource.
        
        Args:
            provider: Cloud provider (aws, gcp, azure)
            resource_type: Type of resource (e.g., aws_instance, google_compute_instance)
            resource_config: Resource configuration parameters
            region: Target region
        
        Returns:
            Dictionary containing pricing information
        """
        provider_data = self.get_provider_pricing(provider)
        if not provider_data:
            return {"error": f"No pricing data found for provider: {provider}"}
        
        # Get region multiplier
        region_multiplier = 1.0
        if region and "regions" in provider_data:
            region_info = provider_data["regions"].get(region, {})
            region_multiplier = region_info.get("multiplier", 1.0)
        
        # Find resource in pricing categories
        resource_pricing = self._find_resource_pricing(provider_data, resource_type, resource_config)
        
        if not resource_pricing:
            return {
                "error": f"No pricing data found for resource type: {resource_type}",
                "default_estimate": 0.05 * region_multiplier  # Default fallback
            }
        
        # Apply region multiplier to all price fields
        adjusted_pricing = self._apply_region_multiplier(resource_pricing, region_multiplier)
        adjusted_pricing["region"] = region
        adjusted_pricing["region_multiplier"] = region_multiplier
        
        # Add metadata information
        resource_metadata = self.get_resource_metadata(provider, resource_type)
        if resource_metadata:
            adjusted_pricing["metadata"] = resource_metadata
        
        return adjusted_pricing
    
    def _find_resource_pricing(self, provider_data: Dict[str, Any], 
                              resource_type: str, 
                              resource_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Find pricing data for a resource type within provider data."""
        # Search through all categories (compute, storage, database, etc.)
        for category, resources in provider_data.items():
            if category == "regions":
                continue
                
            if isinstance(resources, dict) and resource_type in resources:
                resource_pricing = resources[resource_type]
                
                # If resource has sub-types (e.g., instance types), try to match
                if resource_config and isinstance(resource_pricing, dict):
                    # Try to find specific instance type or configuration
                    instance_type = resource_config.get("instance_type") or resource_config.get("size") or resource_config.get("type")
                    if instance_type and instance_type in resource_pricing:
                        return resource_pricing[instance_type]
                
                return resource_pricing
        
        return {}
    
    def _apply_region_multiplier(self, pricing: Dict[str, Any], multiplier: float) -> Dict[str, Any]:
        """Apply region multiplier to all price fields in pricing data."""
        adjusted = pricing.copy()
        
        for key, value in pricing.items():
            if isinstance(value, (int, float)) and "price" in key.lower():
                adjusted[key] = value * multiplier
        
        return adjusted
    
    def get_provider_metadata(self, provider: str) -> Dict[str, Any]:
        """Get metadata for a specific provider."""
        provider_data = self.get_provider_pricing(provider)
        return provider_data.get("metadata", {})
    
    def get_resource_metadata(self, provider: str, resource_type: str) -> Dict[str, Any]:
        """Get metadata for a specific resource type."""
        provider_data = self.get_provider_pricing(provider)
        if not provider_data:
            return {}
        
        # Search through all categories for the resource
        for category, resources in provider_data.items():
            if category in ["regions", "metadata"]:
                continue
                
            if isinstance(resources, dict) and resource_type in resources:
                resource_data = resources[resource_type]
                if isinstance(resource_data, dict):
                    return resource_data.get("metadata", {})
        
        return {}
    
    def get_pricing_confidence(self, provider: str, resource_type: str, 
                              resource_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get confidence and verification information for pricing data."""
        pricing_info = self.get_resource_price(provider, resource_type, resource_config)
        
        confidence_info = {
            "confidence_score": pricing_info.get("confidence", 5),
            "impact_level": pricing_info.get("impact_level", "unknown"),
            "last_verified": pricing_info.get("last_verified", "unknown"),
            "tags": pricing_info.get("tags", []),
            "has_metadata": "metadata" in pricing_info
        }
        
        return confidence_info
    
    def get_supported_providers(self) -> list:
        """Get list of supported cloud providers."""
        return list(self._pricing_data.keys())
    
    def get_providers_with_metadata(self) -> Dict[str, Dict[str, Any]]:
        """Get supported providers with their metadata."""
        providers_info = {}
        for provider in self.get_supported_providers():
            providers_info[provider] = self.get_provider_metadata(provider)
        return providers_info
    
    def get_supported_regions(self, provider: str) -> Dict[str, str]:
        """Get supported regions for a provider."""
        provider_data = self.get_provider_pricing(provider)
        regions = provider_data.get("regions", {})
        return {region: info.get("name", region) for region, info in regions.items()}
    
    def estimate_monthly_cost(self, provider: str, resource_type: str, 
                            resource_config: Dict[str, Any] = None,
                            region: str = None,
                            usage_hours: float = 730) -> Dict[str, Any]:
        """
        Estimate monthly cost for a resource.
        
        Args:
            provider: Cloud provider
            resource_type: Resource type
            resource_config: Resource configuration
            region: Target region
            usage_hours: Hours of usage per month (default: 730 = 24*365/12)
        
        Returns:
            Cost estimation details
        """
        pricing_info = self.get_resource_price(provider, resource_type, resource_config, region)
        
        if "error" in pricing_info:
            return pricing_info
        
        monthly_cost = 0.0
        cost_breakdown = {}
        
        # Calculate based on different pricing models
        if "price_per_hour" in pricing_info:
            hourly_cost = pricing_info["price_per_hour"] * usage_hours
            monthly_cost += hourly_cost
            cost_breakdown["compute_hours"] = hourly_cost
        
        if "price_per_gb_month" in pricing_info:
            # Assume 100GB as default if not specified
            gb_size = resource_config.get("size_gb", 100) if resource_config else 100
            storage_cost = pricing_info["price_per_gb_month"] * gb_size
            monthly_cost += storage_cost
            cost_breakdown["storage"] = storage_cost
        
        if "price_per_month" in pricing_info:
            fixed_cost = pricing_info["price_per_month"]
            monthly_cost += fixed_cost
            cost_breakdown["fixed"] = fixed_cost
        
        return {
            "total_monthly_cost": round(monthly_cost, 4),
            "cost_breakdown": cost_breakdown,
            "pricing_details": pricing_info,
            "usage_hours": usage_hours,
            "confidence_info": self.get_pricing_confidence(provider, resource_type, resource_config),
            "metadata": pricing_info.get("metadata", {})
        }