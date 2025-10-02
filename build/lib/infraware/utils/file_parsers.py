"""
file_parsers.py
Module for parsing different file formats (Terraform, JSON, YAML) for cost analysis.
"""

import json
import yaml
import re
from typing import Dict, List, Any, Optional
from pathlib import Path

class TerraformParser:
    """Parser for Terraform files (.tf)."""
    
    def __init__(self):
        self.resource_patterns = {
            'resource_block': r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
            'provider_block': r'provider\s+"([^"]+)"\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
            'variable_block': r'variable\s+"([^"]+)"\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}',
        }
    
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """Parse a Terraform .tf file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            return self.parse_content(content)
        except Exception as e:
            return {"error": f"Error parsing Terraform file: {e}"}
    
    def parse_content(self, content: str) -> Dict[str, Any]:
        """Parse Terraform content string."""
        result = {
            "resources": [],
            "providers": [],
            "variables": [],
            "file_type": "terraform"
        }
        
        # Parse resources
        resource_matches = re.finditer(self.resource_patterns['resource_block'], content, re.DOTALL)
        for match in resource_matches:
            resource_type = match.group(1)
            resource_name = match.group(2)
            resource_body = match.group(3)
            
            resource_config = self._parse_resource_body(resource_body)
            
            result["resources"].append({
                "type": resource_type,
                "name": resource_name,
                "config": resource_config,
                "provider": self._infer_provider(resource_type)
            })
        
        # Parse providers
        provider_matches = re.finditer(self.resource_patterns['provider_block'], content, re.DOTALL)
        for match in provider_matches:
            provider_name = match.group(1)
            provider_body = match.group(2)
            provider_config = self._parse_resource_body(provider_body)
            
            result["providers"].append({
                "name": provider_name,
                "config": provider_config
            })
        
        return result
    
    def _parse_resource_body(self, body: str) -> Dict[str, Any]:
        """Parse the body of a resource block."""
        config = {}
        
        # Simple parsing for key-value pairs
        lines = body.strip().split('\n')
        for line in lines:
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                try:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    
                    # Try to convert to appropriate type
                    if value.lower() == 'true':
                        value = True
                    elif value.lower() == 'false':
                        value = False
                    elif value.isdigit():
                        value = int(value)
                    elif self._is_float(value):
                        value = float(value)
                    
                    config[key] = value
                except ValueError:
                    continue
        
        return config
    
    def _is_float(self, value: str) -> bool:
        """Check if string represents a float."""
        try:
            float(value)
            return True
        except ValueError:
            return False
    
    def _infer_provider(self, resource_type: str) -> str:
        """Infer cloud provider from resource type."""
        if resource_type.startswith('aws_'):
            return 'aws'
        elif resource_type.startswith('google_') or resource_type.startswith('gcp_'):
            return 'gcp'
        elif resource_type.startswith('azurerm_') or resource_type.startswith('azure_'):
            return 'azure'
        else:
            return 'unknown'

class TerraformPlanParser:
    """Parser for Terraform plan JSON files."""
    
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """Parse a Terraform plan JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                plan_data = json.load(file)
            
            return self.parse_plan_data(plan_data)
        except Exception as e:
            return {"error": f"Error parsing Terraform plan file: {e}"}
    
    def parse_plan_data(self, plan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Terraform plan data."""
        result = {
            "resources": [],
            "file_type": "terraform_plan"
        }
        
        # Parse planned values
        planned_values = plan_data.get('planned_values', {})
        root_module = planned_values.get('root_module', {})
        resources = root_module.get('resources', [])
        
        for resource in resources:
            resource_type = resource.get('type')
            resource_name = resource.get('name')
            resource_values = resource.get('values', {})
            
            result["resources"].append({
                "type": resource_type,
                "name": resource_name,
                "config": resource_values,
                "provider": self._infer_provider(resource_type),
                "mode": resource.get('mode', 'managed')
            })
        
        # Parse resource changes for cost impact
        resource_changes = plan_data.get('resource_changes', [])
        for change in resource_changes:
            change_action = change.get('change', {}).get('actions', [])
            if 'create' in change_action:
                # This is a new resource that will incur costs
                resource_type = change.get('type')
                resource_name = change.get('name')
                after_values = change.get('change', {}).get('after', {})
                
                # Find if this resource is already in our list, if not add it
                existing = next((r for r in result["resources"] 
                               if r["type"] == resource_type and r["name"] == resource_name), None)
                if not existing:
                    result["resources"].append({
                        "type": resource_type,
                        "name": resource_name,
                        "config": after_values,
                        "provider": self._infer_provider(resource_type),
                        "change_action": change_action
                    })
        
        return result
    
    def _infer_provider(self, resource_type: str) -> str:
        """Infer cloud provider from resource type."""
        if resource_type.startswith('aws_'):
            return 'aws'
        elif resource_type.startswith('google_') or resource_type.startswith('gcp_'):
            return 'gcp'
        elif resource_type.startswith('azurerm_') or resource_type.startswith('azure_'):
            return 'azure'
        else:
            return 'unknown'

class YAMLParser:
    """Parser for YAML infrastructure files."""
    
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """Parse a YAML infrastructure file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                yaml_data = yaml.safe_load(file)
            
            return self.parse_yaml_data(yaml_data)
        except Exception as e:
            return {"error": f"Error parsing YAML file: {e}"}
    
    def parse_yaml_data(self, yaml_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse YAML data for infrastructure resources."""
        result = {
            "resources": [],
            "file_type": "yaml"
        }
        
        # Check if it's a CloudFormation template
        if 'Resources' in yaml_data:
            return self._parse_cloudformation(yaml_data)
        
        # Check if it's a Kubernetes manifest
        if 'kind' in yaml_data and 'apiVersion' in yaml_data:
            return self._parse_kubernetes(yaml_data)
        
        # Generic YAML parsing
        if 'resources' in yaml_data:
            for resource_name, resource_config in yaml_data['resources'].items():
                resource_type = resource_config.get('type', 'unknown')
                result["resources"].append({
                    "type": resource_type,
                    "name": resource_name,
                    "config": resource_config,
                    "provider": self._infer_provider_from_config(resource_config)
                })
        
        return result
    
    def _parse_cloudformation(self, cf_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse CloudFormation template."""
        result = {
            "resources": [],
            "file_type": "cloudformation"
        }
        
        resources = cf_data.get('Resources', {})
        for resource_name, resource_config in resources.items():
            resource_type = resource_config.get('Type', 'unknown')
            properties = resource_config.get('Properties', {})
            
            result["resources"].append({
                "type": resource_type,
                "name": resource_name,
                "config": properties,
                "provider": "aws"  # CloudFormation is AWS-specific
            })
        
        return result
    
    def _parse_kubernetes(self, k8s_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Kubernetes manifest."""
        result = {
            "resources": [],
            "file_type": "kubernetes"
        }
        
        kind = k8s_data.get('kind', 'unknown')
        metadata = k8s_data.get('metadata', {})
        name = metadata.get('name', 'unnamed')
        
        result["resources"].append({
            "type": f"kubernetes_{kind.lower()}",
            "name": name,
            "config": k8s_data,
            "provider": "kubernetes"
        })
        
        return result
    
    def _infer_provider_from_config(self, config: Dict[str, Any]) -> str:
        """Infer provider from resource configuration."""
        provider = config.get('provider', '').lower()
        if provider:
            return provider
        
        # Try to infer from resource type or other properties
        resource_type = config.get('type', '').lower()
        if 'aws' in resource_type or 'ec2' in resource_type or 's3' in resource_type:
            return 'aws'
        elif 'gcp' in resource_type or 'google' in resource_type:
            return 'gcp'
        elif 'azure' in resource_type or 'azurerm' in resource_type:
            return 'azure'
        
        return 'unknown'

class JSONParser:
    """Parser for JSON infrastructure files."""
    
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """Parse a JSON infrastructure file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                json_data = json.load(file)
            
            return self.parse_json_data(json_data)
        except Exception as e:
            return {"error": f"Error parsing JSON file: {e}"}
    
    def parse_json_data(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse JSON data for infrastructure resources."""
        # If it's a Terraform plan, use the plan parser
        if 'planned_values' in json_data or 'resource_changes' in json_data:
            plan_parser = TerraformPlanParser()
            return plan_parser.parse_plan_data(json_data)
        
        # Generic JSON parsing similar to YAML
        result = {
            "resources": [],
            "file_type": "json"
        }
        
        if 'resources' in json_data:
            for resource_name, resource_config in json_data['resources'].items():
                resource_type = resource_config.get('type', 'unknown')
                result["resources"].append({
                    "type": resource_type,
                    "name": resource_name,
                    "config": resource_config,
                    "provider": self._infer_provider_from_config(resource_config)
                })
        
        return result
    
    def _infer_provider_from_config(self, config: Dict[str, Any]) -> str:
        """Infer provider from resource configuration."""
        provider = config.get('provider', '').lower()
        if provider:
            return provider
        
        resource_type = config.get('type', '').lower()
        if 'aws' in resource_type:
            return 'aws'
        elif 'gcp' in resource_type or 'google' in resource_type:
            return 'gcp'
        elif 'azure' in resource_type:
            return 'azure'
        
        return 'unknown'

class FileParserFactory:
    """Factory class to get appropriate parser based on file extension."""
    
    @staticmethod
    def get_parser(file_path: str):
        """Get appropriate parser based on file extension."""
        path = Path(file_path)
        extension = path.suffix.lower()
        
        if extension == '.tf':
            return TerraformParser()
        elif extension == '.json':
            return JSONParser()
        elif extension in ['.yaml', '.yml']:
            return YAMLParser()
        else:
            raise ValueError(f"Unsupported file extension: {extension}")
    
    @staticmethod
    def parse_file(file_path: str) -> Dict[str, Any]:
        """Parse file using appropriate parser."""
        try:
            parser = FileParserFactory.get_parser(file_path)
            return parser.parse_file(file_path)
        except Exception as e:
            return {"error": f"Error parsing file {file_path}: {e}"}