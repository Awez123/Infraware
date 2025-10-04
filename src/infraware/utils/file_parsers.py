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

class CloudFormationYAMLParser:
    """Enhanced CloudFormation YAML parser that handles CloudFormation-specific tags."""
    
    def __init__(self):
        self.cf_constructors = {
            '!Ref': self._construct_ref,
            '!GetAtt': self._construct_getatt,
            '!Sub': self._construct_sub,
            '!Join': self._construct_join,
            '!Select': self._construct_select,
            '!Split': self._construct_split,
            '!Base64': self._construct_base64,
            '!Cidr': self._construct_cidr,
            '!FindInMap': self._construct_findinmap,
            '!GetAZs': self._construct_getazs,
            '!ImportValue': self._construct_importvalue,
            '!Equals': self._construct_equals,
            '!Not': self._construct_not,
            '!And': self._construct_and,
            '!Or': self._construct_or,
            '!If': self._construct_if,
            '!Condition': self._construct_condition
        }
    
    def _construct_ref(self, loader, node):
        """Handle !Ref tag."""
        value = loader.construct_scalar(node)
        return {'Ref': value}
    
    def _construct_getatt(self, loader, node):
        """Handle !GetAtt tag."""
        if isinstance(node.value, str):
            # Single string format: LogicalName.AttributeName
            return {'Fn::GetAtt': node.value.split('.', 1)}
        else:
            # List format: [LogicalName, AttributeName]
            value = loader.construct_sequence(node)
            return {'Fn::GetAtt': value}
    
    def _construct_sub(self, loader, node):
        """Handle !Sub tag."""
        if isinstance(node, yaml.ScalarNode):
            value = loader.construct_scalar(node)
            return {'Fn::Sub': value}
        else:
            value = loader.construct_sequence(node)
            return {'Fn::Sub': value}
    
    def _construct_join(self, loader, node):
        """Handle !Join tag."""
        value = loader.construct_sequence(node)
        return {'Fn::Join': value}
    
    def _construct_select(self, loader, node):
        """Handle !Select tag."""
        value = loader.construct_sequence(node)
        return {'Fn::Select': value}
    
    def _construct_split(self, loader, node):
        """Handle !Split tag."""
        value = loader.construct_sequence(node)
        return {'Fn::Split': value}
    
    def _construct_base64(self, loader, node):
        """Handle !Base64 tag."""
        value = loader.construct_scalar(node)
        return {'Fn::Base64': value}
    
    def _construct_cidr(self, loader, node):
        """Handle !Cidr tag."""
        value = loader.construct_sequence(node)
        return {'Fn::Cidr': value}
    
    def _construct_findinmap(self, loader, node):
        """Handle !FindInMap tag."""
        value = loader.construct_sequence(node)
        return {'Fn::FindInMap': value}
    
    def _construct_getazs(self, loader, node):
        """Handle !GetAZs tag."""
        value = loader.construct_scalar(node)
        return {'Fn::GetAZs': value}
    
    def _construct_importvalue(self, loader, node):
        """Handle !ImportValue tag."""
        value = loader.construct_scalar(node)
        return {'Fn::ImportValue': value}
    
    def _construct_equals(self, loader, node):
        """Handle !Equals tag."""
        value = loader.construct_sequence(node)
        return {'Fn::Equals': value}
    
    def _construct_not(self, loader, node):
        """Handle !Not tag."""
        value = loader.construct_sequence(node)
        return {'Fn::Not': value}
    
    def _construct_and(self, loader, node):
        """Handle !And tag."""
        value = loader.construct_sequence(node)
        return {'Fn::And': value}
    
    def _construct_or(self, loader, node):
        """Handle !Or tag."""
        value = loader.construct_sequence(node)
        return {'Fn::Or': value}
    
    def _construct_if(self, loader, node):
        """Handle !If tag."""
        value = loader.construct_sequence(node)
        return {'Fn::If': value}
    
    def _construct_condition(self, loader, node):
        """Handle !Condition tag."""
        value = loader.construct_scalar(node)
        return {'Condition': value}
    
    def create_cf_loader(self):
        """Create a YAML loader with CloudFormation constructors."""
        class CFLoader(yaml.SafeLoader):
            pass
        
        # Add constructors for CloudFormation tags
        for tag, constructor in self.cf_constructors.items():
            CFLoader.add_constructor(tag, constructor)
        
        return CFLoader
    
    def parse_cloudformation_yaml(self, file_path: str) -> Dict[str, Any]:
        """Parse CloudFormation YAML with proper tag handling."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                cf_loader = self.create_cf_loader()
                data = yaml.load(file, Loader=cf_loader)
                return self._parse_cloudformation_data(data)
        except Exception as e:
            return {"error": f"Error parsing CloudFormation YAML: {e}"}
    
    def _parse_cloudformation_data(self, cf_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse CloudFormation data structure."""
        result = {
            "resources": [],
            "file_type": "cloudformation",
            "parameters": cf_data.get('Parameters', {}),
            "outputs": cf_data.get('Outputs', {}),
            "conditions": cf_data.get('Conditions', {}),
            "mappings": cf_data.get('Mappings', {})
        }
        
        resources = cf_data.get('Resources', {})
        for resource_name, resource_config in resources.items():
            resource_type = resource_config.get('Type', 'unknown')
            properties = resource_config.get('Properties', {})
            
            # Process CloudFormation intrinsic functions
            processed_properties = self._process_intrinsic_functions(properties)
            
            result["resources"].append({
                "type": resource_type,
                "name": resource_name,
                "config": processed_properties,
                "provider": "aws",  # CloudFormation is AWS-specific
                "condition": resource_config.get('Condition'),
                "depends_on": resource_config.get('DependsOn', []),
                "metadata": resource_config.get('Metadata', {})
            })
        
        return result
    
    def _process_intrinsic_functions(self, obj: Any) -> Any:
        """Process CloudFormation intrinsic functions recursively."""
        if isinstance(obj, dict):
            if len(obj) == 1:
                key, value = next(iter(obj.items()))
                if key in ['Ref', 'Fn::GetAtt', 'Fn::Sub', 'Fn::Join', 'Fn::Select', 
                          'Fn::Split', 'Fn::Base64', 'Fn::Cidr', 'Fn::FindInMap',
                          'Fn::GetAZs', 'Fn::ImportValue', 'Fn::Equals', 'Fn::Not',
                          'Fn::And', 'Fn::Or', 'Fn::If', 'Condition']:
                    # Keep intrinsic function as-is but process its value
                    return {key: self._process_intrinsic_functions(value)}
            
            # Process all dict values
            return {k: self._process_intrinsic_functions(v) for k, v in obj.items()}
        
        elif isinstance(obj, list):
            return [self._process_intrinsic_functions(item) for item in obj]
        
        else:
            return obj

class YAMLParser:
    """Parser for YAML infrastructure files."""
    
    def __init__(self):
        self.cf_parser = CloudFormationYAMLParser()
    
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """Parse a YAML infrastructure file."""
        try:
            # First, try to detect if it's a CloudFormation template
            if self._is_cloudformation_template(file_path):
                return self.cf_parser.parse_cloudformation_yaml(file_path)
            
            # Otherwise, use standard YAML parsing
            with open(file_path, 'r', encoding='utf-8') as file:
                yaml_data = yaml.safe_load(file)
            
            return self.parse_yaml_data(yaml_data)
        except Exception as e:
            return {"error": f"Error parsing YAML file: {e}"}
    
    def _is_cloudformation_template(self, file_path: str) -> bool:
        """Detect if YAML file is a CloudFormation template."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            # Check for CloudFormation indicators
            cf_indicators = [
                'AWSTemplateFormatVersion',
                'Resources:',
                'Parameters:',
                'Outputs:',
                '!Ref',
                '!GetAtt',
                '!Sub'
            ]
            
            return any(indicator in content for indicator in cf_indicators)
        except Exception:
            return False
    
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