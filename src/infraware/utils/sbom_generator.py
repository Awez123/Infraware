"""
sbom_generator.py
Software Bill of Materials (SBOM) generation for InfraWare.
Supports SPDX and CycloneDX formats.
"""

import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import uuid
import hashlib
from pathlib import Path

@dataclass
class Component:
    """Represents a software component in SBOM."""
    bom_ref: str
    type: str  # application, library, framework, file, etc.
    name: str
    version: str
    description: Optional[str] = None
    hashes: Optional[List[Dict[str, str]]] = None
    licenses: Optional[List[str]] = None
    purl: Optional[str] = None  # Package URL
    external_references: Optional[List[Dict[str, str]]] = None
    dependencies: Optional[List[str]] = None
    vulnerabilities: Optional[List[Dict[str, Any]]] = None

@dataclass
class Vulnerability:
    """Represents a vulnerability in SBOM."""
    bom_ref: str
    id: str
    source_name: str
    source_url: str
    ratings: List[Dict[str, Any]]
    cwes: Optional[List[int]] = None
    description: Optional[str] = None
    recommendations: Optional[List[str]] = None
    affects: Optional[List[str]] = None

class SBOMGenerator:
    """SBOM generation in multiple formats."""
    
    def __init__(self):
        self.components = []
        self.vulnerabilities = []
        self.metadata = {
            'timestamp': datetime.now().isoformat(),
            'tools': ['InfraWare'],
            'authors': []
        }
    
    def add_component(self, component: Component):
        """Add a component to the SBOM."""
        self.components.append(component)
    
    def add_vulnerability(self, vulnerability: Vulnerability):
        """Add a vulnerability to the SBOM."""
        self.vulnerabilities.append(vulnerability)
    
    def generate_cyclone_dx(self, output_format: str = 'json') -> str:
        """Generate SBOM in CycloneDX format."""
        bom = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'serialNumber': f"urn:uuid:{uuid.uuid4()}",
            'version': 1,
            'metadata': {
                'timestamp': self.metadata['timestamp'],
                'tools': [
                    {
                        'vendor': 'InfraWare',
                        'name': 'InfraWare Scanner',
                        'version': '1.0.0'
                    }
                ],
                'authors': self.metadata.get('authors', [])
            },
            'components': [asdict(comp) for comp in self.components]
        }
        
        if self.vulnerabilities:
            bom['vulnerabilities'] = [asdict(vuln) for vuln in self.vulnerabilities]
        
        if output_format.lower() == 'json':
            return json.dumps(bom, indent=2)
        elif output_format.lower() == 'xml':
            return self._cyclone_dx_to_xml(bom)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
    
    def generate_spdx(self, output_format: str = 'json') -> str:
        """Generate SBOM in SPDX format."""
        spdx_id = f"SPDXRef-DOCUMENT"
        
        spdx = {
            'spdxVersion': 'SPDX-2.3',
            'dataLicense': 'CC0-1.0',
            'SPDXID': spdx_id,
            'name': 'InfraWare-SBOM',
            'documentNamespace': f"https://infraware.com/spdx/{uuid.uuid4()}",
            'creationInfo': {
                'created': self.metadata['timestamp'],
                'creators': ['Tool: InfraWare'],
                'licenseListVersion': '3.20'
            },
            'packages': []
        }
        
        # Convert components to SPDX packages
        for comp in self.components:
            package = {
                'SPDXID': f"SPDXRef-Package-{comp.name}",
                'name': comp.name,
                'downloadLocation': comp.external_references[0]['url'] if comp.external_references else 'NOASSERTION',
                'filesAnalyzed': False,
                'licenseConcluded': comp.licenses[0] if comp.licenses else 'NOASSERTION',
                'licenseDeclared': comp.licenses[0] if comp.licenses else 'NOASSERTION',
                'copyrightText': 'NOASSERTION'
            }
            
            if comp.version:
                package['versionInfo'] = comp.version
            
            if comp.description:
                package['description'] = comp.description
            
            if comp.hashes:
                package['checksums'] = [
                    {
                        'algorithm': hash_info['alg'].upper(),
                        'checksumValue': hash_info['content']
                    }
                    for hash_info in comp.hashes
                ]
            
            spdx['packages'].append(package)
        
        if output_format.lower() == 'json':
            return json.dumps(spdx, indent=2)
        else:
            raise ValueError(f"Unsupported SPDX format: {output_format}")
    
    def scan_terraform_for_components(self, plan_data: Dict[str, Any]) -> List[Component]:
        """Extract components from Terraform plan."""
        components = []
        resources = plan_data.get('planned_values', {}).get('root_module', {}).get('resources', [])
        
        for resource in resources:
            component = Component(
                bom_ref=f"terraform-{resource.get('address', 'unknown')}",
                type='infrastructure',
                name=f"{resource.get('type', 'unknown')}.{resource.get('name', 'unknown')}",
                version='terraform-managed',
                description=f"Terraform managed {resource.get('type', 'resource')}",
                external_references=[
                    {
                        'type': 'terraform',
                        'url': f"terraform://{resource.get('address', 'unknown')}"
                    }
                ]
            )
            components.append(component)
            self.add_component(component)
        
        return components
    
    def scan_package_json_for_components(self, file_path: str) -> List[Component]:
        """Extract components from package.json."""
        components = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
            
            # Main package
            main_component = Component(
                bom_ref=f"npm-{data.get('name', 'unknown')}",
                type='application',
                name=data.get('name', 'unknown'),
                version=data.get('version', 'unknown'),
                description=data.get('description'),
                licenses=[data.get('license')] if data.get('license') else None,
                purl=f"pkg:npm/{data.get('name')}@{data.get('version')}"
            )
            components.append(main_component)
            self.add_component(main_component)
            
            # Dependencies
            dependencies = data.get('dependencies', {})
            for dep_name, dep_version in dependencies.items():
                dep_component = Component(
                    bom_ref=f"npm-{dep_name}",
                    type='library',
                    name=dep_name,
                    version=dep_version.lstrip('^~'),
                    purl=f"pkg:npm/{dep_name}@{dep_version.lstrip('^~')}",
                    external_references=[
                        {
                            'type': 'website',
                            'url': f"https://www.npmjs.com/package/{dep_name}"
                        }
                    ]
                )
                components.append(dep_component)
                self.add_component(dep_component)
        
        except Exception as e:
            print(f"Error scanning package.json {file_path}: {e}")
        
        return components
    
    def scan_requirements_txt_for_components(self, file_path: str) -> List[Component]:
        """Extract components from requirements.txt."""
        components = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parse package name and version
                    if '==' in line:
                        package_name, version = line.split('==', 1)
                    elif '>=' in line:
                        package_name, version = line.split('>=', 1)
                        version = f">={version}"
                    else:
                        package_name = line
                        version = 'unknown'
                    
                    component = Component(
                        bom_ref=f"pypi-{package_name}",
                        type='library',
                        name=package_name,
                        version=version,
                        purl=f"pkg:pypi/{package_name}@{version}",
                        external_references=[
                            {
                                'type': 'website',
                                'url': f"https://pypi.org/project/{package_name}/"
                            }
                        ]
                    )
                    components.append(component)
                    self.add_component(component)
        
        except Exception as e:
            print(f"Error scanning requirements.txt {file_path}: {e}")
        
        return components
    
    def scan_go_mod_for_components(self, file_path: str) -> List[Component]:
        """Extract components from go.mod."""
        components = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            # Parse module name
            module_match = re.search(r'module\\s+([^\\s]+)', content)
            if module_match:
                module_name = module_match.group(1)
                
                # Parse version from nearby go.sum or git tag
                version_match = re.search(r'go\\s+([0-9.]+)', content)
                go_version = version_match.group(1) if version_match else 'unknown'
                
                main_component = Component(
                    bom_ref=f"go-{module_name}",
                    type='application',
                    name=module_name,
                    version=go_version,
                    purl=f"pkg:golang/{module_name}@{go_version}"
                )
                components.append(main_component)
                self.add_component(main_component)
            
            # Parse dependencies
            import re
            require_matches = re.findall(r'require\\s+([^\\s]+)\\s+([^\\s]+)', content)
            
            for dep_name, version in require_matches:
                if not dep_name.startswith('//'):  # Skip comments
                    component = Component(
                        bom_ref=f"go-{dep_name}",
                        type='library',
                        name=dep_name,
                        version=version,
                        purl=f"pkg:golang/{dep_name}@{version}",
                        external_references=[
                            {
                                'type': 'vcs',
                                'url': f"https://{dep_name}"
                            }
                        ]
                    )
                    components.append(component)
                    self.add_component(component)
        
        except Exception as e:
            print(f"Error scanning go.mod {file_path}: {e}")
        
        return components
    
    def scan_directory_for_sbom(self, directory: str) -> Dict[str, Any]:
        """Scan directory and generate comprehensive SBOM."""
        path = Path(directory)
        
        # Scan different file types
        package_files = {
            'package.json': self.scan_package_json_for_components,
            'requirements.txt': self.scan_requirements_txt_for_components,
            'go.mod': self.scan_go_mod_for_components,
        }
        
        for file_pattern, scan_func in package_files.items():
            for file_path in path.rglob(file_pattern):
                scan_func(str(file_path))
        
        # Generate report
        return {
            'total_components': len(self.components),
            'component_types': self._count_component_types(),
            'ecosystems': self._count_ecosystems(),
            'sbom_formats': {
                'cyclone_dx_json': 'Available',
                'cyclone_dx_xml': 'Available',
                'spdx_json': 'Available'
            }
        }
    
    def _count_component_types(self) -> Dict[str, int]:
        """Count components by type."""
        types = {}
        for comp in self.components:
            types[comp.type] = types.get(comp.type, 0) + 1
        return types
    
    def _count_ecosystems(self) -> Dict[str, int]:
        """Count components by ecosystem."""
        ecosystems = {}
        for comp in self.components:
            if comp.purl:
                ecosystem = comp.purl.split(':')[1] if ':' in comp.purl else 'unknown'
                ecosystems[ecosystem] = ecosystems.get(ecosystem, 0) + 1
        return ecosystems
    
    def _cyclone_dx_to_xml(self, bom_data: Dict[str, Any]) -> str:
        """Convert CycloneDX JSON to XML format."""
        # Simplified XML conversion - full implementation would be more complex
        root = ET.Element('bom', {
            'xmlns': 'http://cyclonedx.org/schema/bom/1.4',
            'serialNumber': bom_data['serialNumber'],
            'version': str(bom_data['version'])
        })
        
        # Metadata
        metadata = ET.SubElement(root, 'metadata')
        timestamp = ET.SubElement(metadata, 'timestamp')
        timestamp.text = bom_data['metadata']['timestamp']
        
        # Components
        components = ET.SubElement(root, 'components')
        for comp_data in bom_data['components']:
            comp_elem = ET.SubElement(components, 'component', {'type': comp_data['type']})
            
            name_elem = ET.SubElement(comp_elem, 'name')
            name_elem.text = comp_data['name']
            
            version_elem = ET.SubElement(comp_elem, 'version')
            version_elem.text = comp_data['version']
        
        return ET.tostring(root, encoding='unicode')
    
    def export_sbom(self, output_path: str, format_type: str = 'cyclone_dx', 
                    output_format: str = 'json'):
        """Export SBOM to file."""
        if format_type.lower() == 'cyclone_dx':
            content = self.generate_cyclone_dx(output_format)
        elif format_type.lower() == 'spdx':
            content = self.generate_spdx(output_format)
        else:
            raise ValueError(f"Unsupported format type: {format_type}")
        
        with open(output_path, 'w', encoding='utf-8') as file:
            file.write(content)
        
        print(f"SBOM exported to {output_path}")

class EnhancedSBOMGenerator(SBOMGenerator):
    """Enhanced SBOM generator with vulnerability correlation."""
    
    def __init__(self):
        super().__init__()
        self.vulnerability_mappings = {}
    
    def correlate_vulnerabilities(self, vulnerability_data: List[Dict[str, Any]]):
        """Correlate vulnerabilities with components."""
        for vuln_data in vulnerability_data:
            # Create vulnerability object
            vulnerability = Vulnerability(
                bom_ref=f"vuln-{vuln_data.get('id', 'unknown')}",
                id=vuln_data.get('id', 'unknown'),
                source_name=vuln_data.get('source', 'InfraWare'),
                source_url=vuln_data.get('url', ''),
                ratings=[
                    {
                        'source': vuln_data.get('source', 'InfraWare'),
                        'score': vuln_data.get('severity_score', 0),
                        'severity': vuln_data.get('severity', 'UNKNOWN'),
                        'method': 'CVSSv3'
                    }
                ],
                description=vuln_data.get('description'),
                recommendations=vuln_data.get('remediation', '').split('\\n') if vuln_data.get('remediation') else []
            )
            
            self.add_vulnerability(vulnerability)
            
            # Map to affected components
            affected_component = vuln_data.get('resource_name')
            if affected_component:
                if affected_component not in self.vulnerability_mappings:
                    self.vulnerability_mappings[affected_component] = []
                self.vulnerability_mappings[affected_component].append(vulnerability.bom_ref)
    
    def generate_enhanced_cyclone_dx(self) -> str:
        """Generate CycloneDX with vulnerability data."""
        # Update components with vulnerability references
        for comp in self.components:
            if comp.name in self.vulnerability_mappings:
                if not comp.vulnerabilities:
                    comp.vulnerabilities = []
                comp.vulnerabilities.extend(self.vulnerability_mappings[comp.name])
        
        return self.generate_cyclone_dx()