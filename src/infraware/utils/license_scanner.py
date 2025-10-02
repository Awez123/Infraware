"""
license_scanner.py
License compliance and scanning module for InfraWare.
"""

import re
import json
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from pathlib import Path
import hashlib

@dataclass
class LicenseFinding:
    """Represents a detected license."""
    id: str
    license_name: str
    license_type: str
    file_path: str
    package_name: str
    package_version: str
    compatibility: str  # COMPATIBLE, INCOMPATIBLE, UNKNOWN, REQUIRES_REVIEW
    risk_level: str     # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    url: str
    obligations: List[str]
    restrictions: List[str]

class LicenseDatabase:
    """Database of software licenses and their characteristics."""
    
    LICENSES = {
        'MIT': {
            'type': 'Permissive',
            'compatibility': 'COMPATIBLE',
            'risk_level': 'LOW',
            'description': 'MIT License - Very permissive license',
            'url': 'https://opensource.org/licenses/MIT',
            'obligations': ['Include copyright notice', 'Include license text'],
            'restrictions': [],
            'aliases': ['MIT License', 'The MIT License']
        },
        'Apache-2.0': {
            'type': 'Permissive',
            'compatibility': 'COMPATIBLE',
            'risk_level': 'LOW',
            'description': 'Apache License 2.0 - Permissive with patent grant',
            'url': 'https://opensource.org/licenses/Apache-2.0',
            'obligations': ['Include copyright notice', 'Include license text', 'State changes'],
            'restrictions': ['Cannot use trademark'],
            'aliases': ['Apache License 2.0', 'Apache-2.0', 'ASL 2.0']
        },
        'BSD-3-Clause': {
            'type': 'Permissive',
            'compatibility': 'COMPATIBLE',
            'risk_level': 'LOW',
            'description': 'BSD 3-Clause License - Permissive with attribution',
            'url': 'https://opensource.org/licenses/BSD-3-Clause',
            'obligations': ['Include copyright notice', 'Include license text'],
            'restrictions': ['Cannot use names for endorsement'],
            'aliases': ['BSD-3-Clause', '3-Clause BSD', 'New BSD License']
        },
        'GPL-2.0': {
            'type': 'Copyleft',
            'compatibility': 'REQUIRES_REVIEW',
            'risk_level': 'HIGH',
            'description': 'GNU General Public License v2.0 - Strong copyleft',
            'url': 'https://opensource.org/licenses/GPL-2.0',
            'obligations': ['Include copyright notice', 'Include license text', 'Disclose source', 'Same license'],
            'restrictions': ['Must remain open source', 'Cannot combine with proprietary'],
            'aliases': ['GPL-2.0', 'GNU General Public License v2.0', 'GPLv2']
        },
        'GPL-3.0': {
            'type': 'Copyleft',
            'compatibility': 'REQUIRES_REVIEW',
            'risk_level': 'HIGH',
            'description': 'GNU General Public License v3.0 - Strong copyleft with anti-tivoization',
            'url': 'https://opensource.org/licenses/GPL-3.0',
            'obligations': ['Include copyright notice', 'Include license text', 'Disclose source', 'Same license'],
            'restrictions': ['Must remain open source', 'Cannot combine with proprietary', 'Anti-tivoization'],
            'aliases': ['GPL-3.0', 'GNU General Public License v3.0', 'GPLv3']
        },
        'LGPL-2.1': {
            'type': 'Weak Copyleft',
            'compatibility': 'COMPATIBLE',
            'risk_level': 'MEDIUM',
            'description': 'GNU Lesser General Public License v2.1 - Weak copyleft',
            'url': 'https://opensource.org/licenses/LGPL-2.1',
            'obligations': ['Include copyright notice', 'Include license text', 'Allow modification'],
            'restrictions': ['Modified library must remain LGPL'],
            'aliases': ['LGPL-2.1', 'GNU Lesser General Public License v2.1', 'LGPLv2.1']
        },
        'ISC': {
            'type': 'Permissive',
            'compatibility': 'COMPATIBLE',
            'risk_level': 'LOW',
            'description': 'ISC License - Very permissive license',
            'url': 'https://opensource.org/licenses/ISC',
            'obligations': ['Include copyright notice'],
            'restrictions': [],
            'aliases': ['ISC License', 'ISC']
        },
        'MPL-2.0': {
            'type': 'Weak Copyleft',
            'compatibility': 'COMPATIBLE',
            'risk_level': 'MEDIUM',
            'description': 'Mozilla Public License 2.0 - File-level copyleft',
            'url': 'https://opensource.org/licenses/MPL-2.0',
            'obligations': ['Include copyright notice', 'Include license text', 'Disclose source of MPL files'],
            'restrictions': ['Modified MPL files must remain MPL'],
            'aliases': ['MPL-2.0', 'Mozilla Public License 2.0']
        },
        'AGPL-3.0': {
            'type': 'Strong Copyleft',
            'compatibility': 'INCOMPATIBLE',
            'risk_level': 'CRITICAL',
            'description': 'GNU Affero General Public License v3.0 - Network copyleft',
            'url': 'https://opensource.org/licenses/AGPL-3.0',
            'obligations': ['Include copyright notice', 'Include license text', 'Disclose source', 'Network disclosure'],
            'restrictions': ['Must remain open source', 'Network services must provide source'],
            'aliases': ['AGPL-3.0', 'GNU Affero General Public License v3.0', 'AGPLv3']
        },
        'UNLICENSED': {
            'type': 'Proprietary',
            'compatibility': 'INCOMPATIBLE',
            'risk_level': 'CRITICAL',
            'description': 'No license or proprietary license',
            'url': '',
            'obligations': ['Cannot use without permission'],
            'restrictions': ['All rights reserved'],
            'aliases': ['UNLICENSED', 'Proprietary', 'All Rights Reserved']
        }
    }

class LicenseScanner:
    """License scanning and compliance analysis."""
    
    def __init__(self, policy_config: Dict[str, Any] = None):
        self.database = LicenseDatabase.LICENSES
        self.findings = []
        self.policy = policy_config or self._default_policy()
        
    def _default_policy(self) -> Dict[str, Any]:
        """Default license policy configuration."""
        return {
            'allowed_licenses': ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'ISC'],
            'requires_review': ['LGPL-2.1', 'MPL-2.0'],
            'forbidden_licenses': ['GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'UNLICENSED'],
            'allow_unknown': False
        }
    
    def scan_package_json(self, file_path: str) -> List[LicenseFinding]:
        """Scan package.json for license information."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                
            # Check main package license
            if 'license' in data:
                finding = self._create_license_finding(
                    data['license'], file_path, data.get('name', 'unknown'), 
                    data.get('version', 'unknown')
                )
                if finding:
                    findings.append(finding)
            
            # Check dependencies
            dependencies = data.get('dependencies', {})
            dev_dependencies = data.get('devDependencies', {})
            
            all_deps = {**dependencies, **dev_dependencies}
            
            for package_name, version in all_deps.items():
                # Try to find license in node_modules
                license_finding = self._scan_node_modules_license(package_name, file_path)
                if license_finding:
                    findings.append(license_finding)
                    
        except Exception as e:
            print(f"Error scanning package.json {file_path}: {e}")
            
        return findings
    
    def scan_requirements_txt(self, file_path: str) -> List[LicenseFinding]:
        """Scan Python requirements.txt for packages."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parse package name and version
                    package_info = re.match(r'([^=><]+)([=><][^\\s]*)?', line)
                    if package_info:
                        package_name = package_info.group(1).strip()
                        version = package_info.group(2) or 'unknown'
                        
                        # Create finding with unknown license (would need PyPI API in real implementation)
                        finding = LicenseFinding(
                            id=f"LICENSE-PYTHON-{package_name}",
                            license_name="UNKNOWN",
                            license_type="Unknown",
                            file_path=file_path,
                            package_name=package_name,
                            package_version=version,
                            compatibility="UNKNOWN",
                            risk_level="MEDIUM",
                            description="Python package with unknown license",
                            url="",
                            obligations=[],
                            restrictions=["Requires license verification"]
                        )
                        findings.append(finding)
                        
        except Exception as e:
            print(f"Error scanning requirements.txt {file_path}: {e}")
            
        return findings
    
    def scan_go_mod(self, file_path: str) -> List[LicenseFinding]:
        """Scan Go mod file for dependencies."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            # Parse require blocks
            require_blocks = re.findall(r'require\\s*\\((.*?)\\)', content, re.DOTALL)
            require_lines = re.findall(r'require\\s+([^\\s]+)\\s+([^\\s]+)', content)
            
            all_requires = []
            
            # Parse block format
            for block in require_blocks:
                lines = block.strip().split('\\n')
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('//'):
                        match = re.match(r'([^\\s]+)\\s+([^\\s]+)', line)
                        if match:
                            all_requires.append((match.group(1), match.group(2)))
            
            # Add single line requires
            all_requires.extend(require_lines)
            
            for package_name, version in all_requires:
                finding = LicenseFinding(
                    id=f"LICENSE-GO-{package_name.replace('/', '-')}",
                    license_name="UNKNOWN",
                    license_type="Unknown",
                    file_path=file_path,
                    package_name=package_name,
                    package_version=version,
                    compatibility="UNKNOWN",
                    risk_level="MEDIUM",
                    description="Go package with unknown license",
                    url="",
                    obligations=[],
                    restrictions=["Requires license verification"]
                )
                findings.append(finding)
                
        except Exception as e:
            print(f"Error scanning go.mod {file_path}: {e}")
            
        return findings
    
    def scan_directory(self, directory: str) -> List[LicenseFinding]:
        """Scan directory for license files and dependency manifests."""
        findings = []
        path = Path(directory)
        
        # Scan for package files
        package_files = {
            'package.json': self.scan_package_json,
            'requirements.txt': self.scan_requirements_txt,
            'go.mod': self.scan_go_mod,
        }
        
        for file_pattern, scan_func in package_files.items():
            for file_path in path.rglob(file_pattern):
                findings.extend(scan_func(str(file_path)))
        
        # Scan for license files
        license_files = path.rglob('LICENSE*')
        for license_file in license_files:
            if license_file.is_file():
                license_finding = self._scan_license_file(str(license_file))
                if license_finding:
                    findings.append(license_finding)
        
        return findings
    
    def _scan_license_file(self, file_path: str) -> Optional[LicenseFinding]:
        """Scan a license file to identify the license type."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
            
            # Try to identify license by content patterns
            license_name = self._identify_license_by_content(content)
            
            if license_name:
                license_info = self.database.get(license_name, {})
                return LicenseFinding(
                    id=f"LICENSE-FILE-{Path(file_path).parent.name}",
                    license_name=license_name,
                    license_type=license_info.get('type', 'Unknown'),
                    file_path=file_path,
                    package_name=Path(file_path).parent.name,
                    package_version="unknown",
                    compatibility=license_info.get('compatibility', 'UNKNOWN'),
                    risk_level=license_info.get('risk_level', 'MEDIUM'),
                    description=license_info.get('description', f'{license_name} License'),
                    url=license_info.get('url', ''),
                    obligations=license_info.get('obligations', []),
                    restrictions=license_info.get('restrictions', [])
                )
        except Exception as e:
            print(f"Error scanning license file {file_path}: {e}")
        
        return None
    
    def _identify_license_by_content(self, content: str) -> Optional[str]:
        """Identify license type by file content."""
        content_lower = content.lower()
        
        # License identification patterns
        patterns = {
            'MIT': ['permission is hereby granted, free of charge', 'mit license'],
            'Apache-2.0': ['apache license', 'version 2.0'],
            'GPL-2.0': ['gnu general public license', 'version 2'],
            'GPL-3.0': ['gnu general public license', 'version 3'],
            'BSD-3-Clause': ['redistribution and use in source and binary forms', '3-clause'],
            'ISC': ['permission to use, copy, modify, and/or distribute'],
            'MPL-2.0': ['mozilla public license version 2.0'],
            'AGPL-3.0': ['gnu affero general public license']
        }
        
        for license_name, keywords in patterns.items():
            if all(keyword in content_lower for keyword in keywords):
                return license_name
        
        return None
    
    def _create_license_finding(self, license_name: str, file_path: str, 
                              package_name: str, version: str) -> Optional[LicenseFinding]:
        """Create a license finding from license name."""
        # Normalize license name
        normalized_name = self._normalize_license_name(license_name)
        
        if normalized_name in self.database:
            license_info = self.database[normalized_name]
            return LicenseFinding(
                id=f"LICENSE-{normalized_name}-{package_name}",
                license_name=normalized_name,
                license_type=license_info['type'],
                file_path=file_path,
                package_name=package_name,
                package_version=version,
                compatibility=license_info['compatibility'],
                risk_level=license_info['risk_level'],
                description=license_info['description'],
                url=license_info['url'],
                obligations=license_info['obligations'],
                restrictions=license_info['restrictions']
            )
        else:
            # Unknown license
            return LicenseFinding(
                id=f"LICENSE-UNKNOWN-{package_name}",
                license_name=license_name,
                license_type="Unknown",
                file_path=file_path,
                package_name=package_name,
                package_version=version,
                compatibility="UNKNOWN",
                risk_level="MEDIUM",
                description=f"Unknown license: {license_name}",
                url="",
                obligations=["Requires manual review"],
                restrictions=["Unknown restrictions"]
            )
    
    def _normalize_license_name(self, license_name: str) -> str:
        """Normalize license name to match database keys."""
        license_name = license_name.strip()
        
        # Check direct match
        if license_name in self.database:
            return license_name
        
        # Check aliases
        for key, info in self.database.items():
            if license_name in info.get('aliases', []):
                return key
        
        return license_name
    
    def _scan_node_modules_license(self, package_name: str, base_path: str) -> Optional[LicenseFinding]:
        """Scan node_modules for package license."""
        # This is a simplified version - real implementation would parse package.json in node_modules
        base_dir = Path(base_path).parent
        package_json_path = base_dir / 'node_modules' / package_name / 'package.json'
        
        if package_json_path.exists():
            try:
                with open(package_json_path, 'r', encoding='utf-8') as file:
                    package_data = json.load(file)
                
                license_name = package_data.get('license', 'UNKNOWN')
                version = package_data.get('version', 'unknown')
                
                return self._create_license_finding(license_name, str(package_json_path), package_name, version)
                
            except Exception:
                pass
        
        return None
    
    def generate_compliance_report(self, findings: List[LicenseFinding]) -> Dict[str, Any]:
        """Generate license compliance report."""
        compliance_status = {
            'COMPATIBLE': 0,
            'REQUIRES_REVIEW': 0,
            'INCOMPATIBLE': 0,
            'UNKNOWN': 0
        }
        
        risk_levels = {
            'LOW': 0,
            'MEDIUM': 0,
            'HIGH': 0,
            'CRITICAL': 0
        }
        
        license_types = {}
        violations = []
        
        for finding in findings:
            compliance_status[finding.compatibility] += 1
            risk_levels[finding.risk_level] += 1
            license_types[finding.license_name] = license_types.get(finding.license_name, 0) + 1
            
            # Check policy violations
            if finding.license_name in self.policy['forbidden_licenses']:
                violations.append({
                    'type': 'FORBIDDEN_LICENSE',
                    'package': finding.package_name,
                    'license': finding.license_name,
                    'severity': 'HIGH'
                })
            elif finding.compatibility == 'UNKNOWN' and not self.policy['allow_unknown']:
                violations.append({
                    'type': 'UNKNOWN_LICENSE',
                    'package': finding.package_name,
                    'license': finding.license_name,
                    'severity': 'MEDIUM'
                })
        
        # Calculate compliance score
        total_packages = len(findings)
        compatible_packages = compliance_status['COMPATIBLE']
        compliance_score = (compatible_packages / total_packages * 100) if total_packages > 0 else 0
        
        return {
            'summary': {
                'total_packages': total_packages,
                'compliance_score': round(compliance_score, 2),
                'compliance_status': compliance_status,
                'risk_distribution': risk_levels,
                'license_types': license_types,
                'violations': len(violations)
            },
            'violations': violations,
            'findings': [self._finding_to_dict(f) for f in findings],
            'policy': self.policy
        }
    
    def _finding_to_dict(self, finding: LicenseFinding) -> Dict[str, Any]:
        """Convert LicenseFinding to dictionary."""
        return {
            'id': finding.id,
            'license_name': finding.license_name,
            'license_type': finding.license_type,
            'file_path': finding.file_path,
            'package_name': finding.package_name,
            'package_version': finding.package_version,
            'compatibility': finding.compatibility,
            'risk_level': finding.risk_level,
            'description': finding.description,
            'url': finding.url,
            'obligations': finding.obligations,
            'restrictions': finding.restrictions
        }