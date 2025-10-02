"""
dependency_scanner.py
Advanced dependency scanning with vulnerability detection for InfraWare.
"""

import json
import re
import requests
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path
import hashlib
from datetime import datetime, timedelta

@dataclass
class DependencyVulnerability:
    """Represents a vulnerability in a dependency."""
    id: str
    cve_id: str
    severity: str
    score: float
    summary: str
    description: str
    affected_versions: List[str]
    fixed_versions: List[str]
    published_date: str
    references: List[str]
    package_name: str
    package_version: str

@dataclass
class Dependency:
    """Represents a software dependency."""
    name: str
    version: str
    ecosystem: str  # npm, pypi, go, nuget, etc.
    license: Optional[str] = None
    description: Optional[str] = None
    homepage: Optional[str] = None
    vulnerabilities: List[DependencyVulnerability] = None
    direct: bool = True  # Is this a direct dependency?
    dependencies: List[str] = None  # Sub-dependencies

class VulnerabilityDatabase:
    """Mock vulnerability database - in production, this would connect to real sources."""
    
    def __init__(self):
        self.cache = {}
        self.cache_expiry = timedelta(hours=24)
        
        # Mock vulnerability data for demonstration
        self.mock_vulnerabilities = {
            'lodash': [
                {
                    'id': 'GHSA-jf85-cpcp-j695',
                    'cve_id': 'CVE-2021-23337',
                    'severity': 'HIGH',
                    'score': 7.2,
                    'summary': 'Command Injection in lodash',
                    'description': 'lodash versions prior to 4.17.21 are vulnerable to Command Injection via template.',
                    'affected_versions': ['<4.17.21'],
                    'fixed_versions': ['4.17.21'],
                    'published_date': '2021-02-15',
                    'references': [
                        'https://github.com/advisories/GHSA-jf85-cpcp-j695',
                        'https://nvd.nist.gov/vuln/detail/CVE-2021-23337'
                    ]
                }
            ],
            'requests': [
                {
                    'id': 'PYSEC-2023-74',
                    'cve_id': 'CVE-2023-32681',
                    'severity': 'MEDIUM',
                    'score': 6.1,
                    'summary': 'Proxy-Authorization header leak in Requests',
                    'description': 'Requests is a HTTP library. Since Requests 2.3.0, Requests has been vulnerable to potentially leaking Proxy-Authorization headers.',
                    'affected_versions': ['>=2.3.0,<2.31.0'],
                    'fixed_versions': ['2.31.0'],
                    'published_date': '2023-05-26',
                    'references': [
                        'https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q'
                    ]
                }
            ],
            'golang.org/x/crypto': [
                {
                    'id': 'GO-2022-0969',
                    'cve_id': 'CVE-2022-27191',
                    'severity': 'HIGH',
                    'score': 7.5,
                    'summary': 'Crash in golang.org/x/crypto/ssh',
                    'description': 'The golang.org/x/crypto/ssh package before 0.0.0-20220314234659-1baeb1ce4c0b for Go allows an attacker to crash a server.',
                    'affected_versions': ['<0.0.0-20220314234659-1baeb1ce4c0b'],
                    'fixed_versions': ['0.0.0-20220314234659-1baeb1ce4c0b'],
                    'published_date': '2022-03-18',
                    'references': [
                        'https://pkg.go.dev/vuln/GO-2022-0969'
                    ]
                }
            ]
        }
    
    def get_vulnerabilities(self, package_name: str, version: str, ecosystem: str) -> List[DependencyVulnerability]:
        """Get vulnerabilities for a package."""
        cache_key = f"{ecosystem}:{package_name}:{version}"
        
        # Check cache first
        if cache_key in self.cache:
            cache_time, vulns = self.cache[cache_key]
            if datetime.now() - cache_time < self.cache_expiry:
                return vulns
        
        # Mock implementation - in production, query real vulnerability databases
        vulns = self._query_mock_vulnerabilities(package_name, version, ecosystem)
        
        # Cache results
        self.cache[cache_key] = (datetime.now(), vulns)
        
        return vulns
    
    def _query_mock_vulnerabilities(self, package_name: str, version: str, ecosystem: str) -> List[DependencyVulnerability]:
        """Query mock vulnerability data."""
        vulnerabilities = []
        
        mock_data = self.mock_vulnerabilities.get(package_name, [])
        
        for vuln_data in mock_data:
            # Check if version is affected
            if self._is_version_affected(version, vuln_data['affected_versions']):
                vulnerability = DependencyVulnerability(
                    id=vuln_data['id'],
                    cve_id=vuln_data['cve_id'],
                    severity=vuln_data['severity'],
                    score=vuln_data['score'],
                    summary=vuln_data['summary'],
                    description=vuln_data['description'],
                    affected_versions=vuln_data['affected_versions'],
                    fixed_versions=vuln_data['fixed_versions'],
                    published_date=vuln_data['published_date'],
                    references=vuln_data['references'],
                    package_name=package_name,
                    package_version=version
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _is_version_affected(self, version: str, affected_patterns: List[str]) -> bool:
        """Check if a version matches affected version patterns."""
        # Simplified version matching - production would use semantic versioning
        for pattern in affected_patterns:
            if '<' in pattern:
                # Handle patterns like "<4.17.21" or ">=2.3.0,<2.31.0"
                if ',' in pattern:
                    # Range pattern
                    parts = pattern.split(',')
                    for part in parts:
                        part = part.strip()
                        if part.startswith('>=') and self._version_gte(version, part[2:]):
                            continue
                        elif part.startswith('<') and self._version_lt(version, part[1:]):
                            continue
                        else:
                            return False
                    return True
                else:
                    # Simple less than
                    if pattern.startswith('<') and self._version_lt(version, pattern[1:]):
                        return True
            elif pattern == version:
                return True
        
        return False
    
    def _version_lt(self, v1: str, v2: str) -> bool:
        """Simple version comparison - less than."""
        try:
            # Remove non-numeric characters for simple comparison
            v1_clean = re.sub(r'[^0-9.]', '', v1)
            v2_clean = re.sub(r'[^0-9.]', '', v2)
            
            v1_parts = [int(x) for x in v1_clean.split('.') if x.isdigit()]
            v2_parts = [int(x) for x in v2_clean.split('.') if x.isdigit()]
            
            # Pad shorter version with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            return v1_parts < v2_parts
        except:
            return False
    
    def _version_gte(self, v1: str, v2: str) -> bool:
        """Simple version comparison - greater than or equal."""
        return not self._version_lt(v1, v2)

class DependencyScanner:
    """Advanced dependency scanner with vulnerability detection."""
    
    def __init__(self):
        self.vuln_db = VulnerabilityDatabase()
        self.dependencies = []
        
    def scan_package_json(self, file_path: str) -> List[Dependency]:
        """Scan Node.js package.json for dependencies."""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
            
            # Scan production dependencies
            prod_deps = data.get('dependencies', {})
            for name, version in prod_deps.items():
                clean_version = self._clean_version(version)
                vulns = self.vuln_db.get_vulnerabilities(name, clean_version, 'npm')
                
                dependency = Dependency(
                    name=name,
                    version=clean_version,
                    ecosystem='npm',
                    direct=True,
                    vulnerabilities=vulns
                )
                dependencies.append(dependency)
            
            # Scan dev dependencies
            dev_deps = data.get('devDependencies', {})
            for name, version in dev_deps.items():
                clean_version = self._clean_version(version)
                vulns = self.vuln_db.get_vulnerabilities(name, clean_version, 'npm')
                
                dependency = Dependency(
                    name=name,
                    version=clean_version,
                    ecosystem='npm',
                    direct=True,
                    vulnerabilities=vulns
                )
                dependencies.append(dependency)
                
        except Exception as e:
            print(f"Error scanning package.json {file_path}: {e}")
        
        return dependencies
    
    def scan_requirements_txt(self, file_path: str) -> List[Dependency]:
        """Scan Python requirements.txt for dependencies."""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parse package specification
                    match = re.match(r'([^=><]+)([=><][^\\s]*)?', line)
                    if match:
                        name = match.group(1).strip()
                        version_spec = match.group(2) or ''
                        version = self._extract_version_from_spec(version_spec)
                        
                        vulns = self.vuln_db.get_vulnerabilities(name, version, 'pypi')
                        
                        dependency = Dependency(
                            name=name,
                            version=version,
                            ecosystem='pypi',
                            direct=True,
                            vulnerabilities=vulns
                        )
                        dependencies.append(dependency)
                        
        except Exception as e:
            print(f"Error scanning requirements.txt {file_path}: {e}")
        
        return dependencies
    
    def scan_go_mod(self, file_path: str) -> List[Dependency]:
        """Scan Go mod file for dependencies."""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            # Parse require statements
            require_pattern = r'require\\s+([^\\s]+)\\s+([^\\s]+)'
            matches = re.findall(require_pattern, content)
            
            for name, version in matches:
                if not name.startswith('//'):  # Skip comments
                    vulns = self.vuln_db.get_vulnerabilities(name, version, 'go')
                    
                    dependency = Dependency(
                        name=name,
                        version=version,
                        ecosystem='go',
                        direct=True,
                        vulnerabilities=vulns
                    )
                    dependencies.append(dependency)
                    
        except Exception as e:
            print(f"Error scanning go.mod {file_path}: {e}")
        
        return dependencies
    
    def scan_directory(self, directory: str) -> Dict[str, Any]:
        """Scan directory for all dependency files."""
        path = Path(directory)
        all_dependencies = []
        
        # Define scanners for different file types
        scanners = {
            'package.json': self.scan_package_json,
            'requirements.txt': self.scan_requirements_txt,
            'go.mod': self.scan_go_mod,
        }
        
        # Scan each file type
        for file_pattern, scanner in scanners.items():
            for file_path in path.rglob(file_pattern):
                deps = scanner(str(file_path))
                all_dependencies.extend(deps)
        
        # Generate summary
        return self._generate_dependency_report(all_dependencies)
    
    def _generate_dependency_report(self, dependencies: List[Dependency]) -> Dict[str, Any]:
        """Generate comprehensive dependency report."""
        total_deps = len(dependencies)
        vulnerable_deps = [dep for dep in dependencies if dep.vulnerabilities]
        
        # Count vulnerabilities by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        ecosystem_counts = {}
        
        for dep in dependencies:
            ecosystem_counts[dep.ecosystem] = ecosystem_counts.get(dep.ecosystem, 0) + 1
            
            if dep.vulnerabilities:
                for vuln in dep.vulnerabilities:
                    severity_counts[vuln.severity] += 1
        
        # Calculate risk score
        risk_score = (
            severity_counts['CRITICAL'] * 10 +
            severity_counts['HIGH'] * 7 +
            severity_counts['MEDIUM'] * 4 +
            severity_counts['LOW'] * 1
        )
        
        return {
            'summary': {
                'total_dependencies': total_deps,
                'vulnerable_dependencies': len(vulnerable_deps),
                'total_vulnerabilities': sum(severity_counts.values()),
                'risk_score': risk_score,
                'severity_distribution': severity_counts,
                'ecosystem_distribution': ecosystem_counts
            },
            'vulnerable_dependencies': [
                {
                    'name': dep.name,
                    'version': dep.version,
                    'ecosystem': dep.ecosystem,
                    'vulnerabilities': [
                        {
                            'id': vuln.id,
                            'cve_id': vuln.cve_id,
                            'severity': vuln.severity,
                            'score': vuln.score,
                            'summary': vuln.summary,
                            'fixed_versions': vuln.fixed_versions
                        }
                        for vuln in dep.vulnerabilities
                    ]
                }
                for dep in vulnerable_deps
            ],
            'all_dependencies': [
                {
                    'name': dep.name,
                    'version': dep.version,
                    'ecosystem': dep.ecosystem,
                    'direct': dep.direct,
                    'has_vulnerabilities': bool(dep.vulnerabilities)
                }
                for dep in dependencies
            ]
        }
    
    def _clean_version(self, version: str) -> str:
        """Clean version string by removing prefixes like ^, ~, etc."""
        return re.sub(r'^[^0-9]*', '', version)
    
    def _extract_version_from_spec(self, version_spec: str) -> str:
        """Extract version from specification like ==1.2.3 or >=1.0.0."""
        if not version_spec:
            return 'unknown'
        
        # Remove operators
        version = re.sub(r'^[=><]+', '', version_spec)
        return version.strip()

class EnhancedDependencyScanner(DependencyScanner):
    """Enhanced dependency scanner with license and SBOM integration."""
    
    def __init__(self):
        super().__init__()
        from .license_scanner import LicenseScanner
        from .sbom_generator import SBOMGenerator
        
        self.license_scanner = LicenseScanner()
        self.sbom_generator = SBOMGenerator()
    
    def scan_with_full_analysis(self, directory: str) -> Dict[str, Any]:
        """Perform comprehensive dependency analysis including vulnerabilities, licenses, and SBOM."""
        # Get dependency report
        dep_report = self.scan_directory(directory)
        
        # Get license report
        license_report = self.license_scanner.scan_directory(directory)
        
        # Generate SBOM
        sbom_report = self.sbom_generator.scan_directory_for_sbom(directory)
        
        # Combine reports
        return {
            'dependencies': dep_report,
            'licenses': self.license_scanner.generate_compliance_report(license_report),
            'sbom': sbom_report,
            'combined_risk_score': self._calculate_combined_risk_score(dep_report, license_report)
        }
    
    def _calculate_combined_risk_score(self, dep_report: Dict[str, Any], license_findings: List) -> float:
        """Calculate combined risk score from dependencies and licenses."""
        dep_risk = dep_report['summary']['risk_score']
        
        # License risk calculation
        license_risk = 0
        for finding in license_findings:
            if hasattr(finding, 'risk_level'):
                if finding.risk_level == 'CRITICAL':
                    license_risk += 10
                elif finding.risk_level == 'HIGH':
                    license_risk += 7
                elif finding.risk_level == 'MEDIUM':
                    license_risk += 4
                elif finding.risk_level == 'LOW':
                    license_risk += 1
        
        # Weighted combination
        combined_risk = (dep_risk * 0.7) + (license_risk * 0.3)
        return round(combined_risk, 2)