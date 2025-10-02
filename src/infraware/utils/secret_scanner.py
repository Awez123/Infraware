"""
secret_scanner.py
Advanced secret detection engine for InfraWare.
"""

import re
import hashlib
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path
import base64

@dataclass
class SecretFinding:
    """Represents a detected secret."""
    id: str
    type: str
    description: str
    severity: str
    file_path: str
    line_number: int
    column_start: int
    column_end: int
    secret_hash: str  # Hash of the secret for tracking
    confidence: float
    context: str
    remediation: str

class SecretPatterns:
    """Common secret patterns and their detection rules."""
    
    PATTERNS = {
        'aws_access_key': {
            'pattern': r'AKIA[0-9A-Z]{16}',
            'description': 'AWS Access Key ID',
            'severity': 'HIGH',
            'confidence': 0.9,
            'remediation': 'Use AWS IAM roles or AWS Secrets Manager instead of hardcoded keys'
        },
        'aws_secret_key': {
            'pattern': r'[A-Za-z0-9/+=]{40}',
            'description': 'AWS Secret Access Key',
            'severity': 'CRITICAL',
            'confidence': 0.7,
            'remediation': 'Use AWS IAM roles or AWS Secrets Manager instead of hardcoded keys'
        },
        'github_token': {
            'pattern': r'ghp_[A-Za-z0-9]{36}',
            'description': 'GitHub Personal Access Token',
            'severity': 'HIGH',
            'confidence': 0.95,
            'remediation': 'Use GitHub Apps or revoke and regenerate token'
        },
        'google_api_key': {
            'pattern': r'AIza[0-9A-Za-z\\-_]{35}',
            'description': 'Google API Key',
            'severity': 'HIGH',
            'confidence': 0.9,
            'remediation': 'Use Google Service Account keys or Google Secret Manager'
        },
        'azure_storage_key': {
            'pattern': r'[A-Za-z0-9+/]{86}==',
            'description': 'Azure Storage Account Key',
            'severity': 'HIGH',
            'confidence': 0.8,
            'remediation': 'Use Azure Managed Identity or Azure Key Vault'
        },
        'jwt_token': {
            'pattern': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'description': 'JWT Token',
            'severity': 'MEDIUM',
            'confidence': 0.8,
            'remediation': 'Use secure token storage and short-lived tokens'
        },
        'private_key': {
            'pattern': r'-----BEGIN[A-Z ]+PRIVATE KEY-----',
            'description': 'Private Key',
            'severity': 'CRITICAL',
            'confidence': 0.95,
            'remediation': 'Use secure key management systems like HashiCorp Vault'
        },
        'database_url': {
            'pattern': r'(postgresql|mysql|mongodb)://[^\\s]*:[^\\s]*@[^\\s]*',
            'description': 'Database Connection String with Credentials',
            'severity': 'HIGH',
            'confidence': 0.85,
            'remediation': 'Use environment variables or secure credential stores'
        },
        'api_key_generic': {
            'pattern': r'(?i)(api_key|apikey|api-key)\\s*[=:]\\s*["\']?([a-zA-Z0-9]{20,})["\']?',
            'description': 'Generic API Key',
            'severity': 'MEDIUM',
            'confidence': 0.6,
            'remediation': 'Use secure API key management and rotation'
        },
        'password_hardcoded': {
            'pattern': r'(?i)(password|passwd|pwd)\\s*[=:]\\s*["\']([^"\'\\s]{8,})["\']',
            'description': 'Hardcoded Password',
            'severity': 'HIGH',
            'confidence': 0.7,
            'remediation': 'Use secure password management systems'
        }
    }

class SecretScanner:
    """Advanced secret detection scanner."""
    
    def __init__(self):
        self.findings = []
        self.patterns = SecretPatterns.PATTERNS
        
    def scan_text(self, text: str, file_path: str = "unknown") -> List[SecretFinding]:
        """Scan text content for secrets."""
        findings = []
        lines = text.split('\\n')
        
        for line_num, line in enumerate(lines, 1):
            for secret_type, pattern_info in self.patterns.items():
                matches = re.finditer(pattern_info['pattern'], line)
                
                for match in matches:
                    # Skip if it's a placeholder or example
                    if self._is_placeholder(match.group()):
                        continue
                        
                    secret_hash = hashlib.sha256(match.group().encode()).hexdigest()[:16]
                    
                    finding = SecretFinding(
                        id=f"SECRET-{secret_type.upper()}-{secret_hash}",
                        type=secret_type,
                        description=pattern_info['description'],
                        severity=pattern_info['severity'],
                        file_path=file_path,
                        line_number=line_num,
                        column_start=match.start(),
                        column_end=match.end(),
                        secret_hash=secret_hash,
                        confidence=pattern_info['confidence'],
                        context=line.strip(),
                        remediation=pattern_info['remediation']
                    )
                    findings.append(finding)
        
        return findings
    
    def scan_file(self, file_path: str) -> List[SecretFinding]:
        """Scan a file for secrets."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
                return self.scan_text(content, file_path)
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
            return []
    
    def scan_directory(self, directory: str, file_extensions: List[str] = None) -> List[SecretFinding]:
        """Scan directory for secrets."""
        if file_extensions is None:
            file_extensions = ['.tf', '.yaml', '.yml', '.json', '.py', '.js', '.ts', '.go', '.java', '.cs']
        
        findings = []
        path = Path(directory)
        
        for file_path in path.rglob('*'):
            if file_path.is_file() and file_path.suffix in file_extensions:
                findings.extend(self.scan_file(str(file_path)))
        
        return findings
    
    def scan_terraform_plan(self, plan_data: Dict[str, Any]) -> List[SecretFinding]:
        """Scan Terraform plan for secrets."""
        findings = []
        plan_json = json.dumps(plan_data, indent=2)
        findings.extend(self.scan_text(plan_json, "terraform_plan.json"))
        return findings
    
    def _is_placeholder(self, text: str) -> bool:
        """Check if the detected secret is likely a placeholder."""
        placeholders = [
            'your_api_key_here', 'replace_with_actual_key', 'example_key',
            'dummy_key', 'test_key', 'sample_key', 'placeholder',
            'xxxxxxxxxxxx', '************', 'changeme', 'password123'
        ]
        
        text_lower = text.lower()
        return any(placeholder in text_lower for placeholder in placeholders)
    
    def generate_report(self, findings: List[SecretFinding]) -> Dict[str, Any]:
        """Generate comprehensive secret scanning report."""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        type_counts = {}
        
        for finding in findings:
            severity_counts[finding.severity] += 1
            type_counts[finding.type] = type_counts.get(finding.type, 0) + 1
        
        # Calculate risk score
        risk_score = (
            severity_counts['CRITICAL'] * 10 +
            severity_counts['HIGH'] * 7 +
            severity_counts['MEDIUM'] * 4 +
            severity_counts['LOW'] * 1
        )
        
        return {
            'summary': {
                'total_secrets': len(findings),
                'risk_score': risk_score,
                'severity_distribution': severity_counts,
                'secret_types': type_counts
            },
            'findings': [self._finding_to_dict(f) for f in findings]
        }
    
    def _finding_to_dict(self, finding: SecretFinding) -> Dict[str, Any]:
        """Convert SecretFinding to dictionary."""
        return {
            'id': finding.id,
            'type': finding.type,
            'description': finding.description,
            'severity': finding.severity,
            'file_path': finding.file_path,
            'line_number': finding.line_number,
            'column_start': finding.column_start,
            'column_end': finding.column_end,
            'secret_hash': finding.secret_hash,
            'confidence': finding.confidence,
            'context': finding.context,
            'remediation': finding.remediation
        }

class EnhancedSecretScanner(SecretScanner):
    """Enhanced secret scanner with entropy analysis and custom patterns."""
    
    def __init__(self, custom_patterns: Dict[str, Any] = None):
        super().__init__()
        if custom_patterns:
            self.patterns.update(custom_patterns)
    
    def scan_with_entropy(self, text: str, file_path: str = "unknown", min_entropy: float = 4.5) -> List[SecretFinding]:
        """Scan with entropy analysis for unknown secrets."""
        findings = self.scan_text(text, file_path)
        
        # Add entropy-based detection
        entropy_findings = self._detect_high_entropy_strings(text, file_path, min_entropy)
        findings.extend(entropy_findings)
        
        return findings
    
    def _detect_high_entropy_strings(self, text: str, file_path: str, min_entropy: float) -> List[SecretFinding]:
        """Detect high-entropy strings that might be secrets."""
        findings = []
        lines = text.split('\\n')
        
        for line_num, line in enumerate(lines, 1):
            # Look for quoted strings or assignment values
            potential_secrets = re.findall(r'["\']([A-Za-z0-9+/=]{20,})["\']|=\\s*([A-Za-z0-9+/=]{20,})', line)
            
            for groups in potential_secrets:
                for secret in groups:
                    if secret and self._calculate_entropy(secret) >= min_entropy:
                        secret_hash = hashlib.sha256(secret.encode()).hexdigest()[:16]
                        
                        finding = SecretFinding(
                            id=f"SECRET-ENTROPY-{secret_hash}",
                            type="high_entropy",
                            description="High Entropy String (Potential Secret)",
                            severity="MEDIUM",
                            file_path=file_path,
                            line_number=line_num,
                            column_start=line.find(secret),
                            column_end=line.find(secret) + len(secret),
                            secret_hash=secret_hash,
                            confidence=0.6,
                            context=line.strip(),
                            remediation="Review if this is a secret and use secure storage if needed"
                        )
                        findings.append(finding)
        
        return findings
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0
        
        # Get frequency of each character
        char_counts = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        string_length = len(string)
        
        for count in char_counts.values():
            probability = count / string_length
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy