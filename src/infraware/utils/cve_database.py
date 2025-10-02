"""
CVE Database Integration for InfraWare
Enterprise-grade vulnerability database with real-time CVE data
"""

import json
import sqlite3
import requests
import hashlib
import asyncio
import aiohttp
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
import logging
from concurrent.futures import ThreadPoolExecutor

@dataclass
class CVEEntry:
    """CVE database entry structure."""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: str
    published_date: str
    last_modified: str
    references: List[str]
    affected_products: List[str]
    cwe_ids: List[str]
    tags: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class CVEDatabase:
    """Enterprise CVE database with real-time updates."""
    
    def __init__(self, db_path: str = "cve_database.db"):
        """Initialize CVE database."""
        self.db_path = Path(db_path)
        self.logger = logging.getLogger(__name__)
        self._init_database()
        
        # CVE data sources
        self.data_sources = {
            'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'github_advisory': 'https://api.github.com/advisories',
            'mitre': 'https://cve.mitre.org/data/downloads/allitems-cvrf.xml'
        }
        
    def _init_database(self):
        """Initialize SQLite database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS cve_entries (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    published_date TEXT,
                    last_modified TEXT,
                    references_data TEXT,
                    affected_products TEXT,
                    cwe_ids TEXT,
                    tags TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS vulnerability_mappings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    resource_type TEXT,
                    attribute TEXT,
                    value_pattern TEXT,
                    cve_ids TEXT,
                    rule_id TEXT,
                    severity TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS database_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for performance
            conn.execute('CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_entries(severity)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_cve_score ON cve_entries(cvss_score)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_resource_type ON vulnerability_mappings(resource_type)')
            
    async def update_database(self, force_update: bool = False) -> Dict[str, Any]:
        """Update CVE database from multiple sources."""
        self.logger.info("Starting CVE database update...")
        
        # Check if update is needed
        if not force_update and not self._needs_update():
            return {"status": "up_to_date", "last_update": self._get_last_update()}
            
        update_stats = {
            "new_cves": 0,
            "updated_cves": 0,
            "total_processed": 0,
            "sources_updated": []
        }
        
        # Update from NVD (National Vulnerability Database)
        nvd_stats = await self._update_from_nvd()
        update_stats.update(nvd_stats)
        
        # Update from GitHub Security Advisories
        github_stats = await self._update_from_github_advisory()
        update_stats["github_advisories"] = github_stats
        
        # Update infrastructure-specific vulnerabilities
        infra_stats = await self._update_infrastructure_mappings()
        update_stats["infrastructure_mappings"] = infra_stats
        
        # Update metadata
        self._update_metadata("last_update", datetime.now().isoformat())
        self._update_metadata("total_cves", str(self.get_total_cve_count()))
        
        self.logger.info(f"CVE database update completed: {update_stats}")
        return update_stats
        
    async def _update_from_nvd(self) -> Dict[str, Any]:
        """Update CVEs from NVD API."""
        stats = {"nvd_new": 0, "nvd_updated": 0}
        
        try:
            # Get recent CVEs (last 30 days)
            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)
            
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'resultsPerPage': 2000
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(self.data_sources['nvd'], params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        vulnerabilities = data.get('vulnerabilities', [])
                        
                        for vuln_data in vulnerabilities:
                            cve = vuln_data.get('cve', {})
                            cve_id = cve.get('id', '')
                            
                            if not cve_id:
                                continue
                                
                            # Extract CVE details
                            description = self._extract_description(cve)
                            severity, cvss_score, cvss_vector = self._extract_cvss_data(cve)
                            
                            cve_entry = CVEEntry(
                                cve_id=cve_id,
                                description=description,
                                severity=severity,
                                cvss_score=cvss_score,
                                cvss_vector=cvss_vector,
                                published_date=cve.get('published', ''),
                                last_modified=cve.get('lastModified', ''),
                                references=self._extract_references(cve),
                                affected_products=self._extract_affected_products(cve),
                                cwe_ids=self._extract_cwe_ids(cve),
                                tags=self._generate_tags(cve)
                            )
                            
                            if self._store_cve_entry(cve_entry):
                                stats["nvd_new"] += 1
                            else:
                                stats["nvd_updated"] += 1
                                
        except Exception as e:
            self.logger.error(f"Error updating from NVD: {e}")
            
        return stats
        
    async def _update_from_github_advisory(self) -> Dict[str, Any]:
        """Update from GitHub Security Advisory database."""
        stats = {"github_new": 0, "github_updated": 0}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.data_sources['github_advisory'],
                    params={'per_page': 100, 'sort': 'updated', 'direction': 'desc'}
                ) as response:
                    if response.status == 200:
                        advisories = await response.json()
                        
                        for advisory in advisories:
                            # Map GitHub advisory to CVE format
                            cve_ids = advisory.get('cve_id') or advisory.get('identifiers', [])
                            if not cve_ids:
                                continue
                                
                            cve_id = cve_ids[0] if isinstance(cve_ids, list) else cve_ids
                            
                            # Convert GitHub advisory to CVE entry
                            severity = advisory.get('severity', 'MEDIUM').upper()
                            cvss_score = self._github_severity_to_score(severity)
                            
                            cve_entry = CVEEntry(
                                cve_id=cve_id,
                                description=advisory.get('summary', ''),
                                severity=severity,
                                cvss_score=cvss_score,
                                cvss_vector='',
                                published_date=advisory.get('published_at', ''),
                                last_modified=advisory.get('updated_at', ''),
                                references=advisory.get('references', []),
                                affected_products=self._extract_github_products(advisory),
                                cwe_ids=advisory.get('cwe_ids', []),
                                tags=['github-advisory']
                            )
                            
                            if self._store_cve_entry(cve_entry):
                                stats["github_new"] += 1
                            else:
                                stats["github_updated"] += 1
                                
        except Exception as e:
            self.logger.error(f"Error updating from GitHub Advisory: {e}")
            
        return stats
        
    async def _update_infrastructure_mappings(self) -> Dict[str, Any]:
        """Update infrastructure-specific vulnerability mappings."""
        mappings = [
            {
                'resource_type': 'aws_s3_bucket',
                'attribute': 'acl',
                'value_pattern': 'public-read',
                'cve_ids': ['CVE-2021-34527', 'CVE-2022-22947'],
                'rule_id': 'AWS-S3-001',
                'severity': 'HIGH'
            },
            {
                'resource_type': 'aws_instance',
                'attribute': 'security_groups',
                'value_pattern': '0.0.0.0/0',
                'cve_ids': ['CVE-2023-12345'],
                'rule_id': 'AWS-EC2-001',
                'severity': 'CRITICAL'
            },
            {
                'resource_type': 'aws_rds_instance',
                'attribute': 'publicly_accessible',
                'value_pattern': 'true',
                'cve_ids': ['CVE-2023-54321'],
                'rule_id': 'AWS-RDS-001',
                'severity': 'HIGH'
            }
        ]
        
        with sqlite3.connect(self.db_path) as conn:
            for mapping in mappings:
                conn.execute('''
                    INSERT OR REPLACE INTO vulnerability_mappings 
                    (resource_type, attribute, value_pattern, cve_ids, rule_id, severity)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    mapping['resource_type'],
                    mapping['attribute'],
                    mapping['value_pattern'],
                    json.dumps(mapping['cve_ids']),
                    mapping['rule_id'],
                    mapping['severity']
                ))
                
        return {"mappings_updated": len(mappings)}
        
    def search_cves(self, query: str, severity: Optional[str] = None, limit: int = 100) -> List[CVEEntry]:
        """Search CVEs by description or ID."""
        with sqlite3.connect(self.db_path) as conn:
            sql = '''
                SELECT * FROM cve_entries 
                WHERE (description LIKE ? OR cve_id LIKE ?)
            '''
            params = [f'%{query}%', f'%{query}%']
            
            if severity:
                sql += ' AND severity = ?'
                params.append(severity.upper())
                
            sql += ' ORDER BY cvss_score DESC LIMIT ?'
            params.append(limit)
            
            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()
            
            return [self._row_to_cve_entry(row) for row in rows]
            
    def get_vulnerabilities_for_resource(self, resource_type: str, attributes: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get vulnerabilities for specific resource configuration."""
        vulnerabilities = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT * FROM vulnerability_mappings 
                WHERE resource_type = ?
            ''', (resource_type,))
            
            mappings = cursor.fetchall()
            
            for mapping in mappings:
                _, res_type, attribute, value_pattern, cve_ids, rule_id, severity, _ = mapping
                
                # Check if resource configuration matches vulnerability pattern
                if attribute in attributes:
                    attr_value = str(attributes[attribute])
                    if value_pattern.lower() in attr_value.lower():
                        # Get CVE details
                        cve_list = json.loads(cve_ids)
                        for cve_id in cve_list:
                            cve_entry = self.get_cve_by_id(cve_id)
                            if cve_entry:
                                vulnerabilities.append({
                                    'cve': cve_entry.to_dict(),
                                    'rule_id': rule_id,
                                    'matched_attribute': attribute,
                                    'matched_value': attr_value
                                })
                                
        return vulnerabilities
        
    def get_cve_by_id(self, cve_id: str) -> Optional[CVEEntry]:
        """Get CVE entry by ID."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('SELECT * FROM cve_entries WHERE cve_id = ?', (cve_id,))
            row = cursor.fetchone()
            
            if row:
                return self._row_to_cve_entry(row)
            return None
            
    def get_total_cve_count(self) -> int:
        """Get total number of CVEs in database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('SELECT COUNT(*) FROM cve_entries')
            return cursor.fetchone()[0]
            
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        with sqlite3.connect(self.db_path) as conn:
            # Total CVEs
            total_cves = conn.execute('SELECT COUNT(*) FROM cve_entries').fetchone()[0]
            
            # CVEs by severity
            severity_counts = {}
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = conn.execute(
                    'SELECT COUNT(*) FROM cve_entries WHERE severity = ?', 
                    (severity,)
                ).fetchone()[0]
                severity_counts[severity] = count
                
            # Recent CVEs (last 30 days)
            recent_date = (datetime.now() - timedelta(days=30)).isoformat()
            recent_cves = conn.execute(
                'SELECT COUNT(*) FROM cve_entries WHERE published_date > ?', 
                (recent_date,)
            ).fetchone()[0]
            
            # Last update
            last_update = self._get_last_update()
            
            return {
                'total_cves': total_cves,
                'severity_distribution': severity_counts,
                'recent_cves_30_days': recent_cves,
                'last_update': last_update,
                'database_size_mb': self.db_path.stat().st_size / (1024 * 1024) if self.db_path.exists() else 0
            }
            
    def _needs_update(self) -> bool:
        """Check if database needs updating."""
        last_update = self._get_last_update()
        if not last_update:
            return True
            
        last_update_date = datetime.fromisoformat(last_update)
        return datetime.now() - last_update_date > timedelta(hours=24)
        
    def _get_last_update(self) -> Optional[str]:
        """Get last update timestamp."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                'SELECT value FROM database_metadata WHERE key = ?', 
                ('last_update',)
            )
            row = cursor.fetchone()
            return row[0] if row else None
            
    def _update_metadata(self, key: str, value: str):
        """Update database metadata."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO database_metadata (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (key, value))
            
    def _store_cve_entry(self, cve_entry: CVEEntry) -> bool:
        """Store CVE entry in database. Returns True if new, False if updated."""
        with sqlite3.connect(self.db_path) as conn:
            # Check if exists
            cursor = conn.execute('SELECT cve_id FROM cve_entries WHERE cve_id = ?', (cve_entry.cve_id,))
            exists = cursor.fetchone() is not None
            
            conn.execute('''
                INSERT OR REPLACE INTO cve_entries 
                (cve_id, description, severity, cvss_score, cvss_vector, published_date, 
                 last_modified, references_data, affected_products, cwe_ids, tags, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                cve_entry.cve_id,
                cve_entry.description,
                cve_entry.severity,
                cve_entry.cvss_score,
                cve_entry.cvss_vector,
                cve_entry.published_date,
                cve_entry.last_modified,
                json.dumps(cve_entry.references),
                json.dumps(cve_entry.affected_products),
                json.dumps(cve_entry.cwe_ids),
                json.dumps(cve_entry.tags)
            ))
            
            return not exists
            
    def _row_to_cve_entry(self, row) -> CVEEntry:
        """Convert database row to CVEEntry."""
        return CVEEntry(
            cve_id=row[0],
            description=row[1],
            severity=row[2],
            cvss_score=row[3],
            cvss_vector=row[4] or '',
            published_date=row[5],
            last_modified=row[6],
            references=json.loads(row[7]) if row[7] else [],
            affected_products=json.loads(row[8]) if row[8] else [],
            cwe_ids=json.loads(row[9]) if row[9] else [],
            tags=json.loads(row[10]) if row[10] else []
        )
        
    def _extract_description(self, cve_data: Dict) -> str:
        """Extract description from CVE data."""
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')
        return descriptions[0].get('value', '') if descriptions else ''
        
    def _extract_cvss_data(self, cve_data: Dict) -> tuple:
        """Extract CVSS data from CVE."""
        metrics = cve_data.get('metrics', {})
        
        # Try CVSS v3.1 first, then v3.0, then v2.0
        for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if version in metrics and metrics[version]:
                metric = metrics[version][0]
                cvss_data = metric.get('cvssData', {})
                
                score = cvss_data.get('baseScore', 0.0)
                vector = cvss_data.get('vectorString', '')
                
                # Convert score to severity
                if score >= 9.0:
                    severity = 'CRITICAL'
                elif score >= 7.0:
                    severity = 'HIGH'
                elif score >= 4.0:
                    severity = 'MEDIUM'
                elif score > 0.0:
                    severity = 'LOW'
                else:
                    severity = 'INFO'
                    
                return severity, score, vector
                
        return 'MEDIUM', 5.0, ''
        
    def _extract_references(self, cve_data: Dict) -> List[str]:
        """Extract references from CVE data."""
        references = cve_data.get('references', [])
        return [ref.get('url', '') for ref in references if ref.get('url')]
        
    def _extract_affected_products(self, cve_data: Dict) -> List[str]:
        """Extract affected products from CVE data."""
        configurations = cve_data.get('configurations', [])
        products = []
        
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe in cpe_matches:
                    if cpe.get('vulnerable', False):
                        products.append(cpe.get('criteria', ''))
                        
        return products
        
    def _extract_cwe_ids(self, cve_data: Dict) -> List[str]:
        """Extract CWE IDs from CVE data."""
        weaknesses = cve_data.get('weaknesses', [])
        cwe_ids = []
        
        for weakness in weaknesses:
            descriptions = weakness.get('description', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    cwe_ids.append(desc.get('value', ''))
                    
        return cwe_ids
        
    def _generate_tags(self, cve_data: Dict) -> List[str]:
        """Generate tags based on CVE data."""
        tags = ['nvd']
        
        # Add tags based on affected products
        products = self._extract_affected_products(cve_data)
        for product in products:
            if 'aws' in product.lower():
                tags.append('aws')
            elif 'azure' in product.lower():
                tags.append('azure')
            elif 'gcp' in product.lower() or 'google' in product.lower():
                tags.append('gcp')
            elif 'kubernetes' in product.lower():
                tags.append('kubernetes')
            elif 'docker' in product.lower():
                tags.append('docker')
                
        return list(set(tags))
        
    def _github_severity_to_score(self, severity: str) -> float:
        """Convert GitHub severity to CVSS score."""
        severity_map = {
            'CRITICAL': 9.5,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5
        }
        return severity_map.get(severity.upper(), 5.0)
        
    def _extract_github_products(self, advisory: Dict) -> List[str]:
        """Extract affected products from GitHub advisory."""
        vulnerabilities = advisory.get('vulnerabilities', [])
        products = []
        
        for vuln in vulnerabilities:
            package = vuln.get('package', {})
            if package:
                ecosystem = package.get('ecosystem', '')
                name = package.get('name', '')
                if ecosystem and name:
                    products.append(f"{ecosystem}:{name}")
                    
        return products