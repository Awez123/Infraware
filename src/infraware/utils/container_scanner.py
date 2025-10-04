"""
Container Security Scanner for InfraWare
Enterprise-grade container image and Dockerfile security analysis
"""

import json
import re
import subprocess
import docker
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import uuid
import base64
import asyncio
import aiohttp
import tarfile
import tempfile
from concurrent.futures import ThreadPoolExecutor

@dataclass
class ContainerVulnerability:
    """Container vulnerability finding."""
    id: str
    cve_id: str
    package_name: str
    installed_version: str
    fixed_version: Optional[str]
    severity: str
    cvss_score: float
    description: str
    layer_id: str
    file_path: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class DockerfileIssue:
    """Dockerfile security issue."""
    id: str
    rule_id: str
    severity: str
    line_number: int
    instruction: str
    issue: str
    remediation: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ContainerScanResult:
    """Complete container scan results."""
    image_name: str
    image_id: str
    size_mb: float
    layers: List[Dict[str, Any]]
    vulnerabilities: List[ContainerVulnerability]
    dockerfile_issues: List[DockerfileIssue]
    secrets: List[Dict[str, Any]]
    packages: List[Dict[str, Any]]
    os_info: Dict[str, Any]
    security_score: float
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class ContainerSecurityScanner:
    """Enterprise container security scanner."""
    
    def __init__(self):
        """Initialize container scanner."""
        self.docker_client = None
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.dockerfile_rules = self._load_dockerfile_rules()
        self._init_docker_client()
        
    def _init_docker_client(self):
        """Initialize Docker client."""
        try:
            self.docker_client = docker.from_env()
            # Test connection
            self.docker_client.ping()
        except Exception as e:
            print(f"Warning: Docker client not available: {e}")
            self.docker_client = None
            
    async def scan_image(self, image_name: str, include_layers: bool = True) -> ContainerScanResult:
        """Comprehensive container image security scan."""
        print(f"Scanning container image: {image_name}")

        # Pull image if not available locally
        image = await self._pull_image(image_name)
        if not image:
            raise ValueError(f"Could not pull or find image: {image_name}")

        # Extract image metadata
        image_info = self._extract_image_info(image)

        # Scan for vulnerabilities (pass image object then image name)
        vulnerabilities = await self._scan_vulnerabilities(image, image_name)

        # Analyze layers
        layers = []
        if include_layers:
            layers = await self._analyze_layers(image)

        # Scan for secrets
        secrets = await self._scan_container_secrets(image, image_name)

        # Analyze packages
        packages = await self._analyze_packages(image)

        # Get OS information
        os_info = await self._get_os_info(image, image_name)

        # Calculate security score
        security_score = self._calculate_security_score(vulnerabilities, secrets)

        # Generate recommendations
        recommendations = self._generate_recommendations(vulnerabilities, secrets, packages)

        return ContainerScanResult(
            image_name=image_name,
            image_id=image.id if hasattr(image, 'id') else getattr(image, 'short_id', ''),
            size_mb=round(getattr(image, 'attrs', {}).get('Size', 0) / (1024 * 1024), 2),
            layers=layers,
            vulnerabilities=vulnerabilities,
            dockerfile_issues=[],  # Will be populated if Dockerfile is provided
            secrets=secrets,
            packages=packages,
            os_info=os_info,
            security_score=security_score,
            recommendations=recommendations
        )
        
    async def scan_dockerfile(self, dockerfile_path: str) -> List[DockerfileIssue]:
        """Scan Dockerfile for security issues."""
        issues = []
        
        if not Path(dockerfile_path).exists():
            raise FileNotFoundError(f"Dockerfile not found: {dockerfile_path}")
            
        with open(dockerfile_path, 'r') as f:
            lines = f.readlines()
            
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            # Check each rule
            for rule in self.dockerfile_rules:
                if self._matches_rule(line, rule):
                    issue = DockerfileIssue(
                        id=f"DOCKERFILE-{rule['id']}-{line_num}",
                        rule_id=rule['id'],
                        severity=rule['severity'],
                        line_number=line_num,
                        instruction=line,
                        issue=rule['description'],
                        remediation=rule['remediation']
                    )
                    issues.append(issue)
                    
        return issues
        
    async def scan_container_runtime(self, container_id: str) -> Dict[str, Any]:
        """Scan running container for runtime security issues."""
        if not self.docker_client:
            raise RuntimeError("Docker client not available")
            
        try:
            container = self.docker_client.containers.get(container_id)
            
            # Get container info
            info = container.attrs
            
            # Check security configurations
            security_issues = []
            
            # Check if running as root
            user = info.get('Config', {}).get('User', '')
            if not user or user == 'root' or user == '0':
                security_issues.append({
                    'type': 'PRIVILEGE_ESCALATION',
                    'severity': 'HIGH',
                    'description': 'Container running as root user',
                    'remediation': 'Run container with non-root user'
                })
                
            # Check privileged mode
            if info.get('HostConfig', {}).get('Privileged', False):
                security_issues.append({
                    'type': 'PRIVILEGED_CONTAINER',
                    'severity': 'CRITICAL',
                    'description': 'Container running in privileged mode',
                    'remediation': 'Remove --privileged flag and use specific capabilities'
                })
                
            # Check network mode
            network_mode = info.get('HostConfig', {}).get('NetworkMode', '')
            if network_mode == 'host':
                security_issues.append({
                    'type': 'HOST_NETWORK',
                    'severity': 'HIGH',
                    'description': 'Container using host networking',
                    'remediation': 'Use bridge or custom network instead of host network'
                })
                
            # Check mounted volumes
            mounts = info.get('Mounts', [])
            for mount in mounts:
                if mount.get('Source') == '/':
                    security_issues.append({
                        'type': 'ROOT_MOUNT',
                        'severity': 'CRITICAL',
                        'description': 'Root filesystem mounted in container',
                        'remediation': 'Mount specific directories instead of root filesystem'
                    })
                    
            return {
                'container_id': container_id,
                'image': info.get('Config', {}).get('Image', ''),
                'status': container.status,
                'security_issues': security_issues,
                'security_score': self._calculate_runtime_security_score(security_issues)
            }
            
        except docker.errors.NotFound:
            raise ValueError(f"Container not found: {container_id}")
            
    async def _pull_image(self, image_name: str):
        """Pull Docker image if not available locally."""
        if not self.docker_client:
            return None
            
        try:
            # Try to get image locally first
            return self.docker_client.images.get(image_name)
        except docker.errors.ImageNotFound:
            try:
                print(f"Pulling image: {image_name}")
                return self.docker_client.images.pull(image_name)
            except Exception as e:
                print(f"Failed to pull image {image_name}: {e}")
                return None
                
    def _extract_image_info(self, image) -> Dict[str, Any]:
        """Extract basic image information."""
        attrs = image.attrs
        return {
            'id': image.id,
            'tags': image.tags,
            'created': attrs.get('Created', ''),
            'size': attrs.get('Size', 0),
            'architecture': attrs.get('Architecture', ''),
            'os': attrs.get('Os', ''),
            'config': attrs.get('Config', {})
        }
        
    async def _scan_vulnerabilities(self, image, image_name: str) -> List[ContainerVulnerability]:
        """Scan image for known vulnerabilities."""
        vulnerabilities: List[ContainerVulnerability] = []

        # Use docker create/start/exec/remove flow so we control lifecycle and cleanup.
        import subprocess as _subp

        tmp_cid = None
        try:
            # Create a short-lived container but do not start a long-running process; we'll start it detached
            tmp_name = f"infraware_tmp_{uuid.uuid4().hex[:8]}"
            print(f"Creating temporary container {tmp_name} from image {image_name}")
            cid_proc = _subp.run(["docker", "create", "--name", tmp_name, image_name, "sh", "-c", "sleep 3600"], capture_output=True, text=True, timeout=10)
            if cid_proc.returncode != 0 or not cid_proc.stdout:
                print(f"Warning: docker create failed or returned no id: {cid_proc.stderr}")
                # As a last resort, try running commands directly with docker run --rm (may be slower)
                dpkg_proc = _subp.run(["docker", "run", "--rm", image_name, "sh", "-c", "dpkg -l || true"], capture_output=True, text=True, timeout=12)
                if dpkg_proc.returncode == 0 and dpkg_proc.stdout:
                    print("Found dpkg output via docker run; parsing packages...")
                    packages = self._parse_dpkg_output(dpkg_proc.stdout)
                    vulnerabilities.extend(self._check_package_vulnerabilities(packages))
                else:
                    apk_proc = _subp.run(["docker", "run", "--rm", image_name, "sh", "-c", "apk list --installed || true"], capture_output=True, text=True, timeout=8)
                    if apk_proc.returncode == 0 and apk_proc.stdout:
                        print("Found apk output via docker run; parsing packages...")
                        packages = self._parse_apk_output(apk_proc.stdout)
                        vulnerabilities.extend(self._check_package_vulnerabilities(packages))
                return vulnerabilities

            # Get created container id
            tmp_cid = cid_proc.stdout.strip()
            # Start the container (detached)
            _subp.run(["docker", "start", tmp_cid], capture_output=True, text=True, timeout=6)

            # Run dpkg inside the container with a timeout
            try:
                print("Running dpkg -l inside temporary container...")
                dpkg_exec = _subp.run(["docker", "exec", tmp_cid, "dpkg", "-l"], capture_output=True, text=True, timeout=15)
                if dpkg_exec.returncode == 0 and dpkg_exec.stdout:
                    packages = self._parse_dpkg_output(dpkg_exec.stdout)
                    print(f"Parsed {len(packages)} dpkg packages")
                    vulnerabilities.extend(self._check_package_vulnerabilities(packages))
                    print(f"Detected {len(vulnerabilities)} vulnerabilities after dpkg check")
            except _subp.TimeoutExpired:
                print("Warning: dpkg exec timed out")

            # If no vulnerabilities found yet, try apk
            if not vulnerabilities:
                try:
                    print("Running apk list inside temporary container...")
                    apk_exec = _subp.run(["docker", "exec", tmp_cid, "apk", "list", "--installed"], capture_output=True, text=True, timeout=12)
                    if apk_exec.returncode == 0 and apk_exec.stdout:
                        packages = self._parse_apk_output(apk_exec.stdout)
                        print(f"Parsed {len(packages)} apk packages")
                        vulnerabilities.extend(self._check_package_vulnerabilities(packages))
                        print(f"Detected {len(vulnerabilities)} vulnerabilities after apk check")
                except _subp.TimeoutExpired:
                    print("Warning: apk exec timed out")

            # If still no vulnerabilities and no packages parsed, try rpm (CentOS/RHEL)
            if not vulnerabilities and (not packages or len(packages) == 0):
                try:
                    print("Running rpm -qa inside temporary container (if available)...")
                    rpm_exec = _subp.run(["docker", "exec", tmp_cid, "rpm", "-qa"], capture_output=True, text=True, timeout=12)
                    if rpm_exec.returncode == 0 and rpm_exec.stdout:
                        # rpm output is a list of package-version lines; convert to a simple package dict format
                        rpm_lines = [l.strip() for l in rpm_exec.stdout.splitlines() if l.strip()]
                        packages = []
                        for ln in rpm_lines:
                            # try to split name-version
                            if '-' in ln:
                                parts = ln.rsplit('-', 2)
                                if len(parts) >= 2:
                                    name = parts[0]
                                    ver = '-'.join(parts[1:])
                                else:
                                    name = ln
                                    ver = ''
                            else:
                                name = ln
                                ver = ''
                            packages.append({'name': name, 'version': ver, 'type': 'rpm'})
                        print(f"Parsed {len(packages)} rpm packages")
                        vulnerabilities.extend(self._check_package_vulnerabilities(packages))
                        print(f"Detected {len(vulnerabilities)} vulnerabilities after rpm check")
                except _subp.TimeoutExpired:
                    print("Warning: rpm exec timed out")

        except Exception as e:
            print(f"Warning: Could not extract package info: {e}")
        finally:
            # Ensure we remove the temporary container if it was created
            if tmp_cid:
                try:
                    _subp.run(["docker", "rm", "-f", tmp_cid], capture_output=True, text=True, timeout=6)
                except Exception:
                    pass

        return vulnerabilities
        
    async def _analyze_layers(self, image) -> List[Dict[str, Any]]:
        """Analyze image layers for security issues."""
        layers = []
        
        history = image.history()
        for i, layer in enumerate(history):
            layer_info = {
                'id': layer.get('Id', f'layer-{i}'),
                'created': layer.get('Created', ''),
                'created_by': layer.get('CreatedBy', ''),
                'size': layer.get('Size', 0),
                'security_issues': []
            }
            
            # Check for security issues in layer commands
            created_by = layer.get('CreatedBy', '')
            if 'wget' in created_by and 'http://' in created_by:
                layer_info['security_issues'].append({
                    'type': 'INSECURE_DOWNLOAD',
                    'severity': 'MEDIUM',
                    'description': 'Layer downloads files over insecure HTTP'
                })
                
            if 'chmod 777' in created_by:
                layer_info['security_issues'].append({
                    'type': 'OVERLY_PERMISSIVE',
                    'severity': 'HIGH',
                    'description': 'Layer sets overly permissive file permissions'
                })
                
            layers.append(layer_info)
            
        return layers
        
    async def _scan_container_secrets(self, image, image_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Scan container image for secrets."""
        secrets = []
        
        # Secret patterns for container scanning
        secret_patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'[A-Za-z0-9/+=]{40}',
            'api_key': r'[Aa][Pp][Ii]_?[Kk][Ee][Yy].*[\'"][0-9a-zA-Z]{32,45}[\'"]',
            'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'private_key': r'-----BEGIN.*PRIVATE KEY-----'
        }
        
        try:
            # Extract filesystem for scanning
            with tempfile.TemporaryDirectory() as temp_dir:
                container = None
                try:
                    # create a container from the image (do not start)
                    # Try to reuse any temporary container we created earlier (infraware_tmp_*).
                    # This avoids creating both an SDK container and a CLI container which caused duplicates.
                    archive_path = Path(temp_dir) / 'container.tar'
                    try:
                        import subprocess as _subp
                        # Look for existing infraware_tmp_ containers (created by _scan_vulnerabilities)
                        ps_proc = _subp.run(["docker", "ps", "-a", "--filter", "name=infraware_tmp_", "-q"], capture_output=True, text=True, timeout=4)
                        candidate = None
                        if ps_proc.returncode == 0 and ps_proc.stdout.strip():
                            # Use the first matching container id
                            candidate = ps_proc.stdout.strip().splitlines()[0]
                            print(f"Reusing existing temporary container {candidate} for export")

                        if candidate:
                            cid = candidate
                            with open(archive_path, 'wb') as f:
                                exp = _subp.run(["docker", "export", cid], stdout=f, timeout=20)
                        else:
                            # Create a single CLI container specifically for export
                            cid_proc = _subp.run(["docker", "create", image if isinstance(image, str) else getattr(image, 'id', image)], capture_output=True, text=True, timeout=8)
                            if cid_proc.returncode == 0 and cid_proc.stdout:
                                cid = cid_proc.stdout.strip()
                                print(f"Created temporary container {cid} for export")
                                with open(archive_path, 'wb') as f:
                                    exp = _subp.run(["docker", "export", cid], stdout=f, timeout=20)
                                # Remove the created container
                                _subp.run(["docker", "rm", "-f", cid], capture_output=True)
                            else:
                                # Fall back to SDK get_archive if CLI create/export fails
                                print("docker create/export failed; falling back to SDK get_archive")
                                archive_stream, stats = container.get_archive('/')
                                with open(archive_path, 'wb') as f:
                                    for chunk in archive_stream:
                                        f.write(chunk)
                    except Exception as e:
                        print(f"Warning: export via docker CLI failed: {e}; falling back to SDK get_archive")
                        archive_stream, stats = container.get_archive('/')
                        with open(archive_path, 'wb') as f:
                            for chunk in archive_stream:
                                f.write(chunk)

                    # Extract and scan files safely (avoid absolute paths and path traversal)
                    with tarfile.open(archive_path) as tar:
                        def _is_within_directory(directory, target):
                            abs_directory = Path(directory).resolve()
                            abs_target = Path(target).resolve()
                            try:
                                return abs_target.is_relative_to(abs_directory)
                            except Exception:
                                # For Python <3.9 fallback
                                return str(abs_target).startswith(str(abs_directory))

                        for member in tar.getmembers():
                            # sanitize member name: remove leading '/' and drive letters
                            member_name = member.name.lstrip('/\\')
                            # Prevent any path traversal
                            target_path = Path(temp_dir) / member_name
                            # Resolve the final path and ensure it's inside temp_dir
                            try:
                                resolved_target = target_path.resolve()
                            except Exception:
                                continue
                            if not _is_within_directory(temp_dir, resolved_target):
                                continue
                            # Extract the member to the safe path
                            try:
                                tar.extract(member, path=temp_dir)
                            except Exception:
                                # If extraction of a specific member fails, ignore and continue
                                continue

                    # Scan extracted files for secrets
                    for file_path in Path(temp_dir).rglob('*'):
                        if file_path.is_file() and file_path.stat().st_size < 10 * 1024 * 1024:  # Skip large files
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()

                                for secret_type, pattern in secret_patterns.items():
                                    for match in re.finditer(pattern, content):
                                        secrets.append({
                                            'type': secret_type,
                                            'file_path': str(file_path.relative_to(temp_dir)),
                                            'line': content[:match.start()].count('\n') + 1,
                                            'severity': 'HIGH' if 'key' in secret_type else 'MEDIUM',
                                            'hash': hashlib.sha256(match.group().encode()).hexdigest()[:16]
                                        })
                            except Exception:
                                continue

                finally:
                    if container:
                        try:
                            container.remove(force=True)
                        except Exception:
                            pass

        except Exception as e:
            print(f"Warning: Could not scan for secrets: {e}")
            
        return secrets
        
    async def _analyze_packages(self, image) -> List[Dict[str, Any]]:
        """Analyze installed packages."""
        packages = []
        
        # This would extract and analyze all installed packages
        # For demonstration, we'll return sample data
        
        return packages
        
    async def _get_os_info(self, image, image_name: Optional[str] = None) -> Dict[str, Any]:
        """Get operating system information."""
        os_info = {
            'name': 'Unknown',
            'version': 'Unknown',
            'architecture': 'Unknown'
        }
        
        try:
            # Try to get OS info from image config
            config = getattr(image, 'attrs', {})
            os_info['architecture'] = config.get('Architecture', 'Unknown')

            # Run a short command to get os-release content
            if self.docker_client:
                container = None
                try:
                    container = self.docker_client.containers.run(getattr(image, 'id', image), command='cat /etc/os-release', remove=True)
                    # containers.run returns bytes output when not detached
                    if isinstance(container, (bytes, bytearray)):
                        logs = container.decode(errors='ignore')
                    else:
                        logs = str(container)

                    for line in logs.split('\n'):
                        if line.startswith('NAME='):
                            os_info['name'] = line.split('=')[1].strip('"')
                        elif line.startswith('VERSION='):
                            os_info['version'] = line.split('=')[1].strip('"')
                except Exception:
                    pass

        except Exception:
            pass
            
        return os_info
        
    def _calculate_security_score(self, vulnerabilities: List, secrets: List) -> float:
        """Calculate overall security score (0-100)."""
        score = 100.0
        
        # Deduct points for vulnerabilities
        for vuln in vulnerabilities:
            # Accept either dataclass or dict-like vulnerability
            if isinstance(vuln, ContainerVulnerability):
                severity = getattr(vuln, 'severity', 'MEDIUM')
            elif isinstance(vuln, dict):
                severity = vuln.get('severity', 'MEDIUM')
            else:
                # Fallback: try attribute access
                severity = getattr(vuln, 'severity', getattr(vuln, 'severity', 'MEDIUM'))
                
            if severity == 'CRITICAL':
                score -= 20
            elif severity == 'HIGH':
                score -= 10
            elif severity == 'MEDIUM':
                score -= 5
            elif severity == 'LOW':
                score -= 2
                
        # Deduct points for secrets
        for secret in secrets:
            severity = secret.get('severity', 'MEDIUM')
            if severity == 'CRITICAL':
                score -= 15
            elif severity == 'HIGH':
                score -= 10
            elif severity == 'MEDIUM':
                score -= 5
                
        return max(0.0, score)
        
    def _calculate_runtime_security_score(self, security_issues: List) -> float:
        """Calculate runtime security score."""
        score = 100.0
        
        for issue in security_issues:
            severity = issue.get('severity', 'MEDIUM')
            if severity == 'CRITICAL':
                score -= 25
            elif severity == 'HIGH':
                score -= 15
            elif severity == 'MEDIUM':
                score -= 8
            elif severity == 'LOW':
                score -= 3
                
        return max(0.0, score)
        
    def _generate_recommendations(self, vulnerabilities: List, secrets: List, packages: List) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        if vulnerabilities:
            recommendations.append("Update vulnerable packages to latest versions")
            recommendations.append("Consider using a minimal base image to reduce attack surface")
            
        if secrets:
            recommendations.append("Remove hardcoded secrets and use environment variables or secret management")
            recommendations.append("Scan images before deployment to catch secrets early")
            
        recommendations.extend([
            "Run containers with non-root user",
            "Use read-only filesystems where possible",
            "Implement proper network segmentation",
            "Regular security scanning in CI/CD pipeline"
        ])
        
        return recommendations
        
    def _load_vulnerability_patterns(self) -> Dict[str, Any]:
        """Load vulnerability detection patterns."""
        return {
            'openssl': {
                'vulnerable_versions': ['1.0.1', '1.0.2'],
                'cves': ['CVE-2014-0160', 'CVE-2014-3566']
            },
            'nginx': {
                'vulnerable_versions': ['1.10.0', '1.10.1'],
                'cves': ['CVE-2016-4450']
            }
        }
        
    def _load_dockerfile_rules(self) -> List[Dict[str, Any]]:
        """Load Dockerfile security rules."""
        return [
            {
                'id': 'DF001',
                'pattern': r'^USER\s+root\s*$',
                'severity': 'HIGH',
                'description': 'Container runs as root user',
                'remediation': 'Create and use a non-root user'
            },
            {
                'id': 'DF002',
                'pattern': r'COPY\s+.*\s+/',
                'severity': 'MEDIUM',
                'description': 'Files copied to root directory',
                'remediation': 'Copy files to specific directories'
            },
            {
                'id': 'DF003',
                'pattern': r'wget.*http://',
                'severity': 'MEDIUM',
                'description': 'Downloading over insecure HTTP',
                'remediation': 'Use HTTPS instead of HTTP'
            },
            {
                'id': 'DF004',
                'pattern': r'chmod\s+777',
                'severity': 'HIGH',
                'description': 'Setting overly permissive file permissions',
                'remediation': 'Use more restrictive permissions'
            },
            {
                'id': 'DF005',
                'pattern': r'ADD\s+.*\.tar',
                'severity': 'LOW',
                'description': 'Using ADD for extracting archives',
                'remediation': 'Use COPY and RUN to extract archives explicitly'
            }
        ]
        
    def _matches_rule(self, line: str, rule: Dict[str, Any]) -> bool:
        """Check if line matches a Dockerfile rule."""
        return bool(re.search(rule['pattern'], line, re.IGNORECASE))
        
    def _parse_dpkg_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse dpkg -l output."""
        packages = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if line.startswith('ii'):  # Installed packages
                parts = line.split()
                if len(parts) >= 3:
                    packages.append({
                        'name': parts[1],
                        'version': parts[2],
                        'type': 'deb'
                    })
                    
        return packages
        
    def _parse_apk_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse apk list output."""
        packages = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if '-' in line:
                parts = line.split()
                if len(parts) >= 1:
                    package_info = parts[0]
                    if '-' in package_info:
                        name_version = package_info.rsplit('-', 2)
                        if len(name_version) >= 2:
                            packages.append({
                                'name': name_version[0],
                                'version': '-'.join(name_version[1:]),
                                'type': 'apk'
                            })
                            
        return packages
        
    def _check_package_vulnerabilities(self, packages: List[Dict[str, Any]]) -> List[ContainerVulnerability]:
        """Check packages against vulnerability database."""
        vulnerabilities = []
        
        # This would integrate with the CVE database
        # For now, simulate some known vulnerabilities
        
        vulnerable_packages = {
            'openssl': {
                'versions': ['1.0.1f', '1.0.2'],
                'cve': 'CVE-2014-0160',
                'severity': 'CRITICAL',
                'description': 'OpenSSL Heartbleed vulnerability'
            },
            'bash': {
                'versions': ['4.3'],
                'cve': 'CVE-2014-6271',
                'severity': 'CRITICAL',
                'description': 'Bash Shellshock vulnerability'
            }
        }
        
        for package in packages:
            package_name = package['name']
            package_version = package['version']
            
            if package_name in vulnerable_packages:
                vuln_info = vulnerable_packages[package_name]
                if any(v in package_version for v in vuln_info['versions']):
                    vuln = ContainerVulnerability(
                        id=f"{package_name}-{vuln_info['cve']}",
                        cve_id=vuln_info['cve'],
                        package_name=package_name,
                        installed_version=package_version,
                        fixed_version='Latest',
                        severity=vuln_info['severity'],
                        cvss_score=9.8 if vuln_info['severity'] == 'CRITICAL' else 7.5,
                        description=vuln_info['description'],
                        layer_id='unknown',
                        file_path='/usr/bin/' + package_name
                    )
                    vulnerabilities.append(vuln)
                    
        return vulnerabilities