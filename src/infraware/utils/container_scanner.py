"""
Simple synchronous Container Security Scanner integrated with the project's CVE DB.
"""
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any, Optional
from pathlib import Path
import tarfile
import tempfile
import json
import sqlite3
import re
import docker
import os

from .cve_database import CVEDatabase


@dataclass
class ContainerVulnerability:
    cve_id: str
    pkg_name: str
    installed_version: str
    fixed_version: Optional[str]
    severity: str
    title: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ContainerScanResult:
    image_name: str
    vulnerabilities: List[ContainerVulnerability] = field(default_factory=list)
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'image_name': self.image_name,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'summary': self.summary,
            'notes': self.notes
        }

    @property
    def summary(self) -> Dict[str, int]:
        severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for v in self.vulnerabilities:
            s = (v.severity or 'UNKNOWN').upper()
            severities.setdefault(s, 0)
            severities[s] += 1
        return severities


class ContainerSecurityScanner:
    def __init__(self):
        try:
            self.client = docker.from_env()
            self.client.ping()
        except Exception:
            self.client = None
        self.cve_db = CVEDatabase()

    def scan_image(self, image_name: str) -> ContainerScanResult:
        if not self.client:
            raise RuntimeError("Docker daemon not available")

        # Pull if necessary
        try:
            image = self.client.images.get(image_name)
        except docker.errors.ImageNotFound:
            image = self.client.images.pull(image_name)

        container = None
        packages = []
        notes = None
        try:
            # Create a sleeping container so we can exec into it reliably
            try:
                container = self.client.containers.create(image, command=['sh', '-c', 'sleep 3600'])
            except Exception as e:
                raise RuntimeError(f"Failed to create container from image {image_name}: {e}")

            try:
                container.start()
            except Exception:
                # starting may fail for some images; we'll still try other methods
                pass

            # If the SDK-created container doesn't actually stay running, fall back to docker CLI run -d
            try:
                container.reload()
            except Exception:
                pass
            use_cli_container = False
            if not getattr(container, 'status', None) == 'running':
                use_cli_container = True
                # remove SDK container if created
                try:
                    container.remove(force=True)
                except Exception:
                    pass
                container = None
                # start container via docker CLI to ensure detached sleep
                try:
                    import subprocess as _subp
                    cli = _subp.run(["docker", "run", "-d", "--entrypoint", "sh", image_name, "-c", "sleep 3600"], capture_output=True, text=True, timeout=20)
                    if cli.returncode == 0 and cli.stdout:
                        cli_cid = cli.stdout.strip()
                        notes = (notes or '') + 'Started detached CLI container for inspection; '
                    else:
                        cli_cid = None
                except Exception:
                    cli_cid = None
                try:
                    # dpkg
                    if not use_cli_container:
                        exec_res = container.exec_run('dpkg -l', stdout=True, stderr=True)
                        out = exec_res.output if hasattr(exec_res, 'output') else (exec_res[1] if isinstance(exec_res, tuple) else exec_res)
                        text = out.decode('utf-8', errors='ignore') if isinstance(out, (bytes, bytearray)) else str(out)
                    else:
                        # use docker exec via CLI
                        import subprocess as _subp
                        dpkg_run = _subp.run(["docker", "exec", cli_cid, "sh", "-c", "dpkg -l || true"], capture_output=True, text=True, timeout=30)
                        text = dpkg_run.stdout

                    if text:
                        parsed = self._parse_dpkg_output(text)
                        if parsed:
                            packages = parsed
                            notes = (notes or '') + 'Used in-container dpkg -l to enumerate packages'
                except Exception:
                    pass
                            notes = 'Used in-container dpkg -l to enumerate packages'
                except Exception:
                    pass

                # apk
                    if not packages:
                        try:
                            if not use_cli_container:
                                exec_res = container.exec_run('apk list --installed', stdout=True, stderr=True)
                                out = exec_res.output if hasattr(exec_res, 'output') else (exec_res[1] if isinstance(exec_res, tuple) else exec_res)
                                text = out.decode('utf-8', errors='ignore') if isinstance(out, (bytes, bytearray)) else str(out)
                            else:
                                import subprocess as _subp
                                apk_run = _subp.run(["docker", "exec", cli_cid, "sh", "-c", "apk list --installed || true"], capture_output=True, text=True, timeout=30)
                                text = apk_run.stdout

                            if text:
                                parsed = self._parse_apk_output(text)
                                if parsed:
                                    packages = parsed
                                    notes = (notes or '') + 'Used in-container apk list --installed to enumerate packages'
                        except Exception:
                            pass

                # rpm
                if not packages:
                    try:
                        exec_res = container.exec_run('rpm -qa', stdout=True, stderr=True)
                        out = exec_res.output if hasattr(exec_res, 'output') else (exec_res[1] if isinstance(exec_res, tuple) else exec_res)
                        if out:
                            text = out.decode('utf-8', errors='ignore') if isinstance(out, (bytes, bytearray)) else str(out)
                            rpm_lines = [l.strip() for l in text.splitlines() if l.strip()]
                            parsed = []
                            for ln in rpm_lines:
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
                                parsed.append({'name': name, 'version': ver})
                            if parsed:
                                packages = parsed
                                notes = 'Used in-container rpm -qa to enumerate packages'
                    except Exception:
                        pass

            except Exception:
                # any exec errors fall through to get_archive / docker-run fallbacks
                pass

            # If exec-based queries didn't find packages, try SDK get_archive export and parse package DB files
            if not packages:
                try:
                    bits, _ = container.get_archive('/')
                    with tempfile.NamedTemporaryFile(delete=False) as tmpf:
                        written = 0
                        for chunk in bits:
                            tmpf.write(chunk)
                            written += len(chunk)
                        tmp_path = tmpf.name
                    if written:
                        packages = self._parse_package_files_from_tar(tmp_path)
                        if packages:
                            notes = 'Used image filesystem export to find package DB files'
                except Exception:
                    # If get_archive fails, we'll try docker run fallbacks next
                    pass

                # CLI-based docker run fallbacks if still empty
                if not packages:
                    import subprocess as _subp
                    try:
                        dpkg_proc = _subp.run(["docker", "run", "--rm", image_name, "sh", "-c", "dpkg -l || true"], capture_output=True, text=True, timeout=30)
                        if dpkg_proc.returncode == 0 and dpkg_proc.stdout and 'no packages found' not in dpkg_proc.stdout.lower():
                            parsed = self._parse_dpkg_output(dpkg_proc.stdout)
                            if parsed:
                                packages = parsed
                                notes = "Used docker run dpkg -l fallback to enumerate packages"

                        if not packages:
                            apk_proc = _subp.run(["docker", "run", "--rm", image_name, "sh", "-c", "apk list --installed || true"], capture_output=True, text=True, timeout=20)
                            if apk_proc.returncode == 0 and apk_proc.stdout:
                                parsed = self._parse_apk_output(apk_proc.stdout)
                                if parsed:
                                    packages = parsed
                                    notes = "Used docker run apk list --installed fallback to enumerate packages"

                        if not packages:
                            rpm_proc = _subp.run(["docker", "run", "--rm", image_name, "sh", "-c", "rpm -qa || true"], capture_output=True, text=True, timeout=20)
                            if rpm_proc.returncode == 0 and rpm_proc.stdout:
                                rpm_lines = [l.strip() for l in rpm_proc.stdout.splitlines() if l.strip()]
                                parsed = []
                                for ln in rpm_lines:
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
                                    parsed.append({'name': name, 'version': ver})
                                if parsed:
                                    packages = parsed
                                    notes = "Used docker run rpm -qa fallback to enumerate packages"
                    except Exception as _e:
                        notes = f"No package DB files found and docker-run fallbacks failed: {_e}"
        finally:
            try:
                if container:
                    container.remove(force=True)
            except Exception:
                pass

        vulnerabilities = self._match_packages_to_cves(packages) if packages else []

        img_name = image.tags[0] if getattr(image, 'tags', None) else getattr(image, 'short_id', str(image))
        return ContainerScanResult(image_name=img_name, vulnerabilities=vulnerabilities, notes=notes)

    def scan_dockerfile(self, dockerfile_path: str) -> List[Dict[str, Any]]:
        issues = []
        try:
            p = Path(dockerfile_path)
                    if not packages:
                        try:
                            if not use_cli_container:
                                exec_res = container.exec_run('rpm -qa', stdout=True, stderr=True)
                                out = exec_res.output if hasattr(exec_res, 'output') else (exec_res[1] if isinstance(exec_res, tuple) else exec_res)
                                text = out.decode('utf-8', errors='ignore') if isinstance(out, (bytes, bytearray)) else str(out)
                            else:
                                import subprocess as _subp
                                rpm_run = _subp.run(["docker", "exec", cli_cid, "sh", "-c", "rpm -qa || true"], capture_output=True, text=True, timeout=30)
                                text = rpm_run.stdout

                            if text:
                                rpm_lines = [l.strip() for l in text.splitlines() if l.strip()]
                                parsed = []
                                for ln in rpm_lines:
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
                                    parsed.append({'name': name, 'version': ver})
                                if parsed:
                                    packages = parsed
                                    notes = (notes or '') + 'Used in-container rpm -qa to enumerate packages'
                        except Exception:
                            pass
            if not user or user == 'root' or user == '0':
                issues.append({'type': 'PRIVILEGE_ESCALATION', 'severity': 'HIGH', 'description': 'Running as root'})

            privileged = info.get('HostConfig', {}).get('Privileged', False)
            if privileged:
                issues.append({'type': 'PRIVILEGED', 'severity': 'CRITICAL', 'description': 'Container is privileged'})

            return {'container_id': container_id, 'issues': issues, 'security_score': 100 - len(issues) * 20}
        except docker.errors.NotFound:
            raise ValueError(f'Container not found: {container_id}')

    def _parse_package_files_from_tar(self, tar_path: str) -> List[Dict[str, str]]:
        packages: List[Dict[str, str]] = []
        try:
            with tarfile.open(tar_path) as tar:
                # dpkg status
                try:
                    member = tar.getmember('var/lib/dpkg/status')
                    f = tar.extractfile(member)
                    if f:
                        data = f.read().decode('utf-8', errors='ignore')
                        packages.extend(self._parse_dpkg_status(data))
                except KeyError:
                    pass

                # alpine apk database
                try:
                    member = tar.getmember('lib/apk/db/installed')
                    f = tar.extractfile(member)
                    if f:
                        data = f.read().decode('utf-8', errors='ignore')
                        packages.extend(self._parse_apk_installed(data))
                except KeyError:
                    pass
        finally:
            try:
                Path(tar_path).unlink()
            except Exception:
                pass

        return packages

    def _parse_dpkg_status(self, content: str) -> List[Dict[str, str]]:
        packages = []
        for block in content.split('\n\n'):
            if not block.strip():
                continue
            pkg_info = {}
            for line in block.split('\n'):
                if line.startswith('Package:'):
                    pkg_info['name'] = line.split(':', 1)[1].strip()
                elif line.startswith('Version:'):
                    pkg_info['version'] = line.split(':', 1)[1].strip()
            if 'name' in pkg_info and 'version' in pkg_info:
                packages.append({'name': pkg_info['name'], 'version': pkg_info['version']})
        return packages

    def _parse_apk_installed(self, content: str) -> List[Dict[str, str]]:
        packages = []
        # apk installed entries separated by blank lines; name after 'P:' and version after 'V:'
        for block in content.split('\n\n'):
            if not block.strip():
                continue
            pkg_info = {}
            for line in block.split('\n'):
                if line.startswith('P:'):
                    pkg_info['name'] = line.split(':', 1)[1].strip()
                elif line.startswith('V:'):
                    pkg_info['version'] = line.split(':', 1)[1].strip()
            if 'name' in pkg_info and 'version' in pkg_info:
                packages.append({'name': pkg_info['name'], 'version': pkg_info['version']})
        return packages

    def _match_packages_to_cves(self, packages: List[Dict[str, str]]) -> List[ContainerVulnerability]:
        findings: List[ContainerVulnerability] = []
        for pkg in packages:
            name = pkg.get('name')
            version = pkg.get('version')
            # Query the CVE DB for the package name
            try:
                cves = self.cve_db.search_cves(name, limit=20)
            except Exception:
                cves = []

            # Basic matching: check if package version text appears in CVE affected_products or description
            for entry in cves:
                affected = ' '.join(entry.affected_products or []) if getattr(entry, 'affected_products', None) else ''
                desc = getattr(entry, 'description', '') or ''
                # crude heuristics: version substring in description or affected products
                if version and (version in affected or version in desc):
                    findings.append(ContainerVulnerability(
                        cve_id=entry.cve_id,
                        pkg_name=name,
                        installed_version=version,
                        fixed_version=None,
                        severity=entry.severity or 'UNKNOWN',
                        title=(entry.description or '')[:200]
                    ))

            # Also check direct mapping table (vulnerability_mappings) for exact name matches
            try:
                with sqlite3.connect(self.cve_db.db_path) as conn:
                    cur = conn.execute('SELECT cve_ids FROM vulnerability_mappings WHERE value_pattern = ? OR value_pattern LIKE ?', (name, f'%{name}%'))
                    for row in cur.fetchall():
                        cve_ids = json.loads(row[0]) if row[0] else []
                        for cve_id in cve_ids:
                            cve_entry = self.cve_db.get_cve_by_id(cve_id)
                            if cve_entry:
                                findings.append(ContainerVulnerability(
                                    cve_id=cve_entry.cve_id,
                                    pkg_name=name,
                                    installed_version=version,
                                    fixed_version=None,
                                    severity=cve_entry.severity or 'UNKNOWN',
                                    title=(cve_entry.description or '')[:200]
                                ))
            except Exception:
                pass

        # Deduplicate by cve_id + pkg_name
        seen = set()
        unique = []
        for f in findings:
            key = (f.cve_id, f.pkg_name, f.installed_version)
            if key in seen:
                continue
            seen.add(key)
            unique.append(f)

        return unique