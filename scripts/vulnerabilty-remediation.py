#!/usr/bin/env python3
# scripts/vulnerability-remediation.py

import json
import re
import argparse
import subprocess
from pathlib import Path
from packaging import version

class VulnerabilityRemediator:
    def __init__(self):
        self.remediation_strategies = {
            'base_image_update': self.update_base_image,
            'package_update': self.update_packages,
            'remove_unnecessary': self.remove_unnecessary_packages,
            'multi_stage_optimization': self.optimize_multi_stage
        }
        
    def parse_trivy_results(self, trivy_file):
        """Parse Trivy SARIF results"""
        with open(trivy_file, 'r') as f:
            sarif_data = json.load(f)
            
        vulnerabilities = []
        
        for run in sarif_data.get('runs', []):
            for result in run.get('results', []):
                vuln = {
                    'rule_id': result.get('ruleId'),
                    'level': result.get('level'),
                    'message': result.get('message', {}).get('text'),
                    'locations': result.get('locations', [])
                }
                vulnerabilities.append(vuln)
                
        return vulnerabilities
        
    def parse_grype_results(self, grype_file):
        """Parse Grype JSON results"""
        with open(grype_file, 'r') as f:
            grype_data = json.load(f)
            
        vulnerabilities = []
        
        for match in grype_data.get('matches', []):
            vuln = {
                'id': match.get('vulnerability', {}).get('id'),
                'severity': match.get('vulnerability', {}).get('severity'),
                'package': match.get('artifact', {}).get('name'),
                'version': match.get('artifact', {}).get('version'),
                'fixed_version': match.get('vulnerability', {}).get('fix', {}).get('versions', [])
            }
            vulnerabilities.append(vuln)
            
        return vulnerabilities
        
    def update_base_image(self, dockerfile_path, vulnerabilities):
        """Update base image to more secure version"""
        with open(dockerfile_path, 'r') as f:
            content = f.read()
            
        lines = content.split('\n')
        updated_lines = []
        
        for line in lines:
            if line.strip().startswith('FROM'):
                # Extract current base image
                parts = line.split()
                current_image = parts[1]
                
                # Get recommended secure base image
                secure_base = self.get_secure_base_image(current_image)
                
                if secure_base != current_image:
                    line = f"FROM {secure_base}"
                    print(f"Updated base image: {current_image} -> {secure_base}")
                    
            updated_lines.append(line)
            
        return '\n'.join(updated_lines)
        
    def get_secure_base_image(self, current_image):
        """Get secure alternative for base image"""
        
        # Mapping of images to secure alternatives
        secure_alternatives = {
            'ubuntu:latest': 'ubuntu:22.04',
            'ubuntu:20.04': 'ubuntu:22.04',
            'debian:latest': 'debian:bullseye-slim',
            'alpine:latest': 'alpine:3.18',
            'node:latest': 'node:18-alpine',
            'python:latest': 'python:3.11-slim',
            'nginx:latest': 'nginx:alpine',
            'redis:latest': 'redis:7-alpine'
        }
        
        # Check for direct mapping
        if current_image in secure_alternatives:
            return secure_alternatives[current_image]
            
        # Try to find slim/alpine variants
        base_name = current_image.split(':')[0]
        
        # Prefer alpine variants
        alpine_variant = f"{base_name}:alpine"
        if self.image_exists(alpine_variant):
            return alpine_variant
            
        # Prefer slim variants
        slim_variant = f"{base_name}:slim"
        if self.image_exists(slim_variant):
            return slim_variant
            
        # Try distroless
        distroless_variant = f"distroless/{base_name}"
        if self.image_exists(distroless_variant):
            return distroless_variant
            
        return current_image
        
    def image_exists(self, image):
        """Check if image exists in registry"""
        try:
            result = subprocess.run(
                f"docker manifest inspect {image}",
                shell=True, capture_output=True, text=True
            )
            return result.returncode == 0
        except:
            return False
            
    def update_packages(self, dockerfile_path, vulnerabilities):
        """Update vulnerable packages"""
        with open(dockerfile_path, 'r') as f:
            content = f.read()
            
        lines = content.split('\n')
        updated_lines = []
        
        # Create package update mapping
        package_updates = {}
        for vuln in vulnerabilities:
            if vuln.get('package') and vuln.get('fixed_version'):
                package_updates[vuln['package']] = vuln['fixed_version'][0]
                
        for line in lines:
            # Update apt-get install commands
            if 'apt-get install' in line or 'apt install' in line:
                line = self.update_apt_packages(line, package_updates)
                
            # Update yum/dnf install commands
            elif 'yum install' in line or 'dnf install' in line:
                line = self.update_yum_packages(line, package_updates)
                
            # Update apk add commands
            elif 'apk add' in line:
                line = self.update_apk_packages(line, package_updates)
                
            updated_lines.append(line)
            
        return '\n'.join(updated_lines)
        
    def update_apt_packages(self, line, package_updates):
        """Update apt package versions"""
        for package, fixed_version in package_updates.items():
            # Look for package in line
            pattern = rf'\b{package}\b'
            if re.search(pattern, line):
                # Replace with versioned package
                line = re.sub(
                    rf'\b{package}\b',
                    f'{package}={fixed_version}',
                    line
                )
                print(f"Updated package: {package} -> {package}={fixed_version}")
                
        return line
        
    def update_yum_packages(self, line, package_updates):
        """Update yum/dnf package versions"""
        for package, fixed_version in package_updates.items():
            pattern = rf'\b{package}\b'
            if re.search(pattern, line):
                line = re.sub(
                    rf'\b{package}\b',
                    f'{package}-{fixed_version}',
                    line
                )
                print(f"Updated package: {package} -> {package}-{fixed_version}")
                
        return line
        
    def update_apk_packages(self, line, package_updates):
        """Update apk package versions"""
        for package, fixed_version in package_updates.items():
            pattern = rf'\b{package}\b'
            if re.search(pattern, line):
                line = re.sub(
                    rf'\b{package}\b',
                    f'{package}={fixed_version}',
                    line
                )
                print(f"Updated package: {package} -> {package}={fixed_version}")
                
        return line
        
    def remove_unnecessary_packages(self, dockerfile_path, vulnerabilities):
        """Remove unnecessary packages that have vulnerabilities"""
        with open(dockerfile_path, 'r') as f:
            content = f.read()
            
        # List of commonly unnecessary packages
        unnecessary_packages = [
            'curl', 'wget', 'git', 'vim', 'nano', 'sudo', 'ssh',
            'telnet', 'ftp', 'netcat', 'nc', 'nmap'
        ]
        
        vulnerable_packages = {v.get('package') for v in vulnerabilities}
        packages_to_remove = set(unnecessary_packages) & vulnerable_packages
        
        lines = content.split('\n')
        updated_lines = []
        
        for line in lines:
            modified_line = line
            
            for package in packages_to_remove:
                # Remove package from install commands
                modified_line = re.sub(rf'\s+{package}\b', '', modified_line)
                modified_line = re.sub(rf'\b{package}\s+', '', modified_line)
                
            # Clean up empty install commands
            if re.match(r'RUN\s+(apt-get|yum|dnf|apk)\s+install\s*$', modified_line):
                continue
                
            updated_lines.append(modified_line)
            
        if packages_to_remove:
            print(f"Removed unnecessary packages: {packages_to_remove}")
            
        return '\n'.join(updated_lines)
        
    def optimize_multi_stage(self, dockerfile_path, vulnerabilities):
        """Optimize multi-stage build to reduce attack surface"""
        with open(dockerfile_path, 'r') as f:
            content = f.read()
            
        # Add multi-stage optimization if not present
        if 'FROM' not in content or content.count('FROM') == 1:
            return self.add_multi_stage_build(content)
            
        return content
        
    def add_multi_stage_build(self, content):
        """Add multi-stage build pattern"""
        lines = content.split('\n')
        
        # Find the FROM instruction
        from_index = -1
        for i, line in enumerate(lines):
            if line.strip().startswith('FROM'):
                from_index = i
                break
                
        if from_index == -1:
            return content
            
        # Create multi-stage build
        base_image = lines[from_index].split()[1]
        
        multi_stage_prefix = f"""# Build stage
FROM {base_image} AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \\
    build-essential \\
    && rm -rf /var/lib/apt/lists/*

"""
        
        # Runtime stage
        runtime_stage = f"""
# Runtime stage
FROM {base_image} AS runtime

# Copy only necessary files from builder
COPY --from=builder /app /app

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser

"""
        
        # Insert multi-stage build
        lines[from_index] = multi_stage_prefix + '\n'.join(lines[from_index+1:]) + runtime_stage
        
        return '\n'.join(lines[:from_index+1])
        
    def remediate_dockerfile(self, dockerfile_path, trivy_results, grype_results):
        """Main remediation function"""
        
        # Parse vulnerability results
        trivy_vulns = self.parse_trivy_results(trivy_results) if trivy_results else []
        grype_vulns = self.parse_grype_results(grype_results) if grype_results else []
        
        all_vulnerabilities = trivy_vulns + grype_vulns
        
        # Start with original dockerfile
        current_content = Path(dockerfile_path).read_text()
        
        # Apply remediation strategies
        for strategy_name, strategy_func in self.remediation_strategies.items():
            print(f"Applying {strategy_name}...")
            current_content = strategy_func(dockerfile_path, all_vulnerabilities)
            
            # Write intermediate result
            with open(dockerfile_path, 'w') as f:
                f.write(current_content)
                
        print("Remediation complete!")
        
        # Generate remediation report
        self.generate_remediation_report(all_vulnerabilities)
        
    def generate_remediation_report(self, vulnerabilities):
        """Generate remediation report"""
        
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', vuln.get('level', 'UNKNOWN'))
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        report = f"""
# Vulnerability Remediation Report

## Summary
- Total vulnerabilities found: {len(vulnerabilities)}
- Critical: {severity_counts.get('CRITICAL', 0)}
- High: {severity_counts.get('HIGH', 0)}
- Medium: {severity_counts.get('MEDIUM', 0)}
- Low: {severity_counts.get('LOW', 0)}

## Remediation Actions Applied
1. Base image security updates
2. Package version updates
3. Removal of unnecessary packages
4. Multi-stage build optimization

## Recommendations
- Run security scans regularly
- Keep base images updated
- Use minimal base images (alpine, distroless)
- Implement multi-stage builds
- Follow principle of least privilege
"""
        
        with open('remediation-report.md', 'w') as f:
            f.write(report)
            
        # Set environment variables for GitHub Actions
        print(f"::set-env name=CRITICAL_COUNT::{severity_counts.get('CRITICAL', 0)}")
        print(f"::set-env name=HIGH_COUNT::{severity_counts.get('HIGH', 0)}")
        print(f"::set-env name=MEDIUM_COUNT::{severity_counts.get('MEDIUM', 0)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Remediate container vulnerabilities')
    parser.add_argument('--trivy-results', help='Path to Trivy SARIF results')
    parser.add_argument('--grype-results', help='Path to Grype JSON results')
    parser.add_argument('--dockerfile', required=True, help='Path to Dockerfile')
    parser.add_argument('--output-dockerfile', help='Output Dockerfile path')
    
    args = parser.parse_args()
    
    remediator = VulnerabilityRemediator()
    remediator.remediate_dockerfile(
        args.dockerfile,
        args.trivy_results,
        args.grype_results
    )
    
    if args.output_dockerfile:
        import shutil
        shutil.copy(args.dockerfile, args.output_dockerfile)
