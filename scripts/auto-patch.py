#!/usr/bin/env python3
import json
import re
import os
import sys
import subprocess

def update_dockerfile(vuln_data):
    """Update Dockerfile with fixed package versions"""
    dockerfile_path = 'Dockerfile'
    updates = {}
    
    # Collect all fixable vulnerabilities
    for result in vuln_data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            if vuln.get('FixedVersion'):
                pkg = vuln['PkgName']
                updates[pkg] = {
                    'current': vuln['InstalledVersion'],
                    'fixed': vuln['FixedVersion'],
                    'severity': vuln['Severity'],
                    'vuln_id': vuln['VulnerabilityID']
                }
    
    if not updates:
        print("No fixable vulnerabilities found")
        return False
    
    # Read Dockerfile
    with open(dockerfile_path, 'r') as f:
        content = f.read()
    
    # Apply updates
    updated = False
    for pkg, data in updates.items():
        # Update APK packages
        if re.search(fr'\b{pkg}\b[\s=~><]*[\d\w\.-]*', content):
            pattern = fr'(\b{pkg}\b)[\s=~><]*([\d\w\.-]*)'
            replacement = f'\\1={data["fixed"]}  # Fixed from {data["current"]} (CVE: {data["vuln_id"]})'
            content, count = re.subn(pattern, replacement, content)
            if count > 0:
                print(f"✅ Updated {pkg}: {data['current']} → {data['fixed']}")
                updated = True
        
        # Update PIP packages
        elif re.search(fr'\b{pkg}==[\d\.]+', content):
            pattern = fr'({pkg}==)([\d\.]+)'
            content, count = re.subn(pattern, f'\\1{data["fixed"]}  # Fixed from \\2 (CVE: {data["vuln_id"]})', content)
            if count > 0:
                print(f"✅ Updated {pkg}: {data['current']} → {data['fixed']}")
                updated = True
    
    # Write updated Dockerfile
    if updated:
        with open(dockerfile_path, 'w') as f:
            f.write(content)
        return True
    return False

def main():
    if len(sys.argv) < 2:
        print("Usage: auto-patch.py <trivy-results.json>")
        return 1
    
    try:
        with open(sys.argv[1]) as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading scan results: {e}")
        return 1
    
    if update_dockerfile(data):
        print("\n🎉 Dockerfile updated successfully")
        return 0
    print("\n⚠️ No updates applied to Dockerfile")
    return 1

if __name__ == "__main__":
    sys.exit(main())
