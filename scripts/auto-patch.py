#!/usr/bin/env python3
import json
import re
import sys
import os

def update_dockerfile(vuln_data, service_name):
    dockerfile_path = 'Dockerfile'
    updates = {}
    
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
        print(f"No fixable vulnerabilities found in {service_name}")
        return False
    
    with open(dockerfile_path, 'r') as f:
        content = f.read()
    
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
    
    if updated:
        with open(dockerfile_path, 'w') as f:
            f.write(content)
        return True
    return False

def main():
    if len(sys.argv) < 2:
        print("Usage: auto-patch.py <trivy-results.json>")
        return 1
    
    service_name = os.path.basename(os.getcwd())
    
    try:
        with open(sys.argv[1]) as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading scan results: {e}")
        return 1
    
    if update_dockerfile(data, service_name):
        print(f"\n🎉 Dockerfile updated successfully for {service_name}")
        return 0
    
    print(f"\n⚠️ No updates applied to Dockerfile in {service_name}")
    return 1

if __name__ == "__main__":
    sys.exit(main())
