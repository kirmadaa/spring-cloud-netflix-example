#!/usr/bin/env python3
import json
import re
import os
import sys

def update_dockerfile(vulns):
    dockerfile_path = 'Dockerfile'
    with open(dockerfile_path, 'r') as f:
        content = f.read()

    # Update package versions
    for pkg, fixed_version in vulns.items():
        # Handle Alpine package formats
        content = re.sub(
            fr'(\b{re.escape(pkg)}\b)[~><=]?[\w\.-]*', 
            f'\\1={fixed_version}', 
            content
        )
    
    # Write updated Dockerfile
    with open(dockerfile_path, 'w') as f:
        f.write(content)

def main():
    report_path = sys.argv[1]
    with open(report_path) as f:
        data = json.load(f)
    
    fixable_vulns = {}
    for result in data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            if vuln.get('FixedVersion'):
                pkg = vuln['PkgName']
                fixed_version = vuln['FixedVersion']
                
                # Only update if newer than current
                if pkg not in fixable_vulns or fixed_version > fixable_vulns[pkg]:
                    fixable_vulns[pkg] = fixed_version
                    
    if fixable_vulns:
        print(f"Found fixable vulnerabilities: {', '.join(fixable_vulns.keys())}")
        update_dockerfile(fixable_vulns)
        return True
    return False

if __name__ == "__main__":
    if main():
        sys.exit(0)
    else:
        sys.exit(1)
