#!/usr/bin/env python3
# scripts/base-image-selector.py

import json
import requests
import subprocess
import sys
from datetime import datetime, timedelta

class BaseImageSelector:
    def __init__(self):
        self.registries = {
            'docker.io': 'https://hub.docker.com/v2',
            'gcr.io': 'https://gcr.io/v2',
            'quay.io': 'https://quay.io/api/v1'
        }
        
    def get_image_vulnerabilities(self, image):
        """Scan base image for vulnerabilities"""
        cmd = f"trivy image --format json --quiet {image}"
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                return json.loads(result.stdout)
        except Exception as e:
            print(f"Error scanning {image}: {e}")
        return None
        
    def get_image_age(self, image):
        """Get image creation date"""
        cmd = f"docker inspect {image} --format='{{{{.Created}}}}'"
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception as e:
            print(f"Error getting image age for {image}: {e}")
        return None
        
    def score_image(self, image, scan_results):
        """Score image based on vulnerabilities and age"""
        if not scan_results or not scan_results.get('Results'):
            return 0
            
        score = 100
        
        for result in scan_results['Results']:
            if 'Vulnerabilities' in result:
                for vuln in result['Vulnerabilities']:
                    severity = vuln.get('Severity', 'UNKNOWN')
                    if severity == 'CRITICAL':
                        score -= 20
                    elif severity == 'HIGH':
                        score -= 10
                    elif severity == 'MEDIUM':
                        score -= 5
                    elif severity == 'LOW':
                        score -= 1
                        
        return max(0, score)
        
    def select_best_base_image(self, current_image):
        """Select the best base image alternative"""
        
        # Extract base image info
        base_name = current_image.split(':')[0]
        current_tag = current_image.split(':')[1] if ':' in current_image else 'latest'
        
        # Common secure alternatives
        alternatives = [
            f"{base_name}:{current_tag}",
            f"{base_name}:alpine",
            f"{base_name}:slim",
            f"distroless/{base_name}",
            f"chainguard/{base_name}",
            f"cgr.dev/chainguard/{base_name}"
        ]
        
        best_image = current_image
        best_score = 0
        
        for alt_image in alternatives:
            try:
                # Pull image
                subprocess.run(f"docker pull {alt_image}", shell=True, 
                             capture_output=True, check=True)
                
                # Scan for vulnerabilities
                scan_results = self.get_image_vulnerabilities(alt_image)
                score = self.score_image(alt_image, scan_results)
                
                if score > best_score:
                    best_score = score
                    best_image = alt_image
                    
            except subprocess.CalledProcessError:
                continue
                
        return best_image

if __name__ == "__main__":
    selector = BaseImageSelector()
    
    # Read current Dockerfile
    with open('Dockerfile', 'r') as f:
        dockerfile_content = f.read()
        
    # Extract FROM instruction
    lines = dockerfile_content.split('\n')
    current_base = None
    
    for line in lines:
        if line.strip().startswith('FROM'):
            current_base = line.split()[1]
            break
            
    if current_base:
        recommended_base = selector.select_best_base_image(current_base)
        print(f"::set-output name=base-image::{recommended_base}")
    else:
        print("::error::No FROM instruction found in Dockerfile")
        sys.exit(1)
