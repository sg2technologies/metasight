import sys
import os
from pprint import pprint

# Add the project root to path
sys.path.append(os.getcwd())

from app.services.storage_scanner import check_s3_bucket

# Your provided configuration
config = {
    "bucket_name": "my-bucket",
    "region_name": "us-east-1",
    "aws_access_key_id": "",     # FILL THIS IN
    "aws_secret_access_key": ""  # FILL THIS IN
}

print(f"--- Testing S3 Security Scanner for bucket: {config['bucket_name']} ---")

try:
    result = check_s3_bucket(config)
    
    print(f"\nReachable: {result.reachable}")
    if result.error:
        print(f"Error: {result.error}")
    
    print(f"\nSecurity Grade: {result.grade} ({result.score}/100)")
    print("\nDetailed Checks:")
    for check in result.checks:
        status_icon = "✅" if check.status == "pass" else "❌" if check.status == "fail" else "⚠️"
        print(f" {status_icon} {check.name}: {check.detail}")

except Exception as e:
    print(f"Script Error: {e}")
