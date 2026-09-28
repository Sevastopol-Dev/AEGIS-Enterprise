#!/usr/bin/env python3
import os, json, boto3
from botocore.exceptions import ClientError

ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", "http://localhost:4566")
kw = {"endpoint_url": ENDPOINT, "region_name": "us-east-1", "aws_access_key_id": "test", "aws_secret_access_key": "test"}

ec2, s3 = boto3.client("ec2", **kw), boto3.client("s3", **kw)

def audit_security_groups():
    violations = []
    for sg in ec2.describe_security_groups().get("SecurityGroups", []):
        for p in sg.get("IpPermissions", []):
            if p.get("FromPort") == 22 and any(r.get("CidrIp") == "0.0.0.0/0" for r in p.get("IpRanges", [])):
                violations.append(sg["GroupId"])
    return violations

def audit_s3_buckets():
    non_compliant = []
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        try:
            s3.get_public_access_block(Bucket=name)
            s3.get_bucket_encryption(Bucket=name)
        except ClientError:
            non_compliant.append(name)
    return non_compliant

def run_audit():
    bad_sgs = audit_security_groups()
    bad_buckets = audit_s3_buckets()
    report = {"status": "FAIL" if (bad_sgs or bad_buckets) else "PASS", "open_ssh_sgs": bad_sgs, "unencrypted_buckets": bad_buckets}
    print(json.dumps(report, indent=2))
    return report

if __name__ == "__main__":
    run_audit()
