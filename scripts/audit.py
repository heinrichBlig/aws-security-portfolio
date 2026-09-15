#!/usr/bin/env python3
"""
audit.py — a small AWS security audit tool (CSPM-style checker).

Scans a live AWS account for the specific misconfigurations introduced by
terraform/vulnerable/main.tf and prints a findings report with severity
and a one-line remediation for each.

This mirrors, at a small scale, the pattern used by real Cloud Security
Posture Management (CSPM) tools like Prowler, ScoutSuite, or AWS Security
Hub — enumerate resources, check them against a rule, report findings.

Usage:
    pip install boto3 --break-system-packages
    export AWS_PROFILE=your-profile   # or set AWS_ACCESS_KEY_ID / SECRET
    python audit.py
"""

import boto3
from botocore.exceptions import ClientError

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[94m",
    "LOW": "\033[92m",
}
RESET = "\033[0m"

findings = []


def add_finding(severity, resource, issue, fix):
    findings.append(
        {"severity": severity, "resource": resource, "issue": issue, "fix": fix}
    )


def check_s3_buckets():
    s3 = boto3.client("s3")
    try:
        buckets = s3.list_buckets()["Buckets"]
    except ClientError as e:
        print(f"Could not list S3 buckets: {e}")
        return

    for bucket in buckets:
        name = bucket["Name"]

        # Public access block check
        try:
            pab = s3.get_public_access_block(Bucket=name)
            config = pab["PublicAccessBlockConfiguration"]
            if not all(config.values()):
                add_finding(
                    "CRITICAL",
                    f"S3 bucket: {name}",
                    "Public access block is not fully enabled",
                    "Enable all four block-public-access settings",
                )
        except ClientError:
            add_finding(
                "CRITICAL",
                f"S3 bucket: {name}",
                "No public access block configuration found",
                "Apply aws_s3_bucket_public_access_block with all settings true",
            )

        # Encryption check
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError:
            add_finding(
                "HIGH",
                f"S3 bucket: {name}",
                "No default server-side encryption configured",
                "Enable SSE-S3 or SSE-KMS default encryption",
            )

        # Versioning check
        versioning = s3.get_bucket_versioning(Bucket=name)
        if versioning.get("Status") != "Enabled":
            add_finding(
                "MEDIUM",
                f"S3 bucket: {name}",
                "Versioning is not enabled",
                "Enable versioning to protect against accidental deletion/overwrite",
            )


def check_iam_roles():
    iam = boto3.client("iam")
    roles = iam.list_roles()["Roles"]

    for role in roles:
        role_name = role["RoleName"]
        policies = iam.list_role_policies(RoleName=role_name)["PolicyNames"]

        for policy_name in policies:
            policy = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            statements = policy["PolicyDocument"].get("Statement", [])
            if not isinstance(statements, list):
                statements = [statements]

            for stmt in statements:
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]

                if "*" in actions and "*" in resources:
                    add_finding(
                        "CRITICAL",
                        f"IAM role: {role_name}",
                        f"Policy '{policy_name}' grants '*' action on '*' resource",
                        "Scope the policy to only the specific actions/resources needed",
                    )


def check_rds_instances():
    rds = boto3.client("rds")
    try:
        instances = rds.describe_db_instances()["DBInstances"]
    except ClientError as e:
        print(f"Could not describe RDS instances: {e}")
        return

    for db in instances:
        db_id = db["DBInstanceIdentifier"]

        if not db.get("StorageEncrypted", False):
            add_finding(
                "HIGH",
                f"RDS instance: {db_id}",
                "Storage is not encrypted at rest",
                "Recreate with storage_encrypted = true (cannot be changed in place)",
            )

        if db.get("PubliclyAccessible", False):
            add_finding(
                "CRITICAL",
                f"RDS instance: {db_id}",
                "Instance is publicly accessible from the internet",
                "Set publicly_accessible = false and access via VPC/bastion only",
            )


def check_cloudtrail():
    ct = boto3.client("cloudtrail")
    trails = ct.describe_trails()["trailList"]

    if not trails:
        add_finding(
            "HIGH",
            "Account-wide",
            "No CloudTrail trail configured",
            "Enable a multi-region CloudTrail trail with log file validation",
        )
        return

    if not any(t.get("IsMultiRegionTrail") for t in trails):
        add_finding(
            "MEDIUM",
            "Account-wide",
            "CloudTrail exists but is not multi-region",
            "Enable is_multi_region_trail on at least one trail",
        )


def check_security_groups():
    ec2 = boto3.client("ec2")
    sgs = ec2.describe_security_groups()["SecurityGroups"]

    risky_ports = {22: "SSH", 3389: "RDP"}

    for sg in sgs:
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0" and from_port in risky_ports:
                    add_finding(
                        "CRITICAL",
                        f"Security group: {sg['GroupName']} ({sg['GroupId']})",
                        f"{risky_ports[from_port]} port {from_port} open to 0.0.0.0/0",
                        "Restrict the CIDR range to known admin IPs only",
                    )


def print_report():
    if not findings:
        print("No findings — environment looks clean.")
        return

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: order[f["severity"]])

    print(f"\n{'='*70}\nAWS SECURITY AUDIT REPORT — {len(findings)} finding(s)\n{'='*70}\n")
    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], "")
        print(f"{color}[{f['severity']}]{RESET} {f['resource']}")
        print(f"  Issue: {f['issue']}")
        print(f"  Fix:   {f['fix']}\n")


if __name__ == "__main__":
    print("Running AWS security audit...")
    check_s3_buckets()
    check_iam_roles()
    check_rds_instances()
    check_cloudtrail()
    check_security_groups()
    print_report()
