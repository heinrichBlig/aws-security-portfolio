# AWS Security Audit Tool

A Python/boto3 tool that scans an AWS environment for common security
misconfigurations, and a real audit report from running it end-to-end
against a live (simulated) environment.

## What it does

`scripts/audit.py` checks for:
- S3 buckets missing public access blocks, encryption, or versioning
- IAM roles with overly permissive (`"*"` on `"*"`) policies
- RDS instances that are unencrypted or publicly accessible
- Security groups with SSH/RDP open to the entire internet (`0.0.0.0/0`)
- Missing or misconfigured CloudTrail logging

Each finding is reported with a severity level (Critical/High/Medium) and
a specific, actionable fix.

## Real results — see REPORT.md

`REPORT.md` documents a full real audit cycle I ran against a live
environment: an initial scan turning up 6 findings, fixing them one at a
time via the AWS CLI, re-scanning after each fix to verify it actually
worked, hitting a realistic snag (a new resource created mid-fix
introduced its own findings), fixing those too, and reaching a fully
clean scan. This wasn't a scripted demo — every fix and every re-scan in
that report is a real command I ran and a real result I verified.

## How I built this

I wrote this by learning boto3's core patterns — dictionary responses,
looping through resource lists, nested policy/permission structures, and
error handling — and rebuilding each check function myself rather than
just copying working code. I can walk through and explain every function
in this script.

## Running it yourself

```bash
pip install -r scripts/requirements.txt
python scripts/audit.py
```

Requires AWS credentials configured (via `aws configure` or environment
variables) pointing at either a real AWS account (read-only credentials
recommended) or a local AWS-compatible emulator.

## What's not in this repo yet

I'm currently learning AWS fundamentals (Cloud Practitioner) and have not
yet gone deep on Infrastructure as Code (Terraform) — so I'm keeping this
repo focused on the Python/boto3 work I've actually learned and can
confidently explain, rather than including code I generated but haven't
studied. I'll add Terraform here once I've gone through it properly.

## Disclaimer

Only run this against AWS accounts you own or have explicit permission
to audit, using read-only credentials.
# aws-security-portfolio
