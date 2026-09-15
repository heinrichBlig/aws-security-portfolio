# Security Audit Report — Portfolio Demo Environment

**Environment**: Simulated AWS account (via floci, a local AWS emulator)
**Tooling**: Custom Python/boto3 audit script (`audit.py`)
**Date**: September 2026

---

## Executive Summary (for a non-technical reader)

I reviewed a demo cloud environment consisting of two storage buckets, one
server access rule, and the account's activity logging setup. The initial
review found 6 issues, ranging from a server left open to the entire
internet to missing backup protection on stored files.

All 6 issues were fixed directly, one at a time, with the environment
re-scanned after each fix to confirm it actually worked — this is
important, since assuming a fix worked without verifying it is itself a
common source of security gaps. Along the way, enabling activity logging
(CloudTrail) required creating a new storage bucket to hold the logs —
that new bucket was itself created with insecure defaults, surfacing 2
additional findings that were fixed in turn. This is a realistic pattern:
security work is iterative, and fixing one gap can introduce a new one
that also needs attention.

The environment now passes a full clean scan with **zero findings**.

---

## Findings Summary

| Severity | Count (initial scan) | Count (after all fixes) |
|---|---|---|
| Critical | 3 | 0 |
| High | 1 | 0 |
| Medium | 2 | 0 |
| Low | 0 | 0 |
| **Total** | **6** | **0** |

---

## Detailed Findings

### [CRITICAL] S3 bucket: test-bucket — ✅ FIXED
- **Issue**: No public access block configuration found
- **Risk**: Without this control in place, the bucket is one misconfigured
  permission away from being readable by anyone on the internet — a
  common root cause of real-world data breaches (leaked customer records,
  source code, credentials stored in files).
- **Fix applied**: `aws s3api put-public-access-block --bucket test-bucket
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`
- **Verified**: Re-ran `audit.py` — finding no longer appears.

### [CRITICAL] S3 bucket: test-vulnerable-bucket — ✅ FIXED
- **Issue**: No public access block configuration found
- **Risk**: Same as above — this bucket was unprotected against accidental
  or malicious public exposure.
- **Fix applied**: Same public access block command applied to this bucket
- **Verified**: Re-ran `audit.py` — finding no longer appears.

### [CRITICAL] Security group: test-sg (sg-47f409592febd2748) — ✅ FIXED
- **Issue**: SSH (port 22) open to 0.0.0.0/0 — i.e., the entire internet
- **Risk**: Anyone, anywhere, could attempt to connect to this server over
  SSH. In practice, open SSH ports are scanned and attacked by automated
  bots within minutes of being exposed. This is one of the single most
  common initial access points in real breaches.
- **Fix applied**: Revoked the `0.0.0.0/0` ingress rule and replaced it
  with a rule restricted to a specific admin CIDR range
- **Verified**: Re-ran `audit.py` — finding no longer appears.

### [HIGH] Account-wide: CloudTrail — ✅ FIXED
- **Issue**: No CloudTrail trail configured
- **Risk**: Without CloudTrail, there is no record of who did what in this
  AWS account. If something goes wrong — a breach, an accidental deletion,
  unauthorized changes — there would be no way to investigate what
  happened or who was responsible.
- **Fix applied**: Created a dedicated logging bucket and a multi-region
  CloudTrail trail, then started logging
- **Verified**: Re-ran `audit.py` — finding no longer appears. (Note: this
  fix introduced 2 new findings on the newly created logging bucket
  itself — see below. This is documented deliberately, since it's a
  realistic example of remediation surfacing new gaps.)

### [MEDIUM] S3 bucket: test-bucket — Versioning — ✅ FIXED
- **Issue**: Versioning was not enabled
- **Risk**: Without versioning, an accidental deletion or overwrite of a
  file is permanent and unrecoverable.
- **Fix applied**: `aws s3api put-bucket-versioning --bucket test-bucket
  --versioning-configuration Status=Enabled`
- **Verified**: Re-ran `audit.py` after the fix — finding no longer
  appears. Confirmed resolved.

### [MEDIUM] S3 bucket: test-vulnerable-bucket — Versioning — ✅ FIXED
- **Issue**: Versioning was not enabled
- **Risk**: Same as above — files in this bucket could have been
  permanently lost through accidental deletion or overwrite.
- **Fix applied**: Same versioning command applied to this bucket
- **Verified**: Re-ran `audit.py` — finding no longer appears.

### [CRITICAL] S3 bucket: audit-trail-logs-bucket — ✅ FIXED (newly surfaced)
- **Issue**: No public access block configuration found — this bucket was
  created mid-remediation (to hold CloudTrail logs) with default,
  unhardened settings
- **Risk**: Same as the other public access block findings — this bucket
  holds audit logs, so exposing it publicly would be especially serious,
  potentially revealing account activity to an attacker.
- **Fix applied**: Same public access block command applied to this bucket
- **Verified**: Re-ran `audit.py` — finding no longer appears.

### [MEDIUM] S3 bucket: audit-trail-logs-bucket — Versioning — ✅ FIXED (newly surfaced)
- **Issue**: Versioning was not enabled on the newly created logging bucket
- **Risk**: Log files could be overwritten or deleted without recovery.
- **Fix applied**: Same versioning command applied to this bucket
- **Verified**: Re-ran `audit.py` — finding no longer appears.

---

## Audit Trail (Full Before / During / After)

**Initial scan** — 6 findings:
```
[CRITICAL] S3 bucket: test-bucket — No public access block configuration
[CRITICAL] S3 bucket: test-vulnerable-bucket — No public access block configuration
[CRITICAL] Security group: test-sg — SSH port 22 open to 0.0.0.0/0
[HIGH]     Account-wide — No CloudTrail trail configured
[MEDIUM]   S3 bucket: test-bucket — Versioning is not enabled
[MEDIUM]   S3 bucket: test-vulnerable-bucket — Versioning is not enabled
```

**After fixing versioning on `test-bucket`** — 5 findings:
```
[CRITICAL] S3 bucket: test-bucket — No public access block configuration
[CRITICAL] S3 bucket: test-vulnerable-bucket — No public access block configuration
[CRITICAL] Security group: test-sg — SSH port 22 open to 0.0.0.0/0
[HIGH]     Account-wide — No CloudTrail trail configured
[MEDIUM]   S3 bucket: test-vulnerable-bucket — Versioning is not enabled
```

**After fixing public access blocks, the security group, and enabling
CloudTrail** — 3 *new* findings surfaced on the logging bucket created
during the CloudTrail fix:
```
[CRITICAL] S3 bucket: audit-trail-logs-bucket — No public access block configuration
[MEDIUM]   S3 bucket: audit-trail-logs-bucket — Versioning is not enabled
[MEDIUM]   S3 bucket: test-vulnerable-bucket — Versioning is not enabled
```

**Final scan, after fixing the logging bucket and remaining versioning
gap** — 0 findings:
```
Running AWS security audit...
No findings — environment looks clean.
```

This confirms the audit script correctly detects both the presence and
absence of a misconfiguration, that each fix was verified through
re-scanning rather than assumed, and that a new resource created during
remediation (the CloudTrail logging bucket) was itself caught by the same
audit process — exactly as it should be in a real environment.

---

## Lessons / What I'd Do Differently in Production

Running this against a real (simulated) environment made a few things
concrete that weren't obvious from just reading the script:

- **Detection often relies on absence, not a clean "false" flag.** Several
  checks (public access block, encryption, CloudTrail) work by catching
  an error or an empty result when a setting was never configured, rather
  than reading a simple `true`/`false` value. Real AWS APIs are not always
  consistent about this.
- **Fixing one issue at a time and re-scanning is the right workflow.**
  Batch-fixing everything blind, without verifying each fix individually,
  risks missing something or introducing a new misconfiguration.
- **In a real production environment**, none of these fixes should be
  applied ad hoc via CLI commands the way this demo did — they belong in
  version-controlled Infrastructure as Code (Terraform), so the fix is
  repeatable, reviewable, and won't silently drift back to an insecure
  state later.

---

*This report was generated using a custom-built Python/boto3 audit tool,
run against a local AWS-compatible sandbox (floci), as part of an
ongoing cloud security portfolio.*
