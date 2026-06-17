# AWS Cloud Security Misconfiguration Scanner

Python CLI for enumerating common AWS security misconfigurations across S3, EC2, IAM, Lambda, and VPCs.

It checks for:

- S3 public ACLs and public bucket policies
- EC2 instances using IMDSv1
- Security groups with 0.0.0.0/0 or ::/0 ingress and broad port exposure
- IAM policies with wildcard permissions and unused roles
- Lambda function URLs that are public
- VPCs missing Flow Logs

Each finding includes a remediation recommendation and framework references for CIS AWS Foundations Benchmark and MITRE ATT&CK Cloud.

## Install

```bash
python -m pip install -e .
```

## Run

```bash
aws-misconfig-scan --region us-east-1 --output report.json
```

You can also run it as a module after installation:

```bash
python -m aws_cloud_security_misconfiguration_scanner --region us-east-1 --output report.json
```

Useful options:

- `--all-regions` scans every AWS region returned by the boto3 session.
- `--regions us-east-1 eu-west-1` limits the scan to specific regions.
- `--json-only` suppresses the human-readable summary.
- `--iam-unused-days 90` changes the threshold for unused IAM roles.

## Output

The tool writes a JSON report containing:

- scan metadata
- per-service findings
- severity counts
- remediation guidance
- CIS and MITRE references
