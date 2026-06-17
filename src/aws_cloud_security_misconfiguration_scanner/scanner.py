from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, NoRegionError

from .models import Finding, ScanReport


PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}
DEFAULT_UNUSED_ROLE_DAYS = 90


@dataclass(slots=True)
class ScanContext:
    account_id: str | None
    partition: str | None
    regions: list[str]


class AwsMisconfigurationScanner:
    def __init__(
        self,
        session: boto3.session.Session | None = None,
        regions: Iterable[str] | None = None,
        iam_unused_days: int = DEFAULT_UNUSED_ROLE_DAYS,
    ) -> None:
        self.session = session or boto3.Session()
        self.iam_unused_days = iam_unused_days
        self.regions = self._resolve_regions(regions)

    def scan(self) -> ScanReport:
        context = self._build_context()
        findings: list[Finding] = []

        findings.extend(self._scan_s3())
        findings.extend(self._scan_iam())

        for region in context.regions:
            findings.extend(self._scan_ec2(region))
            findings.extend(self._scan_lambda(region))
            findings.extend(self._scan_vpc(region))
            findings.extend(self._scan_rds(region))

        return ScanReport.create(
            account_id=context.account_id,
            partition=context.partition,
            regions_scanned=context.regions,
            findings=findings,
        )

    def _build_context(self) -> ScanContext:
        account_id: str | None = None
        partition: str | None = None
        try:
            sts = self.session.client("sts")
            identity = sts.get_caller_identity()
            account_id = identity.get("Account")
            arn = identity.get("Arn")
            partition = arn.split(":")[1] if arn else None
        except (BotoCoreError, ClientError, NoCredentialsError, NoRegionError):
            pass
        return ScanContext(account_id=account_id, partition=partition, regions=self.regions)

    def _resolve_regions(self, regions: Iterable[str] | None) -> list[str]:
        if regions:
            return list(dict.fromkeys(region.strip() for region in regions if region.strip()))

        if self.session.region_name:
            return [self.session.region_name]

        try:
            return self.session.get_available_regions("ec2") or ["us-east-1"]
        except Exception:
            return ["us-east-1"]

    def _scan_s3(self) -> list[Finding]:
        findings: list[Finding] = []
        s3 = self.session.client("s3")

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except (BotoCoreError, ClientError) as error:
            return [self._scan_error("s3", "account", "s3-account", error)]

        for bucket in buckets:
            bucket_name = bucket["Name"]
            findings.extend(self._scan_s3_bucket(s3, bucket_name))

        return findings

    def _scan_s3_bucket(self, s3: Any, bucket_name: str) -> list[Finding]:
        findings: list[Finding] = []

        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                grantee_uri = grantee.get("URI", "")
                permission = grant.get("Permission", "")
                if grantee_uri.endswith("AllUsers") or grantee_uri.endswith("AuthenticatedUsers"):
                    findings.append(
                        Finding(
                            service="s3",
                            resource_type="bucket",
                            resource_id=bucket_name,
                            title="Public S3 bucket ACL",
                            severity="high",
                            description=f"Bucket ACL grants {permission} to a public principal.",
                            remediation="Remove public ACL grants and enable S3 Block Public Access for the bucket and account.",
                            cis_references=["CIS AWS Foundations Benchmark - S3 public access controls"],
                            mitre_techniques=["T1530 Data from Cloud Storage"],
                            details={"permission": permission, "grantee_uri": grantee_uri},
                        )
                    )
                    break
        except (BotoCoreError, ClientError):
            pass

        try:
            policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)
            if policy_status.get("PolicyStatus", {}).get("IsPublic"):
                findings.append(
                    Finding(
                        service="s3",
                        resource_type="bucket",
                        resource_id=bucket_name,
                        title="Public S3 bucket policy",
                        severity="high",
                        description="Bucket policy evaluates as public.",
                        remediation="Restrict bucket policy principals and conditions so the bucket is not publicly reachable.",
                        cis_references=["CIS AWS Foundations Benchmark - S3 public access controls"],
                        mitre_techniques=["T1530 Data from Cloud Storage"],
                        details={"policy_status": "public"},
                    )
                )
        except (BotoCoreError, ClientError):
            pass

        try:
            public_access = s3.get_public_access_block(Bucket=bucket_name)
            configuration = public_access.get("PublicAccessBlockConfiguration", {})
            flags = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
            if not all(configuration.get(flag, False) for flag in flags):
                findings.append(
                    Finding(
                        service="s3",
                        resource_type="bucket",
                        resource_id=bucket_name,
                        title="S3 bucket public access block incomplete",
                        severity="medium",
                        description="One or more Block Public Access settings are disabled.",
                        remediation="Enable all S3 Block Public Access settings at the account and bucket level.",
                        cis_references=["CIS AWS Foundations Benchmark - S3 public access controls"],
                        mitre_techniques=["T1530 Data from Cloud Storage"],
                        details=configuration,
                    )
                )
        except (BotoCoreError, ClientError):
            pass

        return findings

    def _scan_ec2(self, region: str) -> list[Finding]:
        findings: list[Finding] = []
        ec2 = self.session.client("ec2", region_name=region)

        try:
            reservations = ec2.describe_instances().get("Reservations", [])
        except (BotoCoreError, ClientError) as error:
            return [self._scan_error("ec2", "region", region, error)]

        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                instance_id = instance.get("InstanceId", "unknown")
                metadata = instance.get("MetadataOptions", {})
                if metadata.get("HttpTokens") == "optional":
                    findings.append(
                        Finding(
                            service="ec2",
                            resource_type="instance",
                            resource_id=instance_id,
                            region=region,
                            title="EC2 instance allows IMDSv1",
                            severity="high",
                            description="Instance metadata service does not require session tokens.",
                            remediation="Set HttpTokens to required and review applications for IMDSv2 compatibility.",
                            cis_references=["CIS AWS Foundations Benchmark - EC2 instance metadata protection"],
                            mitre_techniques=["T1552.005 Cloud Instance Metadata API"],
                            details={"http_tokens": metadata.get("HttpTokens"), "http_endpoint": metadata.get("HttpEndpoint")},
                        )
                    )

        try:
            security_groups = ec2.describe_security_groups().get("SecurityGroups", [])
        except (BotoCoreError, ClientError) as error:
            findings.append(self._scan_error("ec2", "region", region, error))
            return findings

        for security_group in security_groups:
            group_id = security_group.get("GroupId", "unknown")
            group_name = security_group.get("GroupName", group_id)
            for permission in security_group.get("IpPermissions", []):
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")
                ip_ranges = permission.get("IpRanges", [])
                ipv6_ranges = permission.get("Ipv6Ranges", [])
                public_sources = [
                    source.get("CidrIp") for source in ip_ranges if source.get("CidrIp") in PUBLIC_CIDRS
                ] + [
                    source.get("CidrIpv6") for source in ipv6_ranges if source.get("CidrIpv6") in PUBLIC_CIDRS
                ]
                if not public_sources:
                    continue

                findings.append(
                    Finding(
                        service="ec2",
                        resource_type="security_group",
                        resource_id=group_id,
                        region=region,
                        title="Security group exposes ingress to the internet",
                        severity="high",
                        description=f"Security group {group_name} allows ingress from a public CIDR.",
                        remediation="Restrict the source CIDR and scope ports to the smallest required network range.",
                        cis_references=["CIS AWS Foundations Benchmark - Security groups should not allow unrestricted ingress"],
                        mitre_techniques=["T1190 Exploit Public-Facing Application", "T1046 Network Service Discovery"],
                        details={
                            "group_name": group_name,
                            "ports": self._describe_ports(from_port, to_port),
                            "public_sources": public_sources,
                            "protocol": permission.get("IpProtocol"),
                        },
                    )
                )

        return findings

    def _scan_lambda(self, region: str) -> list[Finding]:
        findings: list[Finding] = []
        lambda_client = self.session.client("lambda", region_name=region)

        try:
            paginator = lambda_client.get_paginator("list_functions")
            for page in paginator.paginate():
                for function in page.get("Functions", []):
                    function_name = function.get("FunctionName", "unknown")
                    try:
                        config = lambda_client.get_function_url_config(FunctionName=function_name)
                    except lambda_client.exceptions.ResourceNotFoundException:
                        continue
                    except (BotoCoreError, ClientError):
                        continue

                    if config.get("AuthType") == "NONE":
                        findings.append(
                            Finding(
                                service="lambda",
                                resource_type="function",
                                resource_id=function_name,
                                region=region,
                                title="Public Lambda function URL",
                                severity="medium",
                                description="Function URL is configured without authentication.",
                                remediation="Require AWS_IAM auth or remove the function URL if public access is not required.",
                                cis_references=["CIS AWS Foundations Benchmark - limit public exposure of serverless endpoints"],
                                mitre_techniques=["T1190 Exploit Public-Facing Application"],
                                details={"url": config.get("FunctionUrl"), "auth_type": config.get("AuthType")},
                            )
                        )
        except (BotoCoreError, ClientError, NoRegionError) as error:
            findings.append(self._scan_error("lambda", "region", region, error))

        return findings

    def _scan_iam(self) -> list[Finding]:
        findings: list[Finding] = []
        iam = self.session.client("iam")

        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role.get("RoleName", "unknown")
                    last_used = role.get("RoleLastUsed", {}).get("LastUsedDate")
                    if self._is_role_unused(last_used):
                        findings.append(
                            Finding(
                                service="iam",
                                resource_type="role",
                                resource_id=role_name,
                                title="Unused IAM role",
                                severity="medium",
                                description="Role has not been used recently and may be removable.",
                                remediation="Confirm the role is still needed; remove stale roles and attached permissions if unused.",
                                cis_references=["CIS AWS Foundations Benchmark - remove unused IAM entities"],
                                mitre_techniques=["T1078 Valid Accounts"],
                                details={"last_used": last_used.isoformat() if last_used else None},
                            )
                        )

                    findings.extend(self._scan_role_policies(iam, role_name))

            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user.get("UserName", "unknown")
                    findings.extend(self._scan_access_keys(iam, user_name, user.get("CreateDate")))
        except (BotoCoreError, ClientError) as error:
            findings.append(self._scan_error("iam", "account", "iam-account", error))

        return findings

    def _scan_access_keys(self, iam: Any, user_name: str, created_at: datetime | None) -> list[Finding]:
        findings: list[Finding] = []
        try:
            response = iam.list_access_keys(UserName=user_name)
            for access_key in response.get("AccessKeyMetadata", []):
                key_id = access_key.get("AccessKeyId", "unknown")
                status = access_key.get("Status")
                create_date = access_key.get("CreateDate") or created_at
                if create_date is None:
                    continue
                if create_date.tzinfo is None:
                    create_date = create_date.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - create_date).days
                if age_days >= self.iam_unused_days:
                    findings.append(
                        Finding(
                            service="iam",
                            resource_type="access_key",
                            resource_id=key_id,
                            title="Old IAM access key",
                            severity="medium",
                            description=f"Access key for user {user_name} is {age_days} days old.",
                            remediation="Rotate or disable aged access keys and prefer roles or temporary credentials.",
                            cis_references=["CIS AWS Foundations Benchmark - rotate IAM access keys regularly"],
                            mitre_techniques=["T1098 Account Manipulation"],
                            details={"user_name": user_name, "status": status, "age_days": age_days},
                        )
                    )
        except (BotoCoreError, ClientError):
            pass

        return findings

    def _scan_role_policies(self, iam: Any, role_name: str) -> list[Finding]:
        findings: list[Finding] = []

        try:
            attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
            for policy in attached:
                policy_arn = policy.get("PolicyArn")
                policy_name = policy.get("PolicyName", policy_arn or "unknown")
                findings.extend(
                    self._inspect_iam_policy(
                        iam=iam,
                        resource_type="role",
                        resource_id=role_name,
                        policy_name=policy_name,
                        policy_arn=policy_arn,
                    )
                )

            inline_names = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
            for policy_name in inline_names:
                policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name).get("PolicyDocument", {})
                findings.extend(
                    self._find_wildcard_policy(
                        resource_type="role",
                        resource_id=role_name,
                        policy_name=policy_name,
                        policy_document=policy_doc,
                        region=None,
                    )
                )
        except (BotoCoreError, ClientError):
            pass

        return findings

    def _inspect_iam_policy(
        self,
        iam: Any,
        resource_type: str,
        resource_id: str,
        policy_name: str,
        policy_arn: str | None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not policy_arn:
            return findings

        try:
            policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
            version_id = policy["DefaultVersionId"]
            version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            policy_document = version["PolicyVersion"]["Document"]
            findings.extend(
                self._find_wildcard_policy(
                    resource_type=resource_type,
                    resource_id=resource_id,
                    policy_name=policy_name,
                    policy_document=policy_document,
                    region=None,
                )
            )
        except (BotoCoreError, ClientError):
            pass

        return findings

    def _find_wildcard_policy(
        self,
        resource_type: str,
        resource_id: str,
        policy_name: str,
        policy_document: dict[str, Any],
        region: str | None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        statements = policy_document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get("Action", [])
            resources = statement.get("Resource", [])
            not_actions = statement.get("NotAction")
            if self._contains_wildcard(actions) and self._contains_wildcard(resources) and not not_actions:
                findings.append(
                    Finding(
                        service="iam",
                        resource_type=resource_type,
                        resource_id=resource_id,
                        region=region,
                        title="Overly permissive IAM policy",
                        severity="high",
                        description=f"Policy {policy_name} allows wildcard actions on wildcard resources.",
                        remediation="Replace wildcard permissions with narrowly scoped actions and resource ARNs.",
                        cis_references=["CIS AWS Foundations Benchmark - least privilege IAM policies"],
                        mitre_techniques=["T1098 Account Manipulation", "T1078 Valid Accounts"],
                        details={"policy_name": policy_name, "statement": statement},
                    )
                )
                break

        return findings

    def _scan_vpc(self, region: str) -> list[Finding]:
        findings: list[Finding] = []
        ec2 = self.session.client("ec2", region_name=region)

        try:
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
        except (BotoCoreError, ClientError) as error:
            return [self._scan_error("vpc", "region", region, error)]

        flow_log_vpcs = {flow_log.get("ResourceId") for flow_log in flow_logs if flow_log.get("ResourceType") == "VPC"}
        for vpc in vpcs:
            vpc_id = vpc.get("VpcId", "unknown")
            if vpc_id not in flow_log_vpcs:
                findings.append(
                    Finding(
                        service="vpc",
                        resource_type="vpc",
                        resource_id=vpc_id,
                        region=region,
                        title="VPC missing Flow Logs",
                        severity="medium",
                        description="No VPC Flow Logs were found for this VPC.",
                        remediation="Enable VPC Flow Logs to capture traffic metadata for monitoring and incident response.",
                        cis_references=["CIS AWS Foundations Benchmark - VPC Flow Logs should be enabled"],
                        mitre_techniques=["T1046 Network Service Discovery"],
                        details={"vpc_id": vpc_id},
                    )
                )

        return findings

    def _scan_rds(self, region: str) -> list[Finding]:
        findings: list[Finding] = []
        rds = self.session.client("rds", region_name=region)

        try:
            for db_instance in rds.describe_db_instances().get("DBInstances", []):
                if db_instance.get("PubliclyAccessible"):
                    identifier = db_instance.get("DBInstanceIdentifier", "unknown")
                    findings.append(
                        Finding(
                            service="rds",
                            resource_type="db_instance",
                            resource_id=identifier,
                            region=region,
                            title="Publicly accessible RDS instance",
                            severity="high",
                            description="Database instance is exposed to public network access.",
                            remediation="Disable public accessibility and restrict database access to private subnets and security groups.",
                            cis_references=["CIS AWS Foundations Benchmark - RDS databases should not be publicly accessible"],
                            mitre_techniques=["T1190 Exploit Public-Facing Application"],
                            details={
                                "engine": db_instance.get("Engine"),
                                "publicly_accessible": db_instance.get("PubliclyAccessible"),
                            },
                        )
                    )
        except (BotoCoreError, ClientError) as error:
            findings.append(self._scan_error("rds", "region", region, error))

        return findings

    def _scan_error(self, service: str, resource_type: str, resource_id: str, error: Exception) -> Finding:
        return Finding(
            service=service,
            resource_type=resource_type,
            resource_id=resource_id,
            title="Scan error",
            severity="info",
            description="The scanner could not complete this check.",
            remediation="Verify AWS credentials, permissions, and region configuration.",
            details={"error": str(error)},
        )

    def _contains_wildcard(self, value: Any) -> bool:
        if isinstance(value, str):
            return value == "*"
        if isinstance(value, list):
            return any(self._contains_wildcard(item) for item in value)
        return False

    def _is_role_unused(self, last_used: datetime | None) -> bool:
        if last_used is None:
            return True
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.iam_unused_days)
        if last_used.tzinfo is None:
            last_used = last_used.replace(tzinfo=timezone.utc)
        return last_used < cutoff

    def _describe_ports(self, from_port: int | None, to_port: int | None) -> str:
        if from_port is None and to_port is None:
            return "all ports"
        if from_port == to_port:
            return f"port {from_port}"
        return f"ports {from_port}-{to_port}"
