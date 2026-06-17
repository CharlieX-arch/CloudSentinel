from __future__ import annotations

from datetime import datetime, timezone
import unittest

from aws_cloud_security_misconfiguration_scanner.scanner import AwsMisconfigurationScanner


class StubPaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self):
        return iter(self.pages)


class StubSTS:
    def get_caller_identity(self):
        return {"Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/demo/test"}


class StubS3:
    def list_buckets(self):
        return {"Buckets": [{"Name": "public-bucket"}]}

    def get_bucket_acl(self, Bucket):
        return {
            "Grants": [
                {
                    "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                    "Permission": "READ",
                }
            ]
        }

    def get_bucket_policy_status(self, Bucket):
        return {"PolicyStatus": {"IsPublic": True}}

    def get_public_access_block(self, Bucket):
        return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": False}}


class StubEC2:
    def describe_instances(self):
        return {
            "Reservations": [
                {
                    "Instances": [
                        {"InstanceId": "i-123", "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "enabled"}}
                    ]
                }
            ]
        }

    def describe_security_groups(self):
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-123",
                    "GroupName": "public-sg",
                    "IpPermissions": [
                        {"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                    ],
                }
            ]
        }

    def describe_vpcs(self):
        return {"Vpcs": [{"VpcId": "vpc-123"}]}

    def describe_flow_logs(self):
        return {"FlowLogs": []}


class StubLambdaExceptions:
    class ResourceNotFoundException(Exception):
        pass


class StubLambda:
    exceptions = StubLambdaExceptions

    def get_paginator(self, name):
        return StubPaginator([{"Functions": [{"FunctionName": "fn-1"}]}])

    def get_function_url_config(self, FunctionName):
        return {"AuthType": "NONE", "FunctionUrl": "https://example.com"}


class StubIAM:
    def get_paginator(self, name):
        if name == "list_roles":
            return StubPaginator(
                [
                    {
                        "Roles": [
                            {
                                "RoleName": "unused-role",
                                "RoleLastUsed": {"LastUsedDate": datetime.now(timezone.utc) - __import__("datetime").timedelta(days=120)},
                            }
                        ]
                    }
                ]
            )
        if name == "list_users":
            return StubPaginator(
                [{"Users": [{"UserName": "demo-user", "CreateDate": datetime.now(timezone.utc) - __import__("datetime").timedelta(days=120)}]}]
            )
        raise AssertionError(name)

    def list_attached_role_policies(self, RoleName):
        return {"AttachedPolicies": []}

    def list_role_policies(self, RoleName):
        return {"PolicyNames": []}

    def list_access_keys(self, UserName):
        return {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "AKIAOLDKEY",
                    "Status": "Active",
                    "CreateDate": datetime.now(timezone.utc) - __import__("datetime").timedelta(days=120),
                }
            ]
        }


class StubRDS:
    def describe_db_instances(self):
        return {"DBInstances": [{"DBInstanceIdentifier": "db-1", "PubliclyAccessible": True, "Engine": "postgres"}]}


class StubSession:
    region_name = "us-east-1"

    def client(self, service_name, region_name=None):
        if service_name == "sts":
            return StubSTS()
        if service_name == "s3":
            return StubS3()
        if service_name == "ec2":
            return StubEC2()
        if service_name == "lambda":
            return StubLambda()
        if service_name == "iam":
            return StubIAM()
        if service_name == "rds":
            return StubRDS()
        raise AssertionError(service_name)

    def get_available_regions(self, service_name):
        return ["us-east-1"]


class ScannerTests(unittest.TestCase):
    def test_scanner_finds_common_misconfigurations(self) -> None:
        scanner = AwsMisconfigurationScanner(session=StubSession(), regions=["us-east-1"], iam_unused_days=90)
        report = scanner.scan()

        titles = {finding.title for finding in report.findings}
        self.assertIn("Public S3 bucket ACL", titles)
        self.assertIn("EC2 instance allows IMDSv1", titles)
        self.assertIn("Security group exposes ingress to the internet", titles)
        self.assertIn("Public Lambda function URL", titles)
        self.assertIn("Unused IAM role", titles)
        self.assertIn("Old IAM access key", titles)
        self.assertIn("Publicly accessible RDS instance", titles)
        self.assertIn("VPC missing Flow Logs", titles)

        self.assertGreaterEqual(report.summary.get("high", 0), 3)


if __name__ == "__main__":
    unittest.main()
