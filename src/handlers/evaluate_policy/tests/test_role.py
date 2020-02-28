#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from parliament.finding import Finding

from evaluate_policy.role import Role


class TestRole(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def test_principal_service_multiple(self):
        data = {"settings": {"principal_service": ["ec2", "lambda"]}}

        role = Role(data)
        actual = role.principal_service
        expected = ["ec2", "lambda"]
        self.assertEqual(actual, expected)

    def test_principal_service_single(self):
        data = {"settings": {"principal_service": "ec2"}}

        role = Role(data)
        actual = role.principal_service
        expected = ["ec2"]
        self.assertEqual(actual, expected)

    def test_principal_service_none(self):
        data = {"settings": {}}

        role = Role(data)
        actual = role.principal_service
        expected = []
        self.assertEqual(actual, expected)

    def test_update_statements(self):
        statements = [
            {
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Resource": "arn:${AWS::Partition}:kms:${AWS::Region}:${AWS::AccountId}:key/my-key",
            }
        ]

        role = Role({}, region="us-east-1", account_id="111222333", partition="aws")
        actual = role._update_statements(statements)
        expected = [
            {
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Resource": ["arn:aws:kms:us-east-1:111222333:key/my-key"],
            }
        ]

        self.assertEqual(actual, expected)

    def test_update_statements_cf(self):
        statements = [
            {
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Resource": "arn:${AWS::Partition}:kms:${AWS::Region}:${AWS::AccountId}:key/my-key",
            }
        ]

        role = Role({}, region="us-east-1", account_id="111222333", partition="aws")
        actual = role._update_statements(statements, cf_sub_func=True)
        expected = [
            {
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Resource": [
                    {
                        "Fn::Sub": "arn:${AWS::Partition}:kms:${AWS::Region}:${AWS::AccountId}:key/my-key"
                    }
                ],
            }
        ]

        self.assertEqual(actual, expected)

    def test_update_statements_cf(self):
        statements = [
            {
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Resource": "arn:aws:kms:us-east-1:111222333:key/my-key",
            }
        ]

        role = Role({})
        actual = role._update_statements(statements, cf_sub_func=True)
        expected = [
            {
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Resource": ["arn:aws:kms:us-east-1:111222333:key/my-key"],
            }
        ]

        self.assertEqual(actual, expected)

    def test_get_default_policies(self):
        data = {"settings": {"principal_service": "lambda"}}
        role = Role(data, region="us-east-1", account_id="111222333")

        actual = role.get_default_policies()
        expected = [
            {
                "PolicyName": "default_lambda_policy",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "ENI",
                            "Effect": "Allow",
                            "Action": [
                                "ec2:CreateNetworkInterface",
                                "ec2:DescribeNetworkInterfaces",
                                "ec2:DeleteNetworkInterface",
                            ],
                            "Resource": ["*"],
                        },
                        {
                            "Sid": "CloudWatchLogGroup",
                            "Effect": "Allow",
                            "Action": "logs:CreateLogGroup",
                            "Resource": ["*"],
                        },
                        {
                            "Sid": "CloudWatchLogStream",
                            "Effect": "Allow",
                            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                            "Resource": [
                                "arn:aws:logs:us-east-1:111222333:log-group:*:log-stream:/aws/lambda/*"
                            ],
                        },
                        {
                            "Sid": "XRay",
                            "Effect": "Allow",
                            "Action": [
                                "xray:PutTraceSegments",
                                "xray:PutTelemetryRecords",
                                "xray:GetSamplingRules",
                                "xray:GetSamplingTargets",
                                "xray:GetSamplingStatisticSummaries",
                            ],
                            "Resource": ["*"],
                        },
                        {
                            "Sid": "KMS",
                            "Effect": "Allow",
                            "Action": [
                                "kms:Encrypt",
                                "kms:Decrypt",
                                "kms:ReEncrypt*",
                                "kms:GenerateDataKey*",
                                "kms:DescribeKey",
                            ],
                            "Resource": [
                                "arn:aws:kms:us-east-1:111222333:key/AccountKey"
                            ],
                        },
                    ],
                },
            }
        ]

        self.assertEqual(actual, expected)

    def test_get_policies(self):
        data = {
            "settings": {
                "additional_policies": [
                    {
                        "action": "s3:GetObject",
                        "resource": "arn:aws:s3:::mybucketname/*",
                    }
                ]
            }
        }
        role = Role(data, region="us-east-1", account_id="111222333")

        actual = role.get_policies()
        expected = [
            {
                "PolicyName": "inline_policy",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Action": "s3:GetObject",
                            "Effect": "Allow",
                            "Resource": ["arn:aws:s3:::mybucketname/*"],
                        }
                    ],
                },
            }
        ]

        self.assertEqual(actual, expected)

    def test_analyze_policies(self):
        data = {
            "settings": {
                "principal_service": ["ec2", "ec2", "lambda"],
                "policies": ["default_role_policy"],
                "additional_policies": [
                    {"action": "s3:GetObject", "resource": "arn:aws:s3:::mybucketname"}
                ],
            }
        }
        role = Role(data)

        actual = [str(finding) for finding in role.analyze_policies()]

        expected = [
            "RESOURCE_MISMATCH"
            " - [{'action': 's3:GetObject', 'required_format': 'arn:*:s3:::*/*'}]"
            " - {'actions': ['s3:GetObject'], 'filepath': None}"
        ]

        self.assertEqual(actual, expected)

    def test_valid_managed_policy(self):
        data = {"settings": {"managed_policy_arns": ["AmazonEKSWorkerNodePolicy"]}}
        role = Role(data)

        actual = role.analyze_policies()
        expected = []

        self.assertEqual(actual, expected)

    def test_invalid_managed_policy(self):
        data = {"settings": {"managed_policy_arns": ["AdministratorAccess"]}}
        role = Role(data)

        actual = [str(finding) for finding in role.analyze_policies()]

        expected = [
            "DENIED_POLICIES"
            " - Managed policies are not approved for use"
            " - {'managed_policy_arns': ['AdministratorAccess']}"
        ]

        self.assertEqual(actual, expected)
