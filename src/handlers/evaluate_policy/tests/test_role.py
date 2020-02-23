#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import unittest

from evaluate_policy.role import Role


def json_dump_slim(obj):
    return json.dumps(obj, sort_keys=True, indent=None, separators=(",", ":"))


class TestRole(unittest.TestCase):
    def test_empty_role_load(self):
        role = Role("")
        actual = role.analyze()
        self.assertFalse(actual)
        self.assertEqual(len(role.findings), 1)
        self.assertEqual(
            str(role.findings[0]),
            "MALFORMED - Role contains no settings - {'filepath': None}",
        )

    def test_unknown_element(self):
        data = {"key": "value"}

        role = Role(data)
        actual = role.analyze()
        self.assertFalse(actual)
        self.assertEqual(len(role.findings), 1)
        self.assertEqual(
            str(role.findings[0]),
            "MALFORMED - Role contains an unknown element - {'string': 'key', 'filepath': None}",
        )

    def test_missing_settings(self):
        data = {"name": "Ec2Role"}

        role = Role(data)
        actual = role.analyze()
        self.assertFalse(actual)
        self.assertEqual(len(role.findings), 1)
        self.assertEqual(
            str(role.findings[0]),
            "MALFORMED - Role contains no settings - {'filepath': None}",
        )

    def test_settings_unknown_element(self):
        data = {"name": "Ec2Role", "settings": {"key": "value"}}

        role = Role(data)
        actual = role.analyze()
        self.assertFalse(actual)
        self.assertEqual(len(role.findings), 1)
        self.assertEqual(
            str(role.findings[0]),
            "MALFORMED - Role settings contains an unknown element - {'string': 'key', 'filepath': None}",
        )

    def test_missing_policies(self):
        data = {"name": "Ec2Role", "settings": {"principal_service": "ec2"}}

        role = Role(data)
        actual = role.analyze()
        self.assertTrue(actual)
        self.assertEqual(len(role.findings), 1)
        self.assertEqual(
            str(role.findings[0]),
            "MALFORMED - Role contains no policies - {'filepath': None}",
        )

    def test_blacklisted_managed_policy(self):
        data = {
            "name": "Ec2Role",
            "settings": {
                "principal_service": "ec2",
                "managed_policy_arns": ["AdministratorAccess"],
            },
        }

        role = Role(data)
        actual = role.analyze()
        self.assertTrue(actual)
        self.assertEqual(len(role.findings), 2)
        self.assertEqual(
            str(role.findings[0]),
            "UNAPPROVED_POLICY - Managed policy is not approved for use - {'string': 'AdministratorAccess', 'filepath': None}",
        )
        self.assertEqual(
            str(role.findings[1]),
            "MALFORMED - Role contains no policies - {'filepath': None}",
        )

    def test_unknown_prefix_policy(self):
        data = {
            "name": "Ec2Role",
            "settings": {
                "principal_service": "ec2",
                "additional_policies": [{"action": ["bad:*"], "resource": "*"}],
            },
        }

        role = Role(data)
        actual = role.analyze()
        self.assertTrue(actual)
        self.assertEqual(len(role.findings), 1)
        self.assertEqual(
            str(role.findings[0]),
            "UNKNOWN_PREFIX - Unknown prefix bad - {'statement': {'Effect': 'Allow', 'Action': ['bad:*'], 'Resource': '*'}, 'filepath': None}",
        )

    def test_unknown_default_service_policy(self):
        data = {
            "name": "Ec2Role",
            "settings": {
                "principal_service": "ec2",
                "policies": ["default_role_policy"],
            },
        }

        role = Role(data)
        actual = role.analyze()
        self.assertTrue(actual)
        self.assertEqual(len(role.findings), 2)
        self.assertEqual(
            str(role.findings[0]),
            "UNKNOWN_POLICY - Role contains an unknown default principal policy - {'string': 'ec2', 'filepath': None}",
        )
        self.assertEqual(
            str(role.findings[1]),
            "MALFORMED - Role contains no policies - {'filepath': None}",
        )

    def test_lambda_default_service_policy(self):
        data = {
            "name": "LambdaRole",
            "settings": {
                "principal_service": "lambda",
                "policies": ["default_role_policy"],
            },
        }

        role = Role(data)
        actual = role.analyze()
        self.assertTrue(actual)
        self.assertEqual(len(role.findings), 0)

    def test_ecs_default_service_policy(self):
        data = {
            "name": "EcsRole",
            "settings": {
                "principal_service": "ecs",
                "policies": ["default_role_policy"],
            },
        }

        role = Role(data)
        actual = role.analyze()
        self.assertTrue(actual)
        self.assertEqual(len(role.findings), 0)

    def test_invalid_policy(self):
        data = {
            "name": "EcsRole",
            "settings": {
                "principal_service": "ecs",
                "additional_policies": [
                    {"action": "s3:GetObject", "resource": "arn:aws:logs:*:*:*"}
                ],
            },
        }

        role = Role(data)
        actual = role.analyze()
        self.assertTrue(actual)
        self.assertEqual(len(role.findings), 1)
        self.assertEqual(
            str(role.findings[0]),
            "RESOURCE_MISMATCH - [{'action': 's3:GetObject', 'required_format': 'arn:*:s3:::*/*'}] - {'actions': ['s3:GetObject'], 'filepath': None}",
        )

    def test_role_to_json(self):
        self.maxDiff = None

        data = {
            "name": "EcsRole",
            "settings": {
                "principal_service": "ecs",
                "policies": ["default_role_policy"],
            },
        }

        role = Role(data)
        role.analyze()
        actual = role.to_json()

        expected = {
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Action": "sts:AssumeRole",
                            "Effect": "Allow",
                            "Principal": {"Service": ["ecs.amazonaws.com"]},
                        }
                    ],
                    "Version": "2012-10-17",
                },
                "Description": "DO NOT DELETE - Created by Role Creation Service. Created by CloudFormation ${AWS::StackId}",
                "Policies": [
                    {
                        "PolicyName": "default_ecs_policy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "ContainerRegistryAccess",
                                    "Effect": "Allow",
                                    "Action": [
                                        "ecr:GetAuthorizationToken",
                                        "ecr:BatchCheckLayerAvailability",
                                        "ecr:GetDownloadUrlForLayer",
                                        "ecr:BatchGetImage",
                                    ],
                                    "Resource": "*",
                                },
                                {
                                    "Sid": "CloudWatchAccess",
                                    "Effect": "Allow",
                                    "Action": [
                                        "logs:CreateLogGroup",
                                        "logs:CreateLogStream",
                                        "logs:PutLogEvents",
                                    ],
                                    "Resource": "*",
                                },
                            ],
                        },
                    }
                ],
                "RoleName": "EcsRole",
            },
            "Type": "AWS::IAM::Role",
        }

        self.assertEqual(actual, json_dump_slim(expected))
