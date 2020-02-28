#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from handler import lambda_handler


class HandlerTest(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def test_empty_event(self):
        actual = lambda_handler("")
        expected = {"result": "NON_COMPLIANT"}
        self.assertEqual(actual, expected)

    def test_no_roles(self):
        event = {"roles": ""}

        actual = lambda_handler(event)
        expected = {"result": "NON_COMPLIANT"}

        self.assertEqual(actual, expected)

    def test_invalid_yaml(self):
        event = {"roles": "{test"}

        actual = lambda_handler(event)
        expected = {"result": "NON_COMPLIANT"}

        self.assertEqual(actual, expected)

    def test_valid_yaml(self):
        event = {
            "roles": """
---
- name: Ec2Role
  settings:
    principal_service: ec2
    policies:
      - default_role_policies
    additional_policies:
      - action: 's3:GetObject'
        resource: 'arn:aws:s3:::mybucketname/*'
    managed_policy_arns:
      - AmazonEKSWorkerNodePolicy
"""
        }

        actual = lambda_handler(event)
        expected = {"result": "COMPLIANT"}

        self.assertEqual(actual, expected)

    def test_invalid_name(self):
        event = {
            "roles": """
---
- name: bad name!!!
  settings:
    principal_service: ec2
    policies: default_role_policies
"""
        }

        actual = lambda_handler(event)
        expected = {"result": "NON_COMPLIANT"}

        self.assertEqual(actual, expected)
