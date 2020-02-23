#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from handler import lambda_handler


class HandlerTest(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def test_empty_event(self):
        event = ""

        with self.assertRaises(Exception) as cm:
            lambda_handler(event, None)

        actual = str(cm.exception)
        self.assertEqual(actual, "Invalid event")

    def test_no_roles(self):
        event = {"roles": ""}

        with self.assertRaises(Exception) as cm:
            lambda_handler(event, None)

        actual = str(cm.exception)
        self.assertEqual(actual, "No roles found in request")

    def test_invalid_yaml(self):
        event = {"roles": "{test"}

        with self.assertRaises(Exception) as cm:
            lambda_handler(event, None)

        actual = str(cm.exception)
        self.assertEqual(actual, "YAML parsing error")

    def test_handler(self):
        event = {
            "roles": """
---
- name: Ec2Role
  settings:
    principal_service: ec2
    policies:
      - default_role_policies
    additional_policies:
      - action:
          - 's3:GetObject'
        resource: mybucketname
    managed_policy_arns:
      - AmazonEKSWorkerNodePolicy
"""
        }

        actual = lambda_handler(event, None)

        self.assertEqual(actual, None)
