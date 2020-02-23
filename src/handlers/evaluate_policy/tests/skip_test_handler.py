#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from handler import lambda_handler
from evaluate_policy.exceptions import InvalidRoleException


class HandlerTest(unittest.TestCase):
    def test_handler_no_roles(self):
        event = ""

        with self.assertRaises(Exception) as cm:
            lambda_handler(event, None)

        actual = str(cm.exception)
        self.assertEqual(actual, "No roles found")

    def test_handler_invalid_yaml(self):
        event = '""hi'

        with self.assertRaises(InvalidRoleException) as cm:
            lambda_handler(event, None)

        actual = cm.exception
        self.assertEqual(actual, None)

    def test_handler_load_json(self):
        event = '{"key":"value"}'

        with self.assertRaises(InvalidRoleException) as cm:
            lambda_handler(event, None)

        actual = cm.exception
        self.assertEqual(actual.errors, None)

    def test_handler(self):
        event = """
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

        actual = lambda_handler(event, None)

        self.assertEqual(actual, None)
