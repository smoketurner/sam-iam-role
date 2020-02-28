#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import sys

from parliament import analyze_policy_string
from parliament.finding import Finding

from .logger import configure_logger
from .utils import load_file_to_set, load_file_to_dict

LOGGER = configure_logger(__name__)
MANAGED_ARN_WHITELIST = load_file_to_set("managed_arn_whitelist.txt")
LOGGER.info(f"Loaded {len(MANAGED_ARN_WHITELIST)} managed policy ARNs from whitelist")


DEFAULT_POLICY_NAME = "default_role_policy"


class Role:
    role_dict = None
    region = None
    account_id = None
    partition = None

    def __init__(self, role_dict: dict, region=None, account_id=None, partition=None):
        self.role_dict = role_dict
        self.region = region or "*"
        self.account_id = account_id or "*"
        self.partition = partition or "aws"

    @property
    def principal_service(self) -> list:
        """
        Return any service principals from the role
        """
        principal = self.role_dict.get("settings", {}).get("principal_service", [])
        if not principal:
            return []
        if not isinstance(principal, list):
            principal = [principal]
        return principal

    def _update_statements(self, statements: list, cf_sub_func=False) -> list:
        """
        Replace partition, region and account ID placeholders in resources
        with specific values.
        """

        if not statements:
            return []

        updated = []
        for statement in statements:
            resources = statement.get("Resource", [])
            if not isinstance(resources, list):
                resources = [resources]

            statement["Resource"] = []

            for resource in resources:
                if cf_sub_func:
                    if "AWS::" in resource:
                        resource = {"Fn::Sub": resource}
                else:
                    resource = (
                        resource.replace("${AWS::Partition}", self.partition)
                        .replace("${AWS::Region}", self.region)
                        .replace("${AWS::AccountId}", self.account_id)
                    )
                statement["Resource"].append(resource)
            updated.append(statement)

        return updated

    def get_default_policies(self, cf_sub_func=False) -> list:
        """
        Return the list of default policies for the role

        Returns a list of dictionaries
        """
        policies = []
        for service in self.principal_service:
            try:
                policy_data = load_file_to_dict(
                    f"default_role_policies/{service}_policy.json"
                )

                statements = policy_data.get("PolicyDocument", {}).get("Statement", [])
                policy_data["PolicyDocument"]["Statement"] = self._update_statements(
                    statements, cf_sub_func=cf_sub_func
                )

                policies.append(policy_data)
            except FileNotFoundError:
                LOGGER.error(f"{DEFAULT_POLICY_NAME} for {service} not found")

        return policies

    def get_policies(self, cf_sub_func=False) -> list:
        """
        Assemble all of the policies defined in the role

        Returns a list of policy dictionaries
        """
        settings = self.role_dict.get("settings")
        if not settings:
            return []

        principal_service = self.principal_service

        policies = []
        for policy_name in settings.get("policies", []):
            if policy_name == DEFAULT_POLICY_NAME:
                policies.extend(self.get_default_policies(cf_sub_func=cf_sub_func))

        statements = []
        for policy in settings.get("additional_policies", []):
            statement = {"Effect": policy.get("effect", "Allow")}
            if "action" in policy:
                statement["Action"] = policy["action"]
            if "condition" in policy:
                statement["Condition"] = policy["condition"]
            if "resource" in policy:
                statement["Resource"] = policy["resource"]
            statements.append(statement)

        if statements:
            policy_doc = {
                "PolicyName": "inline_policy",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": self._update_statements(
                        statements, cf_sub_func=cf_sub_func
                    ),
                },
            }
            policies.append(policy_doc)

        return policies

    def analyze_managed_policies(self) -> list:
        """
        Returning managed policy ARNs not approved for use
        """
        managed_policy_arns = self.role_dict.get("settings", {}).get(
            "managed_policy_arns", []
        )
        if not managed_policy_arns:
            return []

        denied_policies = []
        for managed_policy in managed_policy_arns:
            if managed_policy not in MANAGED_ARN_WHITELIST:
                denied_policies.append(managed_policy)

        findings = []
        if denied_policies:
            findings.append(
                Finding(
                    "DENIED_POLICIES",
                    "Managed policies are not approved for use",
                    {"managed_policy_arns": denied_policies},
                )
            )
        return findings

    def analyze_policies(self, include_community_auditors=False) -> list:
        """
        Analyze the policies on the role
        """
        findings = self.analyze_managed_policies()

        policies = self.get_policies()
        if not policies:
            return findings

        policy_docs = [
            json.dumps(policy.get("PolicyDocument", {})) for policy in policies
        ]

        custom_path = os.path.dirname(os.path.realpath(__file__)) + "/private_auditors"

        for policy_doc in policy_docs:
            analyzed_policy = analyze_policy_string(
                policy_doc,
                ignore_private_auditors=True,
                private_auditors_custom_path=custom_path,
                include_community_auditors=include_community_auditors,
            )
            findings.extend(analyzed_policy.findings)

        return findings
