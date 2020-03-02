#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import sys

from parliament import analyze_policy_string
from parliament.misc import make_list
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
        principal = make_list(
            self.role_dict.get("settings", {}).get("principal_service", [])
        )
        if not principal:
            return []
        return principal

    def _update_statements(self, statements: list, is_cf=False) -> list:
        """
        Replace partition, region and account ID placeholders in resources
        with specific values.
        """

        if not statements:
            return []

        updated = []
        for statement in statements:
            resources = make_list(statement.get("Resource", []))

            statement["Resource"] = []

            for resource in resources:
                if is_cf:
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

    def get_default_policies(self, is_cf=False) -> list:
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
                    statements, is_cf=is_cf
                )

                policies.append(policy_data)
            except FileNotFoundError:
                LOGGER.error(f"{DEFAULT_POLICY_NAME} for {service} not found")

        return policies

    def get_inline_policy(self, is_cf=False) -> dict:
        """
        Returns all of the inline statements as an inline policy
        """
        settings = self.role_dict.get("settings")
        if not settings:
            return {}

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

        if not statements:
            return {}

        policy_doc = {
            "PolicyName": "inline_policy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": self._update_statements(statements, is_cf=is_cf),
            },
        }

        return policy_doc

    def get_policies(self, return_policy_docs=False, is_cf=False) -> list:
        """
        Assemble all of the policies defined in the role

        Returns a list of policy dictionaries
        """
        settings = self.role_dict.get("settings")
        if not settings:
            return []

        policies = []
        for policy_name in settings.get("policies", []):
            if policy_name == DEFAULT_POLICY_NAME:
                policies.extend(self.get_default_policies(is_cf=is_cf))

        inline_policy = self.get_inline_policy(is_cf=is_cf)
        if inline_policy:
            policies.append(inline_policy)

        if return_policy_docs:
            return [policy.get("PolicyDocument", {}) for policy in policies]

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

        Return list of Policy objects
        """
        findings = self.analyze_managed_policies()

        policies = self.get_policies(return_policy_docs=True)
        if not policies:
            return findings

        custom_path = os.path.dirname(os.path.realpath(__file__)) + "/private_auditors"

        analyzed_polices = []
        for policy in policies:
            analyzed_policy = analyze_policy_string(
                json.dumps(policy),
                ignore_private_auditors=True,
                private_auditors_custom_path=custom_path,
                include_community_auditors=include_community_auditors,
            )
            analyzed_polices.append(analyzed_policy)

        return analyzed_polices

    def to_cf_json(self, whitespace=False) -> str:
        """
        Return the role as a CloudFormation JSON template
        """
        assume_statement = {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": {},
        }

        settings = self.role_dict["settings"]

        principal_service = self.principal_service

        if principal_service:
            assume_statement["Principal"]["Service"] = [
                principal + ".amazonaws.com" for principal in principal_service
            ]

        if "principal_aws" in settings:
            assume_statement["Principal"]["AWS"] = settings["principal_aws"]
        if "principal_canonical_user" in settings:
            assume_statement["Principal"]["CanonicalUser"] = settings[
                "principal_canonical_user"
            ]
        if "principal_federated" in settings:
            assume_statement["Principal"]["Federated"] = settings["principal_federated"]

        role = {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [assume_statement],
                },
                "Description": {
                    "Fn::Sub": "DO NOT DELETE - Created by Role Creation Service. Created by CloudFormation ${AWS::StackId}"
                },
                "Path": "/rcs/",
                "RoleName": self.role_dict["name"],
            },
        }

        policies = self.get_policies(is_cf=True)
        if policies:
            role["Properties"]["Policies"] = policies

        managed_policy_arns = settings.get("managed_policy_arns", [])
        if managed_policy_arns:
            role["Properties"]["ManagedPolicyArns"] = [
                {"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/" + policy}
                for policy in managed_policy_arns
            ]

        if whitespace:
            params = {"indent": 2, "sort_keys": True, "separators": (", ", ": ")}
        else:
            params = {"indent": None, "sort_keys": True, "separators": (",", ":")}

        return json.dumps(role, **params)

    def __str__(self):
        return self.to_cf_json(whitespace=True)
