#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import logging
import pkg_resources

from parliament import analyze_policy_string
from parliament.finding import Finding

from .utils import load_file_to_set, load_file_to_dict

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

MANAGED_ARN_WHITELIST = load_file_to_set("managed_arn_whitelist.txt")
LOGGER.info(f"Loaded {len(MANAGED_ARN_WHITELIST)} managed policy ARNs from whitelist")


class Role:
    _findings = []
    role_dict = None
    policies = []
    analyzed_policies = []
    managed_policy_arns = []

    def __init__(self, role_dict, filepath=None):
        self._findings = []
        self.role_dict = role_dict
        self.policies = []
        self.analyzed_policies = []
        self.managed_policy_arns = []
        self.filepath = filepath

    def add_finding(self, finding, detail="", location={}):
        if "filepath" not in location:
            location["filepath"] = self.filepath
        self._findings.append(Finding(finding, detail, location))

    @property
    def findings(self):
        all_findings = []
        all_findings.extend(self._findings)

        for policy in self.analyzed_policies:
            for finding in policy.findings:
                if "filepath" not in finding.location:
                    finding.location["filepath"] = self.filepath

                all_findings.append(finding)

        return all_findings

    @property
    def is_valid(self):
        for policy in self.analyzed_policies:
            if not policy.is_valid:
                return False
        return True

    def analyze(self):
        """
        Returns False if this role is so broken that it couldn't be analyzed further.
        On True, it may still have findings.

        In either case, it will create Findings if there are any.
        """

        # Check no unknown elements exist
        for element in self.role_dict:
            if element not in ["name", "settings"]:
                self.add_finding(
                    "MALFORMED",
                    detail="Role contains an unknown element",
                    location={"string": element},
                )
                return False

        # Check settings
        if "settings" not in self.role_dict:
            self.add_finding("MALFORMED", detail="Role contains no settings")
            return False

        settings = self.role_dict["settings"]

        # Check no unknown elements exist
        for element in settings:
            if element not in [
                "principal_service",
                "principal_aws",
                "principal_federated",
                "additional_policies",
                "policies",
                "managed_policy_arns",
            ]:
                self.add_finding(
                    "MALFORMED",
                    detail="Role settings contains an unknown element",
                    location={"string": element},
                )
                return False

        if (
            "principal_service" not in settings
            and "principal_aws" not in settings
            and "principal_federated" not in settings
        ):
            self.add_finding("MALFORMED", detail="Role contains no principal")

        principal_services = settings.get("principal_service", [])
        if not isinstance(principal_services, list):
            principal_services = [principal_services]

        for policy_name in settings.get("policies", []):
            if principal_services and policy_name == "default_role_policy":
                for principal in principal_services:
                    try:
                        policy_data = load_file_to_dict(
                            f"default_role_policies/{principal}_policy.json"
                        )
                        self.policies.append(policy_data)
                    except FileNotFoundError:
                        self.add_finding(
                            "UNKNOWN_POLICY",
                            detail="Role contains an unknown default principal policy",
                            location={"string": principal},
                        )

        statements = []

        for policy in settings.get("additional_policies", []):
            statement = {}
            statement["Effect"] = policy.get("effect", "Allow")
            if "action" in policy:
                statement["Action"] = policy["action"]
            if "condition" in policy:
                statement["Condition"] = policy["condition"]
            if "resource" in policy:
                statement["Resource"] = policy["resource"]
            if "not_resource" in policy:
                statement["NotResource"] = policy["not_resource"]
            statements.append(statement)

        if statements:
            policy_doc = {
                "PolicyName": "inline_policy",
                "PolicyDocument": {"Version": "2012-10-17", "Statement": statements},
            }
            self.policies.append(policy_doc)

        for policy in self.policies:
            policy_doc = json.dumps(policy["PolicyDocument"])
            analyzed_policy = analyze_policy_string(policy_doc)
            self.analyzed_policies.append(analyzed_policy)

        for policy_name in settings.get("managed_policy_arns", []):
            if policy_name not in MANAGED_ARN_WHITELIST:
                self.add_finding(
                    "UNAPPROVED_POLICY",
                    detail="Managed policy is not approved for use",
                    location={"string": policy_name},
                )
            else:
                self.managed_policy_arns.append(policy_name)

        if not self.policies and not self.managed_policy_arns:
            self.add_finding("MALFORMED", detail="Role contains no policies")

        return True

    def to_json(self, whitespace=False) -> str:
        assume_statement = {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": {},
        }

        settings = self.role_dict["settings"]

        principal_service = settings.get("principal_service", [])
        if not isinstance(principal_service, list):
            principal_service = [principal_service]

        if principal_service:
            assume_statement["Principal"]["Service"] = [
                principal + ".amazonaws.com" for principal in principal_service
            ]

        if "principal_aws" in settings:
            assume_statement["Principal"]["AWS"] = settings["principal_aws"]

        if "principal_federated" in settings:
            assume_statement["Principal"]["Federated"] = settings["principal_federated"]

        role = {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "Description": "DO NOT DELETE - Created by Role Creation Service. Created by CloudFormation ${AWS::StackId}",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [assume_statement],
                },
            },
        }

        if "name" in self.role_dict:
            role["Properties"]["RoleName"] = self.role_dict["name"]
        if self.policies:
            role["Properties"]["Policies"] = self.policies
        if self.managed_policy_arns:
            role["Properties"]["ManagedPolicyArns"] = self.managed_policy_arns

        if whitespace:
            params = {"indent": 2, "sort_keys": True, "separators": (", ", ": ")}
        else:
            params = {"indent": None, "sort_keys": True, "separators": (",", ":")}

        return json.dumps(role, **params)

    def __str__(self):
        return self.to_json()
