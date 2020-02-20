#!/usr/bin/env python
# -*- coding: utf-8 -*-

from dataclasses import dataclass, field
import os
import json
import logging
from typing import List

from evaluate_policy.utils import load_file_to_set, load_file_to_dict

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)


MANAGED_ARN_BLACKLIST = load_file_to_set(
    "src/handlers/evaluate_policy/managed_arn_blacklist.txt"
)
LOGGER.info(f"Loaded {len(MANAGED_ARN_BLACKLIST)} managed policy ARNs from blacklist")

MANAGED_ARN_WHITELIST = load_file_to_set(
    "src/handlers/evaluate_policy/managed_arn_whitelist.txt"
)
LOGGER.info(f"Loaded {len(MANAGED_ARN_WHITELIST)} managed policy ARNs from whitelist")

ACTION_BLACKLIST = load_file_to_set("src/handlers/evaluate_policy/action_blacklist.txt")
LOGGER.info(f"Loaded {len(ACTION_BLACKLIST)} actions from blacklist")


class InvalidRoleException(Exception):
    def __init__(self, errors, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.errors = errors


@dataclass(frozen=True)
class Role:

    name: str
    principal: dict = field(default_factory=dict)
    policies: List[dict] = field(default_factory=list)
    managed_policy_arns: List[str] = field(default_factory=list)

    @classmethod
    def validate_policy(cls, policy):
        actions = policy.get("action", [])
        if isinstance(actions, str):
            actions = [actions]

        for action in actions:
            if action in ACTION_BLACKLIST:
                cls.errors.append(f"Policy action '{action}' is not approved for use")

        policy_data = {
            "Effect": "Allow",
            "Action": policy.get("action", []),
            "Resource": policy.get("resource"),
        }
        return policy_data

    @classmethod
    def load(cls, data):
        missing = []
        errors = []

        if not data:
            errors.append("No role found")
            raise InvalidRoleException(errors)

        name = data.get("name")
        if not name:
            missing.append("name")

        settings = data.get("settings", {})
        if not settings:
            missing.append("settings")

        if "principal_service" in settings:
            principal = {
                "Service": settings.get("principal_service") + ".amazonaws.com"
            }
        elif "principal_aws" in settings:
            principal = {"AWS": settings.get("principal_aws")}
        else:
            missing.append("principal_service or principal_aws")

        if missing:
            errors.append("Missing required fields: " + ", ".join(missing))

        policies = []
        for policy_name in settings.get("policies", []):
            try:
                policy_data = load_file_to_dict(f"policies/{policy_name}.json")
                policies.append(policy_data)
            except Exception:
                errors.append(f"Policy '{policy_name}' not found")

        for policy in settings.get("additional_policies", []):
            policies.append(cls.validate_policy(policy))

        managed_policy_arns = []
        for policy_name in settings.get("managed_policy_arns", []):
            if policy_name in MANAGED_ARN_BLACKLIST:
                errors.append(
                    f"Managed policy ARN {policy_name} is not approved for use"
                )

            managed_policy_arns.append(f"arn:aws:iam::aws:policy/{policy_name}")

        if not policies or not managed_policy_arns:
            errors.append("No policies or managed_policy_arns found")

        if errors:
            raise InvalidRoleException(errors)

        return cls(name, principal, policies, managed_policy_arns)

    def to_json(self) -> dict:
        role = {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": self.name,
                "Description": "DO NOT DELETE - Created by Role Creation Service. Created by CloudFormation ${AWS::StackId}",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Principal": self.principal,
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
            },
        }

        if self.policies:
            role["Properties"]["Policies"] = self.policies
        if self.managed_policy_arns:
            role["Properties"]["ManagedPolicyArns"] = self.managed_policy_arns

        return role

    def __str__(self):
        return f"{self.name}"
