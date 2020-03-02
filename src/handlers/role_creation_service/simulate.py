#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os

import boto3
from parliament import expand_action
from parliament.misc import make_list

from .logger import configure_logger
from .sts import STS

EXECUTION_ROLE_NAME = os.environ.get("EXECUTION_ROLE_NAME")
LOGGER = configure_logger(__name__)

sts = STS()


def simulate_statement(client, account_id: str, statement: dict) -> bool:
    """
    Simulate an individual policy statement using the SimulateCustomPolicy API
    """

    actions = make_list(statement.get("Action", []))
    resources = make_list(statement.get("Resource", []))
    if not resources:
        resources = ["*"]
    if len(resources) > 1 and "*" in resources:
        resources.remove("*")

    all_actions = set()
    for action in actions:
        for expanded_action in expand_action(action, raise_exceptions=False):
            new_action = expanded_action["service"] + ":" + expanded_action["action"]
            all_actions.add(new_action)

    policies = [json.dumps({"Version": "2012-10-17", "Statement": statement})]

    response = client.simulate_custom_policy(
        PolicyInputList=policies,
        ActionNames=sorted(actions),
        ResourceArns=resources,
        ResourceOwner=f"arn:aws:iam::{account_id}:root",
    )

    print(f"response = {response}")

    results = response["EvaluationResults"][0]
    is_org_allowed = results.get("OrganizationDecisionDetail", {}).get(
        "AllowedByOrganizations"
    )
    is_boundary_allowed = results.get("PermissionsBoundaryDecisionDetail", {}).get(
        "AllowedByPermissionsBoundary"
    )
    print(f"is_org_allowed={is_org_allowed}, is_boundary_allowed={is_boundary_allowed}")
    return True


def simulate_role(account_id: str, role) -> bool:
    """
    Simulate an IAM policy in a target account
    """

    if not account_id:
        return False
    if not role:
        return False

    policy = role.get_inline_policy()
    if not policy:
        return False

    role_arn = f"arn:aws:iam::{account_id}:role/{EXECUTION_ROLE_NAME}"
    sts_role = sts.assume_cross_account_role(role_arn, "rcs-simulate-policy")

    client = sts_role.client("iam")
    statements = make_list(policy.get("PolicyDocument", {}).get("Statement", []))
    for statement in statements:
        simulate_statement(client, account_id, statement)

    return True
