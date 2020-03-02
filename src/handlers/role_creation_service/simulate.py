#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os

from parliament import expand_action
from parliament.finding import Finding
from parliament.misc import make_list

from .logger import configure_logger
from .sts import STS

EXECUTION_ROLE_NAME = os.environ.get("EXECUTION_ROLE_NAME")
LOGGER = configure_logger(__name__)

sts = STS()


def simulate_statement(client, account_id: str, statement: object) -> list:
    """
    Simulate a policy statement using the SimulateCustomPolicy API
    """

    all_actions = set()
    actions = make_list(statement.stmt.get("Action", []))
    for action in actions:
        expanded_actions = expand_action(action, raise_exceptions=False)
        for action_struct in expanded_actions:
            all_actions.add(action_struct["service"] + ":" + action_struct["action"])

    resources = make_list(statement.stmt.get("Resource", []))
    if not resources:
        resources = ["*"]
    if len(resources) > 1 and "*" in resources:
        resources.remove("*")

    policies = [json.dumps({"Version": "2012-10-17", "Statement": statement.stmt})]

    response = client.simulate_custom_policy(
        PolicyInputList=policies,
        ActionNames=sorted(all_actions),
        ResourceArns=resources,
        ResourceOwner=f"arn:aws:iam::{account_id}:root",
    )

    print(f"response = {response}")

    findings = []

    results = response["EvaluationResults"][0]
    is_org_allowed = results.get("OrganizationDecisionDetail", {}).get(
        "AllowedByOrganizations"
    )
    if is_org_allowed is False:
        findings.append(Finding("DENIED_POLICY",))

    is_boundary_allowed = results.get("PermissionsBoundaryDecisionDetail", {}).get(
        "AllowedByPermissionsBoundary"
    )
    print(f"is_org_allowed={is_org_allowed}, is_boundary_allowed={is_boundary_allowed}")
    return True


def simulate_policies(account_id: str, polices: list) -> bool:
    """
    Simulate an IAM policy in a target account
    """

    if not account_id:
        return False
    if not polices:
        return False

    role_arn = f"arn:aws:iam::{account_id}:role/{EXECUTION_ROLE_NAME}"
    sts_role = sts.assume_cross_account_role(role_arn, "rcs-simulate-policy")

    client = sts_role.client("iam")
    for policy in polices:
        for statement in policy.statements:
            simulate_statement(client, account_id, statement)

    return True
