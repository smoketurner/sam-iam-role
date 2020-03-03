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

DENY_RESULT = ("implicitDeny", "explicitDeny")


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

    LOGGER.info(f"SimulateResponse = {response}")

    findings = []

    for result in response.get("EvaluationResults", []):

        is_org_allowed = result.get("OrganizationDecisionDetail", {}).get(
            "AllowedByOrganizations"
        )
        is_boundary_allowed = result.get("PermissionsBoundaryDecisionDetail", {}).get(
            "AllowedByPermissionsBoundary"
        )

        action = result.get("EvalActionName")
        is_action_denied = result.get("EvalDecision", "implicitDeny") in DENY_RESULT
        if is_action_denied:
            if is_org_allowed is False:
                findings.append(
                    Finding(
                        "DENIED_POLICY",
                        detail=f"API {action} was denied by an organizational policy",
                        location={"Action": action},
                    )
                )
            elif is_boundary_allowed is False:
                findings.append(
                    Finding(
                        "DENIED_POLICY",
                        detail=f"API {action} was denied by a permission boundary policy",
                        location={"Action": action},
                    )
                )
            else:
                findings.append(
                    Finding(
                        "DENIED_POLICY",
                        detail=f"API {action} was denied because it is not in the approved API list",
                        location={"Action": action},
                    )
                )
            continue

        denied_resources = [
            resource
            for resource in result.get("ResourceSpecificResults", [])
            if resource.get("EvalResourceDecision", "implicitDeny") in DENY_RESULT
        ]

        if denied_resources:
            resource_names = [
                resource.get("EvalResourceName") for resource in denied_resources
            ]

            findings.append(
                Finding(
                    "DENIED_POLICY",
                    detail=f"API {action} was denied because the API is approved but not for the following resources requested:",
                    location={"Resource": resource_names},
                )
            )

    return findings


def simulate_policies(account_id: str, polices: list) -> list:
    """
    Simulate an IAM policy in a target account
    """

    if not account_id:
        return []
    if not polices:
        return []

    role_arn = f"arn:aws:iam::{account_id}:role/{EXECUTION_ROLE_NAME}"
    sts_role = sts.assume_cross_account_role(role_arn, "rcs-simulate-policy")

    all_findings = []
    client = sts_role.client("iam")
    for policy in polices:
        for statement in policy.statements:
            findings = simulate_statement(client, account_id, statement)
            all_findings.extend(findings)

    return all_findings
