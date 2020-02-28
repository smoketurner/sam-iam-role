#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

import boto3

from .logger import configure_logger

EXECUTION_ROLE_NAME = os.environ["EXECUTION_ROLE_NAME"]
LOGGER = configure_logger(__name__)


def assume_cross_account_role(account_id, session_name):
    role_arn = f"arn:aws:iam::{account_id}:role/{EXECUTION_ROLE_NAME}"

    client = boto3.client("sts")
    response = client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    LOGGER.debug(f"Role '{EXECUTION_ROLE_NAME}' has bee assumed for {account_id}")
    return boto3.Session(
        aws_access_key_id=response["Credentials"]["AccessKeyId"],
        aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
        aws_session_token=response["Credentials"]["SessionToken"],
    )


def simulate_policy(account_id, policies=None, actions=None, resources=None):
    role = assume_cross_account_role(account_id, "rcs-simulate-policy")

    client = role.client("iam")
    response = client.simulate_custom_policy(
        PolicyInputList=policies, ActionNames=actions, ResourceArns=resources
    )

    results = response["EvaluationResults"][0]
    is_org_allowed = results.get("OrganizationDecisionDetail", {}).get(
        "AllowedByOrganizations"
    )
    is_boundary_allowed = results.get("PermissionsBoundaryDecisionDetail", {}).get(
        "AllowedByPermissionsBoundary"
    )
