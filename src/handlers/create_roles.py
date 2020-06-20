#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os

import boto3

from role_creation_service.cloudformation import CloudFormation
from role_creation_service.logger import configure_logger
from role_creation_service.role import Role
from role_creation_service.sts import STS

EXECUTION_ROLE_NAME = os.environ.get("EXECUTION_ROLE_NAME")

LOGGER = configure_logger(__name__)

sts = STS()


def create_template_body(roles: list) -> str:
    """
    Create the IAM role CloudFormation template
    """
    template_body = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "IAM roles created by the Role Creation Service",
    }

    resources = {}

    for role_dict in roles:
        role = Role(role_dict)
        resource = role.to_cf_json()
        resources = {**resources, **resource}

    template_body["Resources"] = resources

    params = {"indent": None, "sort_keys": True, "separators": (",", ":")}
    return json.dumps(template_body, **params)


def lambda_handler(event, _):
    LOGGER.info(f"event: {event}")

    account_id = event.get("account_id")
    if not account_id:
        raise Exception("account_id not found in request")

    region = event.get("region")
    if not region:
        raise Exception("region not found in request")

    stack_name = event.get("stack_name")
    if not region:
        raise Exception("stack_name not found in request")

    roles = event.get("roles")
    if not roles:
        raise Exception("roles not found in request")

    role_arn = f"arn:aws:iam::{account_id}:role/{EXECUTION_ROLE_NAME}"
    role = sts.assume_cross_account_role(role_arn, "rcs-role-create")

    cloudformation = CloudFormation(
        region,
        role,
        template_body=create_template_body(roles),
        stack_name=stack_name,
        account_id=account_id,
    )
    cloudformation.create_stack()
