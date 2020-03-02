#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

import boto3

from role_creation_service.cloudformation import CloudFormation
from role_creation_service.logger import configure_logger
from role_creation_service.sts import STS

EXECUTION_ROLE_NAME = os.environ.get("EXECUTION_ROLE_NAME")

LOGGER = configure_logger(__name__)

sts = STS()


def lambda_handler(event, _):
    LOGGER.info(f"event: {event}")

    account_id = event.get("AccountId")
    if not account_id:
        raise Exception("AccountId not found in request")

    region = event.get("Region")
    if not region:
        raise Exception("Region not found in request")

    stack_name = event.get("StackName")
    if not region:
        raise Exception("StackName not found in request")

    template_body = event.get("TemplateBody")
    if not template_body:
        raise Exception("TemplateBody not found in request")

    role_arn = f"arn:aws:iam::{account_id}:role/{EXECUTION_ROLE_NAME}"
    role = sts.assume_cross_account_role(role_arn, "rcs-role-create")

    cloudformation = CloudFormation(
        region,
        role,
        template_body=template_body,
        stack_name=stack_name,
        account_id=account_id,
    )
    cloudformation.create_stack()
