#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import os

import boto3

from create_role.cloudformation import CloudFormation

EXECUTION_ROLE_NAME = os.environ["EXECUTION_ROLE_NAME"]

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


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

    role = assume_cross_account_role(account_id, "rcs-role-create")

    cloudformation = CloudFormation(
        region,
        role,
        template_body=template_body,
        stack_name=stack_name,
        account_id=account_id,
    )
    cloudformation.create_stack()
