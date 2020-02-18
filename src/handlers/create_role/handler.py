#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import os

import boto3

EXECUTION_ROLE_NAME = os.environ["EXECUTION_ROLE_NAME"]

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


def assume_role(account_id):
    options = {
        "RoleArn": f"arn:aws:iam::{account_id}:role/{EXECUTION_ROLE_NAME}",
        "RoleSessionName": "rcs-role-create",
    }

    sts_client = boto3.client("sts")
    response = sts_client.assume_role(**options)
    return response["Credentials"]


def lambda_handler(event, _):
    LOGGER.info(f"event: {event}")

    account_id = event.get("AccountId")
    if not account_id:
        raise Exception("AccountId not found in request")

    credentials = assume_role(account_id)
    if not credentials:
        raise Exception(
            f"Unable to assume role '{EXECUTION_ROLE_NAME}' in account {account_id}"
        )

    iam_client = boto3.client("iam")

    response = iam_client.create_role()
