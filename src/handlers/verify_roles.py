#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

import boto3

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

    role_arn = f"arn:aws:iam::{account_id}:role/{EXECUTION_ROLE_NAME}"
    role = sts.assume_cross_account_role(role_arn, "rcs-role-verify")

    client = role.client("iam")

    options = {"Path": "/rcs/"}

    response = client.get_roles()
