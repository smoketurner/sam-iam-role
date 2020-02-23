#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import logging

import yaml

from evaluate_policy.role import Role
from evaluate_policy.exceptions import InvalidRoleException
from evaluate_policy.utils import load_file_to_string, load_file_to_set


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


def lambda_handler(event, _):
    LOGGER.debug(f"event: {event}")

    roles = event.get("roles")
    if not roles:
        raise Exception("No roles found in request")

    try:
        roles = yaml.safe_load(roles)
    except yaml.YAMLError as ex:
        raise Exception(f"YAML parsing error: {ex}")

    print(f"roles: {roles}")

    if not isinstance(roles, list):
        raise Exception("No roles found found in request")

    findings = []

    for role_dict in roles:
        role = Role(role_dict)
        findings.extend(role.findings)

    if findings:
        LOGGER.error(
            "Correct the resource restriction or contact the Cloud Enablement team for assistance."
        )

