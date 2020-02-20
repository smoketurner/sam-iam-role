#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging

from parliament import analyze_policy_string
import yaml

from evaluate_policy.role import Role, InvalidRoleException
from evaluate_policy.utils import load_file_to_string


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)


def lambda_handler(event, _):
    LOGGER.info(f"event: {event}")

    roles = load_file_to_string("sample_roles.yml")

    try:
        roles = yaml.safe_load(roles)
    except yaml.ParserError:
        raise Exception("Unable to parse YAML roles")

    LOGGER.debug(f"roles: {roles}")

    if not roles:
        raise Exception("No roles found in request")

    for role in roles:
        try:
            role_obj = Role.load(role)
        except InvalidRoleException as ex:
            for error in ex.errors:
                LOGGER.error(error)
            LOGGER.error(
                "Correct the resource restriction or contact the Cloud Enablement team for assistance."
            )

        for policy in role_obj.policies:
            policy_doc = json.dumps(policy)

            analyzed_policy = analyze_policy_string(policy_doc)
            for finding in analyzed_policy.findings:
                LOGGER.warn(f"finding: {finding}")
