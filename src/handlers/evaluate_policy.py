#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import yaml
import yamale

from role_creation_service.role import Role
from role_creation_service.logger import configure_logger
from role_creation_service.simulate import simulate_policies


LOGGER = configure_logger(__name__)


def validate_yaml(input: str) -> list:
    """
    Validate the input YAML data in the request
    """

    if not input:
        return None

    try:
        raw_data = yaml.safe_load(input)
    except yaml.YAMLError:
        LOGGER.exception("YAML parsing error")
        return None

    # format yamale.validate() is expecting
    data = [(raw_data, None)]

    schema_file = os.path.dirname(os.path.realpath(__file__)) + "/schema.yml"
    schema = yamale.make_schema(schema_file)

    try:
        data = yamale.validate(schema, data, strict=True)
    except ValueError:
        LOGGER.exception("YAML validation error")
        return None

    if not isinstance(raw_data, list):
        LOGGER.error("Request data is not a list")
        return None

    return raw_data


def lambda_handler(event, context=None):
    LOGGER.debug(f"event: {event}")

    if not event:
        LOGGER.error("No event found in request")
        return {"result": "UNSUPPORTED"}

    role_type = event.get("type")
    if role_type != "iam":
        return {"result": "UNSUPPORTED"}

    account_id = event.get("account_id")
    region = event.get("region")

    roles = validate_yaml(event.get("roles"))
    if not roles:
        return {"result": "NON_COMPLIANT"}

    all_findings = []

    for role_dict in roles:
        role = Role(role_dict, region, account_id)

        analyzed_polices = role.analyze_policies()

        for analyzed_policy in analyzed_polices:
            all_findings.extend(analyzed_policy.findings)

        if not all_findings:
            simulate_policies(account_id, analyzed_polices)

    if all_findings:
        for finding in all_findings:
            LOGGER.error(str(finding))
        return {"result": "NON_COMPLIANT"}

    return {"result": "COMPLIANT"}
