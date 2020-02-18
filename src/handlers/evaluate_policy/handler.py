#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

from parliament import analyze_policy_string
import yaml


LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)


def load_file_to_set(filename):
    with open(filename, "r") as fp:
        rows = fp.read().splitlines()
    return {*rows}


def load_file_to_string(filename):
    with open(filename, "r") as fp:
        data = fp.read()
    return data


MANAGED_ARN_WHITELIST = load_file_to_set("managed_arn_whitelist.txt")
LOGGER.info(f"Loaded {len(MANAGED_ARN_WHITELIST)} managed policy ARNs from whitelist")

MANAGED_ARN_BLACKLIST = load_file_to_set("managed_arn_blacklist.txt")
LOGGER.info(f"Loaded {len(MANAGED_ARN_BLACKLIST)} managed policy ARNs from blaclist")


def analyze_policy(policy):
    analyzed_policy = analyze_policy_string(policy)
    for finding in analyzed_policy.findings:
        LOGGER.info(f"finding: {finding}")


def lambda_handler(event, _):
    LOGGER.info(f"event: {event}")

    roles = load_file_to_string("sample_roles.yml")
    LOGGER.debug(f"roles: {roles}")

    try:
        roles = yaml.safe_load(roles)
    except yaml.ParserError:
        raise Exception("Unable to parse YAML roles")

    LOGGER.debug(f"roles: {roles}")

    if not roles:
        raise Exception("No roles found in request")

    for role in roles:
        managed_policy_arns = role.get("managed_policy_arns", [])
        if managed_policy_arns:
            pass
