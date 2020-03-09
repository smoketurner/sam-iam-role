#!/usr/bin/env python
# -*- coding: utf-8 -*-

from parliament.misc import make_list

DENIED_SERVICES = {
    "cloudhsm",  # AWS CloudHSM
    "signer",  # AWS Code Signing for Amazon FreeRTOS
    "comprehendmedical",  # Comprehend Medical
    "deeplens",  # AWS DeepLens
    "deepracer",  # AWS DeepRacer
    "freertos",  # Amazon FreeRTOS
    "gamelift",  # Amazon GameLift
    "groundstation",  # AWS Ground Station
    "robomaker",  # AWS RoboMaker
    "workdocs",  # Amazon WorkDocs
    "worklink",  # Amazon WorkLink
    "workmail",  # Amazon WorkMail
    "workmailmessageflow",  # Amazon WorkMail Message Flow
    "workspaces",  # Amazon WorkSpaces
    "wam",  # Amazon WorkSpaces Application Manager
}


def audit(policy):
    services = set()
    for stmt in policy.statements:
        actions = make_list(stmt.stmt["Action"])
        for action in actions:
            prefix = action.split(":")[0]
            if prefix == "*":
                continue
            services.add(prefix.lower())

    print(f"SERVICES: {services}")

    denied_services_in_policy = []
    for service in services:
        if service in DENIED_SERVICES:
            denied_services_in_policy.append(service)

    if denied_services_in_policy:
        policy.add_finding(
            "DENIED_SERVICE",
            "Services are not approved for use",
            location={"Action": denied_services_in_policy},
        )
