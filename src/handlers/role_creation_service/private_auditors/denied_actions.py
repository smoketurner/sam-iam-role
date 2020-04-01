#!/usr/bin/env python
# -*- coding: utf-8 -*-

DENIED_ACTIONS = {
    "access-analyzer:DeleteAnalyzer",
    "cloudtrail:CreateTrail",
    "cloudtrail:DeleteTrail",
    "cloudtrail:UpdateTrail",
    "cloudtrail:StopLogging",
    "config:DeleteConfigRule",
    "config:DeleteConfigurationRecorder",
    "config:DeleteDeliveryChannel",
    "config:StopConfigurationRecorder",
    "ec2:AcceptVpcPeeringConnection",
    "ec2:AttachInternetGateway",
    "ec2:AttachVpnGateway",
    "ec2:CreateInternetGateway",
    "ec2:CreateEgressOnlyInternetGateway",
    "ec2:CreateNatGateway",
    "ec2:CreateTransitGateway",
    "ec2:CreateVpnConnection",
    "ec2:CreateVpnGateway",
    "ec2:CreateVpcPeeringConnection",
    "ec2:DeleteEgressOnlyInternetGateway",
    "ec2:DeleteInternetGateway",
    "ec2:DeleteNatGateway",
    "ec2:DeleteTransitGateway",
    "ec2:DetachClassicLinkVpc",
    "ec2:DetachInternetGateway",
    "ec2:DetachVpnGateway",
    "ec2:DisableEbsEncryptionByDefault",
    "ec2:ModifyInstanceMetadataOptions",
    "globalaccelerator:CreateAccelerator",
    "globalaccelerator:CreateEndpointGroup",
    "globalaccelerator:CreateListener",
    "globalaccelerator:UpdateAccelerator",
    "globalaccelerator:UpdateAcceleratorAttributes",
    "globalaccelerator:UpdateEndpointGroup",
    "globalaccelerator:UpdateListener",
    "guardduty:DeleteDetector",
    "guardduty:DisassociateFromMasterAccount",
    "guardduty:UpdateDetector",
    "guardduty:CreateFilter",
    "guardduty:CreateIPSet",
    "organizations:LeaveOrganization",
    "s3:PutAccountPublicAccessBlock",
}


def audit(policy):
    actions = policy.get_allowed_actions()
    print(f"ACTIONS: {actions}")

    denied_actions_in_policy = []
    for action in actions:
        if action in DENIED_ACTIONS:
            denied_actions_in_policy.append(action)

    if denied_actions_in_policy:
        policy.add_finding(
            "DENIED_ACTIONS",
            "APIs are not approved for use:",
            location={"Action": denied_actions_in_policy},
        )
