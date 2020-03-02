#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
STS module

https://github.com/awslabs/aws-deployment-framework/blob/v3.0.1/src/lambda_codebase/initial_commit/bootstrap_repository/adf-build/shared/python/sts.py
"""

import boto3


class STS:
    def __init__(self):
        self.client = boto3.client("sts")

    def assume_cross_account_role(self, role_arn, role_session_name):
        """
        Assumes a role in another account and returns the temporary credentials
        """

        response = self.client.assume_role(
            RoleArn=role_arn, RoleSessionName=role_session_name
        )

        return boto3.Session(
            aws_access_key_id=response["Credentials"]["AccessKeyId"],
            aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
            aws_session_token=response["Credentials"]["SessionToken"],
        )

