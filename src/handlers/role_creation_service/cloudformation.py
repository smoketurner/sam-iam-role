#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import os
import random

from botocore.config import Config
from botocore.exceptions import WaiterError, ClientError

from ..logger import configure_logger
from ..errors import InvalidTemplateError

LOGGER = configure_logger(__name__)
CFN_CONFIG = Config(retries=dict(max_attempts=10))
STACK_TERMINATION_PROTECTION = os.environ.get("TERMINATION_PROTECTION", False)


class CloudFormation:
    def __init__(
        self,
        region,
        role,
        template_body=None,
        parameters=None,
        wait=False,
        stack_name=None,
        account_id=None,
    ):
        self.client = role.client(
            "cloudformation", region_name=region, config=CFN_CONFIG
        )
        self.stack_name = stack_name
        self.parameters = parameters
        self.wait = wait
        self.account_id = account_id
        self.template_body = template_body

    def validate_template(self):
        try:
            return self.client.validate_template(TemplateBody=self.template_body)
        except ClientError as error:
            raise InvalidTemplateError(f"{error}")

    def _describe_change_set(self):
        try:
            return self.client.describe_change_set(
                ChangeSetName=self.stack_name, StackName=self.stack_name
            )
        except ClientError:
            return False

    def _get_waiter_type(self):
        return (
            "stack_update_complete"
            if self._get_change_set_type() == "UPDATE"
            else "stack_create_complete"
        )

    def _get_change_set_type(self):
        return "UPDATE" if self.get_stack_status() else "CREATE"

    def _wait_stack(self, waiter_type):
        waiter = self.client.get_waiter(waiter_type)
        LOGGER.info(
            f"{self.account_id} - Waiting for CloudFormation stack: {self.stack_name}"
            f" in {self.region} to reach {waiter_type}"
        )
        waiter.wait(
            StackName=self.stack_name,
            WaiterConfig={"Delay": CloudFormation._random_delay(), "MaxAttempts": 45},
        )

    def _wait_change_set(self):
        waiter = self.client.get_waiter("change_set_create_complete")

        LOGGER.debug(
            f"{self.account_id} - Determine CloudFormation Change Set:"
            f" {self.stack_name} in {self.region}"
        )

        waiter.wait(
            StackName=self.stack_name,
            ChangeSetName=self.stack_name,
            WaiterConfig={"Delay": CloudFormation._random_delay(), "MaxAttempts": 20},
        )

    def _create_change_set(self):
        """
        Creates a Cloudformation change set from a template
        """
        LOGGER.debug(
            f"{self.account_id} - calling _create_change_set for {self.stack_name}"
        )

        if not self.template_url:
            return False

        try:
            self.validate_template()
            self.client.create_change_set(
                StackName=self.stack_name,
                TemplateBody=self.template_body,
                Parameters=self.parameters,
                Capabilities=["CAPABILITY_NAMED_IAM",],
                Tags=[{"Key": "createdBy", "Value": "Role Creation Service"}],
                ChangeSetName=self.stack_name,
                ChangeSetType=self._get_change_set_type(),
            )
            self._wait_change_set()
            return True
        except ClientError as error:
            raise error
        except WaiterError as error:
            err = error.last_response
            if CloudFormation._change_set_failed_due_to_empty(
                err["Status"], err["StatusReason"]
            ):
                LOGGER.debug(
                    f"{self.account_id} - The submitted information does not contain changes."
                )
                self._delete_change_set()
                return False

            LOGGER.error(
                f'{self.account_id} - ERROR: {err["StatusReason"]}', exc_info=1,
            )
            self._delete_change_set()
            raise

    @staticmethod
    def _change_set_failed_due_to_empty(status, reason):
        return (
            status == "FAILED"
            and "The submitted information didn't contain changes." in reason
            or "No updates are to be performed" in reason
        )

    def _update_stack_termination_protection(self):
        try:
            return self.client.update_termination_protection(
                EnableTerminationProtection=STACK_TERMINATION_PROTECTION == "True",
                StackName=self.stack_name,
            )
        except ClientError as error:
            LOGGER.error(f"{self.account_id} | {self.stack_name}, Error: {error}")

    def _delete_change_set(self):
        try:
            return self.client.delete_change_set(
                ChangeSetName=self.stack_name, StackName=self.stack_name
            )
        except ClientError as error:
            LOGGER.error(f"{self.account_id} | {self.stack_name}, Error: {error}")

    def _execute_change_set(self, waiter):
        LOGGER.info(
            f"{self.account_id} - Executing Cloudformation Change Set with name: {self.stack_name}"
        )

        self.client.execute_change_set(
            ChangeSetName=self.stack_name, StackName=self.stack_name
        )
        if self.wait:
            self._wait_stack(waiter, self.stack_name)

    def create_stack(self):
        waiter = self._get_waiter_type()
        create_change_set = self._create_change_set()
        if create_change_set:
            self._execute_change_set(waiter)
            self._update_stack_termination_protection()

    @staticmethod
    def _random_delay():
        return random.randint(11, 49)
