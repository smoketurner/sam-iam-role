#!/usr/bin/env python
# -*- coding: utf-8 -*-


class InvalidRoleException(Exception):
    def __init__(self, findings=None):
        if not isinstance(findings, list):
            findings = [findings]
        self.findings = findings
