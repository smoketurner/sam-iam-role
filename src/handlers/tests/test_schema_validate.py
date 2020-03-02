#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

from yamale.yamale_testcase import YamaleTestCase


class TestSchemaValidate(YamaleTestCase):
    base_dir = os.path.dirname(os.path.realpath(__file__))
    schema = "../schema.yml"
    yaml = "data/test_data_*.yml"

    def runTest(self):
        self.assertTrue(self.validate())
