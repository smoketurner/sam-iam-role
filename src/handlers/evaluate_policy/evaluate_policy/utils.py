#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import pkg_resources


def load_file_to_string(filename):
    filepath = pkg_resources.resource_filename(__name__, filename)
    with open(filepath, "r") as fp:
        data = fp.read()
    return data


def load_file_to_set(filename):
    rows = load_file_to_string(filename).splitlines()
    return {*rows}


def load_file_to_dict(filename):
    return json.loads(load_file_to_string(filename))
