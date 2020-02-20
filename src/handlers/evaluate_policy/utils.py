#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json


def load_file_to_set(filename):
    with open(filename, "r") as fp:
        rows = fp.read().splitlines()
    return {*rows}


def load_file_to_string(filename):
    with open(filename, "r") as fp:
        data = fp.read()
    return data


def load_file_to_dict(filename):
    return json.loads(load_file_to_string(filename))
