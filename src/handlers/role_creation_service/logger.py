#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import os

import boto3


def configure_logger(logger_name):
    """
    Configures a generic logger
    """

    logging.getLogger("boto").setLevel(logging.INFO)

    # Create logger and define INFO as the log level
    logger = logging.getLogger(logger_name)
    logger.setLevel(os.environ.get("RCS_LOG_LEVEL", logging.INFO))
    logger.propagate = False

    # Define our logging formatter
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s | (%(filename)s:%(lineno)d)"
    )

    # Create our stream handler and apply the formatting
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    # Add the stream handler to the logger
    logger.addHandler(stream_handler)

    return logger
