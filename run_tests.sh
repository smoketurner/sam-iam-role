#!/usr/bin/env bash

source .venv/bin/activate
python3 -m unittest discover -s src/handlers/evaluate_policy
