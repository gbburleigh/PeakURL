#!/bin/bash
PATH='/tmp_env'

if test -f "$PATH"; then
    source tmp_env/bin/activate
fi
    python3 -m venv create tmp_env
    source tmp_env/bin/activate

tmp_env/bin/pip3 install -r requirments.txt