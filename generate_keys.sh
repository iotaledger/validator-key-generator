#!/bin/bash

function error {
    echo "error: $@"
    exit 1
}

# get real directory
path="$( dirname $( readlink -f "$0" ) )"

# switch to real directory
cd $path

for file in identity.key coo.key tendermint.key private.txt public.txt
do
    [ -f "${file}" ] && error "won't overwrite $file"
done

# Check if Python 3 is installed
test -x "$(which python3)" || error "Python 3 is not installed. Install it with:\n\tsudo apt update && sudo apt install python3"

# Check if pip for Python 3 is installed
test -x "$(which pip3)" || error "pip3 is not installed. Install it with:\n\tsudo apt install python3-pip"

# Check if virtualenv is installed
test -x "$(which virtualenv)" || error "virtualenv is not installed. Install it with:\n\tsudo apt install python3-virtualenv"

# Create virtual environment
python3 -m virtualenv -p $( which python3 ) venv || error "Failed to create virtual environment"

# Activate virtual environment
source venv/bin/activate || error "Failed to activate virtual environment"

# Install required packages from requirements.txt
pip install -r ./requirements.txt > /tmp/requirements.log || error "Failed to install required packages"

# Create keys and yml
python generate_keys.py || error "Failed to create keys and YAML file"

# Deactivate virtual environment
deactivate


echo
echo "done."
