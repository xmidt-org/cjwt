#!/bin/bash
# SPDX-FileCopyrightText: 2021 Comcast Cable Communications Management, LLC
# SPDX-License-Identifier: Apache-2.0

# Usage: get_coverity.sh token GITHUB_REPOSITORY

token=$1
project=${2//\//\%2F}

if [ ! -f coverity_tool.tgz ]; then
    echo "Fetching linux64 binary coverity_tool.tgz"
    wget https://scan.coverity.com/download/linux64 \
        -q --post-data "token=$token&project=$project" -O coverity_tool.tgz
fi

if [ ! -f coverity_tool.md5 ]; then
    echo "Fetching linux64 md5"
    wget https://scan.coverity.com/download/linux64 \
        -q --post-data "token=$token&project=$project&md5=1" -O coverity_tool.md5
    echo "  coverity_tool.tgz" >> coverity_tool.md5
fi

md5sum -c coverity_tool.md5

tar -xzf coverity_tool.tgz

find . -name cov-* -exec ln -s {} coverity \;
