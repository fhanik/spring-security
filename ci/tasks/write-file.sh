#!/bin/bash

set -e -u +x

gpg --version

GIT_REPO="$( cd "$(dirname "$0")"/../.. ; pwd -P )"
echo "GIT_REPO = $GIT_REPO"

echo "Writing file contents to $2"
echo "$1" > "$2"
echo "File contents written"
