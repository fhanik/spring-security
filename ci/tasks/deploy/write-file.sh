#!/bin/bash

set -e -u +x

gpg --version

GIT_REPO="$( cd "$(dirname "$0")"/../.. ; pwd -P )"
echo "GIT_REPO = $GIT_REPO"

echo "Creating destination: $3"
mkdir -p $3
echo "Writing file contents to $3/$2"
echo "$1" > "$3/$2"
echo "File contents written"
