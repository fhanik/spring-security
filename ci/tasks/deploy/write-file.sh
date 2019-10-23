#!/bin/bash

set -e -u +x

GIT_REPO="$( cd "$(dirname "$0")"/../.. ; pwd -P )"
echo "GIT_REPO = $GIT_REPO"

echo "Writing file contents to $WRITE_FILE_NAME"
echo "$WRITE_FILE_CONTENTS" > "$WRITE_FILE_NAME"
echo "File contents written"
