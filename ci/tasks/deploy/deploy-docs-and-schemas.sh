#!/bin/bash

set -e -u +x

GIT_REPO="$( cd "$(dirname "$0")"/../../.. ; pwd -P )"
echo "GIT_REPO = $GIT_REPO"

echo -e "35.245.108.196\tdocs.af.pivotal.io" >> /etc/hosts

./gradlew $DEPLOY_BUILD_CMD \
    -PdeployDocsSshKeyPath=$GIT_REPO/$DEPLOY_KEY_FILE \
    -PdeployDocsSshUsername=concourse \
    --no-daemon \
    --stacktrace \
    --refresh-dependencies

