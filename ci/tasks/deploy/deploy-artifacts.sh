#!/bin/bash

set -e -u +x

GIT_REPO="$( cd "$(dirname "$0")"/../../.. ; pwd -P )"
echo "GIT_REPO = $GIT_REPO"

echo "Deploying Spring Security Artifacts"

./gradlew deployArtifacts finalizeDeployArtifacts \
    -Psigning.secretKeyRingFile="$SIGNING_KEYRING_FILE" \
    -Psigning.keyId="$SPRING_SIGNING_KEYID" \
    -Psigning.password="$SIGNING_PASSWORD" \
    -PossrhUsername="$OSSRH_USERNAME" \
    -PossrhPassword="$OSSRH_PASSWORD" \
    -PartifactoryUsername="$ARTIFACTORY_USERNAME" \
    -PartifactoryPassword="$ARTIFACTORY_PASSWORD" \
    --refresh-dependencies --no-daemon --stacktrace

echo "\nSpring Security Artifacts Successfully Deployed"
