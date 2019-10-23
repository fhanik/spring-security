#!/bin/bash

set -e -u +x

gpg --version

GIT_REPO="$( cd "$(dirname "$0")"/../../.. ; pwd -P )"
echo "GIT_REPO = $GIT_REPO"

echo "Creating GPG Public Key File"
echo "$SIGNING_PUBLIC_KEY" > /tmp/spring-sec-gpg-public.key
echo "Creating GPG Private Key File"
echo "$SIGNING_PRIVATE_KEY" > /tmp/spring-sec-gpg-private.key

echo "Import public key into keyring"
gpg --no-default-keyring --keyring $GIT_REPO/trustedkeys.gpg --import /tmp/spring-sec-gpg-public.key
echo "Import private key into keyring"
echo "$SIGNING_PASSWORD" | gpg --yes --batch --no-default-keyring --keyring $GIT_REPO/trustedkeys.gpg --import /tmp/spring-sec-gpg-private.key

echo "Deleting temporary key files"
rm -f /tmp/spring-sec-gpg-public.key
rm -f /tmp/spring-sec-gpg-private.key

echo "\nGPG keyring creation completed"
