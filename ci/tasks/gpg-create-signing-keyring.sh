#!/bin/bash

set -e -u -x

BASEDIR=$(dirname "$0")

echo "Creating GPG Public Key File"
echo "$1" > /tmp/spring-sec-gpg-public.key
echo "Creating GPG Private Key File"
echo "$2" > /tmp/spring-sec-gpg-private.key

cat /tmp/spring-sec-gpg-public.key
cat /tmp/spring-sec-gpg-private.key

echo "Import public key into keyring"
gpg --no-default-keyring --keyring /tmp/trustedkeys.gpg --import /tmp/spring-sec-gpg-public.key
echo "Import private key into keyring"
echo $3 | gpg --batch --yes --no-default-keyring --keyring git-repo/trustedkeys.gpg --import /tmp/spring-sec-gpg-private.key --yes --passphrase-fd 0

echo "Deleting temporary key files"
rm -f /tmp/spring-sec-gpg-public.key
rm -f /tmp/spring-sec-gpg-private.key

echo "GPG keyring creation completed"
