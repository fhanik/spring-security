#!/bin/bash

echo $1 > /tmp/spring-sec-gpg-public.key
echo $2 > /tmp/spring-sec-gpg-private.key

gpg --no-default-keyring --keyring /tmp/trustedkeys.gpg --import spring-sec-gpg-public.key
echo $3 | gpg --batch --yes --no-default-keyring --keyring trustedkeys.gpg --import /tmp/spring-sec-gpg-private.key --yes --passphrase-fd 0
