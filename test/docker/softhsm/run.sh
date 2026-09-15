#!/bin/sh
# Inside the SoftHSM test container: initialise a throwaway token, generate the test keys inside it, run the
# pkcs11 suite. The PINs are generated here and live only in this container's environment.
set -eu
export SOFTHSM2_CONF=/tmp/softhsm2.conf
mkdir -p /tmp/softhsm-tokens
printf 'directories.tokendir = /tmp/softhsm-tokens\nobjectstore.backend = file\nlog.level = ERROR\n' > "$SOFTHSM2_CONF"

PKCS11_PIN="$(od -An -tx1 -N12 /dev/urandom | tr -d ' \n')"
so_pin="$(od -An -tx1 -N12 /dev/urandom | tr -d ' \n')"
export PKCS11_PIN
softhsm2-util --init-token --free --label "$PKCS11_TOKEN_LABEL" --so-pin "$so_pin" --pin "$PKCS11_PIN" > /dev/null
unset so_pin

node test/docker/softhsm/provision.mjs
exec node node_modules/vitest/vitest.mjs run test/pkcs11-softhsm.test.ts
