#!/bin/sh
# Build the pkcs11js native addon explicitly — the ONLY native build in this project, and never an install
# script. Used by the image Dockerfile and test/docker/softhsm/Dockerfile, after `npm ci --ignore-scripts`.
#
# What was read before trusting this (pkcs11js 2.1.6, the version the lockfile pins by integrity):
#   package.json  no preinstall/install/postinstall script; `prepare` runs `node-gyp configure build`, which
#                 npm does not run for a registry dependency. Because binding.gyp exists, npm would still run
#                 an implicit `node-gyp rebuild` on install — which `--ignore-scripts` suppresses. 2.1.7 differs
#                 from 2.1.6 only in package.json (an explicit `install: node-gyp rebuild`, a nyc bump).
#   binding.gyp   one target, `pkcs11`: src/dl.cpp, src/common.cpp, src/main.cpp (which #includes the rest),
#                 include dir `includes` (the OASIS PKCS#11 headers), define NAPI_DISABLE_CPP_EXCEPTIONS; no
#                 actions, no downloads, no extra libraries. It builds against Node-API only.
#   index.js      require("./build/Release/pkcs11.node") plus error wrapping; no other requires but node:util.
#
# node-gyp is the copy bundled with the image's npm (pinned by the node:20 image), and --nodedir points at the
# headers shipped in that image, so the build fetches nothing from the network.
set -eu
cd "$(dirname "$0")/../node_modules/pkcs11js"
version="$(node -p "require('./package.json').version")"
if [ "$version" != "2.1.6" ]; then
  echo "build-pkcs11js: expected pkcs11js 2.1.6, found $version — re-read binding.gyp and package.json before changing this pin" >&2
  exit 1
fi
NODE_GYP="$(npm root -g)/npm/node_modules/node-gyp/bin/node-gyp.js"
node "$NODE_GYP" rebuild --nodedir="$(dirname "$(dirname "$(command -v node)")")"
node -e "require('./build/Release/pkcs11.node')"
echo "build-pkcs11js: built node_modules/pkcs11js/build/Release/pkcs11.node"
