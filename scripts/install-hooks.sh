#!/usr/bin/env sh
set -eu
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit
echo "Pre-commit secret scan enabled (core.hooksPath=.githooks)"
