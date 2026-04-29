#!/bin/sh
set -eu

cc-bash-guard verify --all-failures
cc-bash-guard explain "git push --force origin main"
cc-bash-guard explain "git push origin main"
