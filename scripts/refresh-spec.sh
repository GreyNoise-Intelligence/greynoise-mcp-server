#!/usr/bin/env bash
set -euo pipefail

REPO="${GN_MONOREPO:-GreyNoise-Intelligence/greynoise}"
REF="${GN_MONOREPO_REF:-master}"
SPEC_PATH="api/docs/oas-production.yaml"
OUT="spec/oas-production.yaml"

command -v gh >/dev/null || { echo "gh CLI not found; install and 'gh auth login'"; exit 1; }

mkdir -p spec
gh api "repos/${REPO}/contents/${SPEC_PATH}?ref=${REF}" \
  -H "Accept: application/vnd.github.raw" > "${OUT}"

echo "refreshed ${OUT} from ${REPO}@${REF}:${SPEC_PATH}"
