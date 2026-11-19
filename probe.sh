#!/usr/bin/env bash
# probe.sh: open a `partex agent` session on a target: baseline + version-disclosure, a briefing, then
# the CLAI2 terminal where you direct further GET/HEAD/OPTIONS probes and checks (model via the Gateway).
#
#   PARTEX_ATTESTATION='I own 192.168.12.1 and authorize this test, 2026-11-19' ./probe.sh http://192.168.12.1/home
#
# Usage: ./probe.sh <target-url>   (not needed with CHAT_ONLY=1)
# Required: PARTEX_ATTESTATION; PYDANTIC_AI_GATEWAY_API_KEY for the chat step.
# Optional: PARTEX_MODEL (default zai-org/GLM-5.3),
#           PARTEX_GATEWAY_ROUTE (default doubleword; set empty when PARTEX_MODEL is a full model
#           string such as gateway/anthropic:claude-sonnet-5-5), PARTEX_DB (default ./partex-probe.db),
#           RUN_ID=run_… to let the session read an earlier run (--from), CHAT_ONLY=1 with RUN_ID to review
#           that run without new traffic, NO_TUI=1 to run `partex test` + show only.
#
# Traffic: the session opens with 3 GETs (TARGET_URL, /robots.txt, /partex-nonexistent-probe-0); after that
# only what you ask for in the chat (GET/HEAD/OPTIONS). 2 req/s, budget 50 per session, host and port locked
# to TARGET_URL, /logout|/reboot|/reset|/restart|/factory excluded — scope is checked by partex, not the model.
set -euo pipefail
export PYDANTIC_AI_NO_BANNER=${PYDANTIC_AI_NO_BANNER:-1}  # skip pydantic-ai's startup banner between findings and briefing

TARGET_URL=${1:-}
MODEL=${PARTEX_MODEL:-zai-org/GLM-5.3}
ROUTE=${PARTEX_GATEWAY_ROUTE-doubleword}
DB=$(realpath -m "${PARTEX_DB:-partex-probe.db}")  # absolute, before the cd below
cd "$(dirname "${BASH_SOURCE[0]}")"
partex() { uv run --quiet partex "$@"; }

if [[ -n ${CHAT_ONLY:-} ]]; then  # review an earlier run read-only: no traffic
  : "${RUN_ID:?CHAT_ONLY needs RUN_ID=run_…}"
  exec uv run --quiet partex chat "$RUN_ID" --db "$DB" --model "$MODEL" ${ROUTE:+--gateway-route "$ROUTE"}
fi

[[ -n $TARGET_URL ]] || { echo "usage: $0 <target-url>" >&2; exit 2; }
: "${PARTEX_ATTESTATION:?set PARTEX_ATTESTATION to who authorized testing $TARGET_URL}"
[[ $TARGET_URL =~ ^(https?)://([^/:]+)(:([0-9]+))?(/.*)?$ ]] || { echo "bad TARGET_URL: $TARGET_URL" >&2; exit 1; }
host=${BASH_REMATCH[2]} port=${BASH_REMATCH[4]:-$([[ ${BASH_REMATCH[1]} == https ]] && echo 443 || echo 80)}
json_str() { python3 -c 'import json, sys; sys.stdout.write(json.dumps(sys.argv[1]))' "$1"; }

eng=$(mktemp -d "${TMPDIR:-/tmp}/partex-engagement.XXXXXX")
trap 'rc=$?; rm -rf "$eng"; exit $rc' EXIT  # keep the exit status (bash 3.2 would return the trap's)
cat > "$eng/engagement.json" <<JSON
{
  "schema_version": 1,
  "target": {"name": $(json_str "$host"), "base_url": $(json_str "$TARGET_URL")},
  "scope": {
    "hosts": [$(json_str "$host")],
    "path_prefixes": ["/"],
    "exclusions": ["/logout", "/reboot", "/reset", "/restart", "/factory"],
    "ports": [$port],
    "max_rps": 2,
    "max_requests": 50
  },
  "authorization": {"attestation": $(json_str "$PARTEX_ATTESTATION"), "operator": $(json_str "${USER:-operator}")},
  "suggested_checks": ["version-disclosure"]
}
JSON

if [[ -n ${NO_TUI:-} ]]; then
  rc=0
  result=$(partex test "$eng" --authorized --checks version-disclosure --db "$DB") || rc=$?
  printf '%s\n' "$result"
  run=$(grep -o 'run_[0-9a-f]\{32\}' <<<"$result" | head -1 || true)
  [[ -n $run ]] && partex show "$run" --db "$DB" --format text
  exit $(( rc == 3 ? 0 : rc ))
fi

if [[ -z ${PYDANTIC_AI_GATEWAY_API_KEY:-} ]]; then  # explicit: bash 3.2 loses ${:?}'s status in the EXIT trap
  echo 'set PYDANTIC_AI_GATEWAY_API_KEY (or NO_TUI=1 to skip the session)' >&2
  exit 1
fi
echo "opening a partex agent session on $TARGET_URL (db: $DB)"
uv run --quiet partex agent "$eng" --authorized --db "$DB" --model "$MODEL" ${ROUTE:+--gateway-route "$ROUTE"} \
  --checks version-disclosure ${RUN_ID:+--from "$RUN_ID"}
