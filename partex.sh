#!/usr/bin/env bash
# partex.sh: open a `partex agent` session on a target: baseline + version-disclosure, a briefing, then
# the CLAI2 terminal where you direct further GET/HEAD/OPTIONS probes and checks (model via the Gateway).
#
#   ./partex.sh http://192.168.12.1/home      # asks who authorized the test
#   ./partex.sh -a 'I own 192.168.12.1 and authorize this test, 2026-11-19' http://192.168.12.1/home
#
# Usage: ./partex.sh [options] <target-url> | -u URLS_FILE   |   ./partex.sh list [-d DB]       (flags override the environment variables in [])
#   -a, --attestation TEXT   who authorized testing the target [PARTEX_ATTESTATION]; prompted for if unset
#   -m, --model NAME         model [PARTEX_MODEL, default zai-org/GLM-5.3]
#   -r, --route NAME         gateway route for a bare model name [PARTEX_GATEWAY_ROUTE, default doubleword]. A
#                            full model string (anything with a ':', e.g. openai:gpt-5 or
#                            gateway/anthropic:claude-sonnet-5-5) uses no route unless you pass one.
#   -S, --search-model NAME  optional separate model for web_search [PARTEX_SEARCH_MODEL]: anthropic:<name>,
#                            google:<name> (API key), google-cloud:<name> (ADC), or openai:<name>; off unless set. Queries
#                            leave this machine and never go through the Gateway.
#   -d, --db PATH            database [PARTEX_DB, default ./partex-probe.db]
#   -f, --from RUN_ID        let the new session read an earlier run [RUN_ID]
#       --resume [RUN_ID]    read-only chat on an earlier run, no traffic and no target URL needed; the
#                            latest run if RUN_ID is omitted [CHAT_ONLY=1, RUN_ID]
#   -k, --insecure           accept invalid TLS certificates (self-signed, expired, mismatch) for the target
#                            [PARTEX_INSECURE=1]; recorded on the run, never available to the model
#   -u, --urls-file PATH     file of authorized URLs, one per line (# comments; a trailing /* allows a path prefix)
#                            [PARTEX_URLS_FILE]. Only those URLs can be requested. <target-url> is then optional: the first
#                            URL in the file is the baseline target; an explicit one must be listed.
#       --recursive          with -u: treat every listed URL as a path prefix (http://foo/ allows all of foo)
#                            [PARTEX_RECURSIVE=1]
#   -l, --list               list the runs saved in the database (same as the word `list`) and exit
#   -n, --max-requests N     request budget for the session [PARTEX_MAX_REQUESTS, default 50; ceiling 100000]
#   -R, --max-rps N          requests per second [PARTEX_MAX_RPS, default 2; ceiling 64]
#       --no-tui             run `partex test` + show only [NO_TUI=1]
#   -h, --help
# Required for the chat step: PYDANTIC_AI_GATEWAY_API_KEY when the model goes through the Gateway (a bare model
# name, or gateway/...); a direct provider string such as openai:... needs that provider's own key (OPENAI_API_KEY).
#
# Traffic: the session opens with 3 GETs (TARGET_URL, /robots.txt, /partex-nonexistent-probe-0); after that
# only what you ask for in the chat (GET/HEAD/OPTIONS). 2 req/s, budget 50 per session (--max-rps /
# --max-requests change them), host and port locked
# to TARGET_URL, /logout|/reboot|/reset|/restart|/factory excluded — scope is checked by partex, not the model.
set -euo pipefail
export PYDANTIC_AI_NO_BANNER=${PYDANTIC_AI_NO_BANNER:-1}  # skip pydantic-ai's startup banner between findings and briefing

usage() { sed -n '/^# Usage:/,/^#   -h/s/^# \{0,1\}//p' "${BASH_SOURCE[0]}"; }
TARGET_URL=
MODEL=${PARTEX_MODEL:-zai-org/GLM-5.3}
ROUTE=${PARTEX_GATEWAY_ROUTE-doubleword}
ROUTE_SET=${PARTEX_GATEWAY_ROUTE+1}
SEARCH_MODEL=${PARTEX_SEARCH_MODEL:-}
DB=${PARTEX_DB:-partex-probe.db}
ATTESTATION=${PARTEX_ATTESTATION:-}
URLS_FILE=${PARTEX_URLS_FILE:-}
RECURSIVE=${PARTEX_RECURSIVE:+1}
LIST=
INSECURE=${PARTEX_INSECURE:+1}
RESUME=${CHAT_ONLY:+1}
NO_TUI=${NO_TUI:-}
MAX_REQUESTS=${PARTEX_MAX_REQUESTS:-50}
MAX_RPS=${PARTEX_MAX_RPS:-2}
RUN_ID=${RUN_ID:-}   # with --resume: the run to open; otherwise the run to read (--from)
while [[ $# -gt 0 ]]; do
  case $1 in
    -a|--attestation) ATTESTATION=${2?$1 needs a value}; shift 2 ;;
    -m|--model) MODEL=${2?$1 needs a value}; shift 2 ;;
    -r|--route) ROUTE=${2?$1 needs a value}; ROUTE_SET=1; shift 2 ;;
    -S|--search-model) SEARCH_MODEL=${2?$1 needs a value}; shift 2 ;;
    -d|--db) DB=${2?$1 needs a value}; shift 2 ;;
    -f|--from) RUN_ID=${2?$1 needs a value}; shift 2 ;;
    --resume) RESUME=1; shift; if [[ ${1:-} == run_* ]]; then RUN_ID=$1; shift; fi ;;
    --recursive) RECURSIVE=1; shift ;;
    -u|--urls-file) URLS_FILE=${2?$1 needs a value}; shift 2 ;;
    -k|--insecure) INSECURE=1; shift ;;
    -l|--list) LIST=1; shift ;;
    -n|--max-requests) MAX_REQUESTS=${2?$1 needs a value}; shift 2 ;;
    -R|--max-rps) MAX_RPS=${2?$1 needs a value}; shift 2 ;;
    --no-tui) NO_TUI=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    list) if [[ -z $TARGET_URL ]]; then LIST=1; shift; else echo "unexpected argument: $1" >&2; exit 2; fi ;;
    *) [[ -z $TARGET_URL ]] || { echo "unexpected argument: $1" >&2; exit 2; }; TARGET_URL=$1; shift ;;
  esac
done
[[ $# -eq 0 || -n $TARGET_URL ]] || TARGET_URL=$1
for _n in MAX_REQUESTS MAX_RPS; do
  [[ ${!_n} =~ ^[1-9][0-9]*$ ]] || { echo "$_n must be a positive integer, got: ${!_n}" >&2; exit 2; }
done
[[ -n $ROUTE_SET || $MODEL != *:* ]] || ROUTE=  # a full model string is not routed through a Gateway route
case $DB in /*) ;; *) DB=$PWD/$DB ;; esac  # absolute, before the cd below (BSD realpath has no -m)
case $URLS_FILE in ''|/*) ;; *) URLS_FILE=$PWD/$URLS_FILE ;; esac  # likewise
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)  # absolute, resolved before the cd (works from any directory)
cd "$SCRIPT_DIR"
partex() { uv run --quiet partex "$@"; }

if [[ -n $LIST ]]; then  # saved runs + available sandboxes; resume any with --resume RUN_ID
  if [[ -e $DB ]]; then
    partex runs --db "$DB" --json | python3 "$SCRIPT_DIR/scripts/list_runs.py" "$DB" "$0"
  else
    echo "no database at $DB (nothing saved yet)"
  fi
  echo
  echo "sandboxes:"
  partex sandboxes --json | python3 -c 'import json, sys
for s in json.load(sys.stdin):
    if "available" not in s:
        continue
    mark = "ok" if s["available"] else "no"
    print("  %-12s [%s]  %s" % (s["name"], mark, s["detail"]))'
  exit 0
fi

if [[ -n $RESUME ]]; then  # review an earlier run read-only: no traffic
  if [[ -z ${RUN_ID:-} ]]; then  # default to the most recent usable run in the DB
    RUN_ID=$(partex runs --db "$DB" --json | python3 -c 'import json, sys
runs = [r for r in json.load(sys.stdin) if r["state"] != "invalid"]
print(runs[-1]["id"] if runs else "")')
    [[ -n $RUN_ID ]] || { echo "no runs in $DB to resume" >&2; exit 1; }
    echo "resuming $RUN_ID (pick another with --resume RUN_ID)"
  fi
  exec uv run --quiet partex chat "$RUN_ID" --db "$DB" --model "$MODEL" ${ROUTE:+--gateway-route "$ROUTE"}
fi

[[ -z $URLS_FILE || -f $URLS_FILE ]] || { echo "URLs file not found: $URLS_FILE" >&2; exit 1; }
if [[ -z $TARGET_URL && -n $URLS_FILE ]]; then  # no <target-url>: the first URL in the file is the baseline target
  while IFS= read -r _line || [[ -n $_line ]]; do
    _line=${_line#"${_line%%[![:space:]]*}"}; _line=${_line%"${_line##*[![:space:]]}"}  # trim
    [[ -z $_line || $_line == '#'* ]] && continue
    TARGET_URL=${_line%\*}  # a trailing /* prefix marker becomes the prefix's own URL
    break
  done < "$URLS_FILE"
  [[ -n $TARGET_URL ]] || { echo "no URLs in $URLS_FILE" >&2; exit 1; }
  echo "target: $TARGET_URL (first URL in $URLS_FILE)"
fi
[[ -n $TARGET_URL ]] || { echo "usage: $0 [options] [<target-url> | -u URLS_FILE]  (-h for options)" >&2; exit 2; }
if [[ -z $ATTESTATION ]]; then
  [[ -t 0 ]] || { echo "pass --attestation (or set PARTEX_ATTESTATION): who authorized testing $TARGET_URL" >&2; exit 1; }
  echo "Testing $TARGET_URL sends live requests; partex needs a written authorization on record."
  read -r -p "Authorization (e.g. 'I own this host and authorize this test, $(date +%F)'): " ATTESTATION
  [[ -n $ATTESTATION ]] || { echo "no authorization given; nothing was sent" >&2; exit 1; }
fi
[[ -z $RECURSIVE || -n $URLS_FILE ]] || { echo "--recursive needs a URLs file (-u)" >&2; exit 2; }
[[ $TARGET_URL =~ ^(https?)://([^/:]+)(:([0-9]+))?(/.*)?$ ]] || { echo "bad TARGET_URL: $TARGET_URL" >&2; exit 1; }
host=${BASH_REMATCH[2]} port=${BASH_REMATCH[4]:-$([[ ${BASH_REMATCH[1]} == https ]] && echo 443 || echo 80)}
json_str() { python3 -c 'import json, sys; sys.stdout.write(json.dumps(sys.argv[1]))' "$1"; }

TLS_JSON=; [[ -z $INSECURE ]] || TLS_JSON='"tls": {"verify": false},'
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
    "max_rps": $MAX_RPS,
    "max_requests": $MAX_REQUESTS
  },
  $TLS_JSON
  "authorization": {"attestation": $(json_str "$ATTESTATION"), "operator": $(json_str "${USER:-operator}")},
  "suggested_checks": ["version-disclosure"]
}
JSON

if [[ -n $NO_TUI ]]; then
  rc=0
  result=$(partex test "$eng" --authorized --checks version-disclosure --db "$DB" ${URLS_FILE:+--urls-file "$URLS_FILE"} ${RECURSIVE:+--recursive}) || rc=$?
  printf '%s\n' "$result"
  run=$(grep -o 'run_[0-9a-f]\{32\}' <<<"$result" | head -1 || true)
  [[ -n $run ]] && partex show "$run" --db "$DB" --format text
  exit $(( rc == 3 ? 0 : rc ))
fi

if [[ -n $ROUTE || $MODEL == gateway/* || $MODEL != *:* ]] && [[ -z ${PYDANTIC_AI_GATEWAY_API_KEY:-} ]]; then
  # explicit check: bash 3.2 loses ${:?}'s status in the EXIT trap. Only Gateway models need this key.
  echo 'set PYDANTIC_AI_GATEWAY_API_KEY (or NO_TUI=1 to skip the session)' >&2
  exit 1
fi
echo "opening a partex agent session on $TARGET_URL (db: $DB)"
uv run --quiet partex agent "$eng" --authorized --db "$DB" --model "$MODEL" ${ROUTE:+--gateway-route "$ROUTE"} \
  ${SEARCH_MODEL:+--search-model "$SEARCH_MODEL"} ${URLS_FILE:+--urls-file "$URLS_FILE"} ${RECURSIVE:+--recursive} --checks version-disclosure ${RUN_ID:+--from "$RUN_ID"}
