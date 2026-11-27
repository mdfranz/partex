#!/usr/bin/env bash
# validate.sh: read-only post-run validation over a saved run in partex.db (#256).
# Previews decision-model skill suggestions (#257), response classifications (#261),
# and advisory finding triage (#258) without modifying the database or sending target traffic.
#
# Usage: ./validate.sh [options] [RUN_ID]   (defaults to the latest usable run in partex.db)
#   -D, --decision-model NAME  decision model [PARTEX_DECISION_MODEL, default google-decisions:gemini-decision-1];
#                              repeatable to compare providers (e.g. -D google-decisions:... -D openai-decisions:...)
#   -d, --db PATH              database [PARTEX_DB, default partex.db in the state directory]
#   -t, --threshold FLOAT      confidence cutoff for skill picks and [uncertain] flags (default 0.75)
#       --max-evidence N       max deduplicated HTTP exchanges to classify (default 10)
#       --max-findings N       max findings to triage (default 20)
#       --json                 output structured JSON instead of text
#   -o, --out PATH             write full JSON report to PATH
#   -h, --help
set -euo pipefail
export PYDANTIC_AI_NO_BANNER=${PYDANTIC_AI_NO_BANNER:-1}

usage() { sed -n '/^# Usage:/,/^#   -h/s/^# \{0,1\}//p' "${BASH_SOURCE[0]}"; }

DB=${PARTEX_DB:-}
THRESHOLD=0.75
MAX_EVIDENCE=10
MAX_FINDINGS=20
JSON_FLAG=
OUT=
RUN_ID=
DECISION_MODELS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    -D|--decision-model) DECISION_MODELS+=("${2?$1 needs a value}"); shift 2 ;;
    -d|--db) DB=${2?$1 needs a value}; shift 2 ;;
    -t|--threshold) THRESHOLD=${2?$1 needs a value}; shift 2 ;;
    --max-evidence) MAX_EVIDENCE=${2?$1 needs a value}; shift 2 ;;
    --max-findings) MAX_FINDINGS=${2?$1 needs a value}; shift 2 ;;
    --json) JSON_FLAG=1; shift ;;
    -o|--out) OUT=${2?$1 needs a value}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) [[ -z $RUN_ID ]] || { echo "unexpected argument: $1" >&2; exit 2; }; RUN_ID=$1; shift ;;
  esac
done
[[ $# -eq 0 || -n $RUN_ID ]] || RUN_ID=$1

case ${PARTEX_STATE_DIR:-} in
  ''|/*) ;;
  *) PARTEX_STATE_DIR=$(pwd -P)/$PARTEX_STATE_DIR
     export PARTEX_STATE_DIR ;;
esac
state_dir=${PARTEX_STATE_DIR:-}
if [[ -z $state_dir ]]; then
  case ${XDG_STATE_HOME:-} in
    /*) state_dir=$XDG_STATE_HOME/partex ;;
    *) state_dir=~/.local/state/partex ;;
  esac
fi
DB=${DB:-$state_dir/partex.db}
case $DB in /*) ;; *) DB=$PWD/$DB ;; esac
case $OUT in ''|/*) ;; *) OUT=$PWD/$OUT ;; esac

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR"

ARGS=(--db "$DB" --threshold "$THRESHOLD" --max-evidence "$MAX_EVIDENCE" --max-findings "$MAX_FINDINGS")
for _dm in ${DECISION_MODELS[@]+"${DECISION_MODELS[@]}"}; do
  ARGS+=(--decision-model "$_dm")
done
[[ -z $JSON_FLAG ]] || ARGS+=(--json)
[[ -z $OUT ]] || ARGS+=(--out "$OUT")
[[ -z $RUN_ID ]] || ARGS+=("$RUN_ID")

exec uv run --quiet python "$SCRIPT_DIR/scripts/validate_run.py" "${ARGS[@]}"
