#!/usr/bin/env bash
# clean-state.sh: interactively remove old Partex databases and trace logs, one confirmation per item (#242).
#
#   scripts/clean-state.sh                      # offer every database and log in the state directory
#   scripts/clean-state.sh --older-than 7       # only items untouched for 7+ days
#   scripts/clean-state.sh -d ./partex-probe.db # also offer a database outside the state directory
#
# Usage: scripts/clean-state.sh [options]
#   -s, --state-dir DIR    state directory [PARTEX_STATE_DIR, else $XDG_STATE_HOME/partex, else ~/.local/state/partex]
#   -d, --db PATH          also offer this database (repeatable); *.db in the state directory are always offered
#   -o, --older-than DAYS  only offer items not modified in the last DAYS days [default 0: everything]
#       --db-only          offer databases only
#       --logs-only        offer trace logs (logs/*.jsonl) only
#   -n, --dry-run          list what would be offered and delete nothing (no terminal needed)
#   -h, --help
#
# Every deletion needs its own `y` typed at a terminal (Enter or `n` keeps the item, `q` stops). There is no
# "yes to all" and no --yes flag, and the script refuses to run when stdin is not a terminal.
#
# A database is removed as one unit: the file, its -wal/-shm/-journal files, and the <db>.artifacts/,
# <db>.reports/ and <db>.clai2/ directories beside it. That deletes every run in it for good, so export
# anything worth keeping first (`uv run partex show RUN_ID --format json --out FILE`). A database that a
# process still has open is skipped. Nothing here writes to a database; symlinks are never followed.
set -euo pipefail

usage() { sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p;}' "$0"; }

die() {
  printf 'clean-state: %s\n' "$*" >&2
  exit 2
}

state_dir=''
extra_dbs=()
older_than=0
want_dbs=1
want_logs=1
dry_run=0

while [ $# -gt 0 ]; do
  case $1 in
    -s | --state-dir) [ $# -ge 2 ] || die "$1 needs a value"; state_dir=$2; shift 2 ;;
    -d | --db) [ $# -ge 2 ] || die "$1 needs a value"; extra_dbs+=("$2"); shift 2 ;;
    -o | --older-than) [ $# -ge 2 ] || die "$1 needs a value"; older_than=$2; shift 2 ;;
    --db-only) want_logs=0; shift ;;
    --logs-only) want_dbs=0; shift ;;
    -n | --dry-run) dry_run=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

case $older_than in
  '' | *[!0-9]*) die "--older-than takes a whole number of days, got: $older_than" ;;
esac
[ "$want_dbs" -eq 1 ] || [ "$want_logs" -eq 1 ] || die '--db-only and --logs-only exclude each other'
if [ "$dry_run" -eq 0 ] && [ ! -t 0 ]; then
  die 'stdin is not a terminal; every deletion needs a typed confirmation (use --dry-run to only list)'
fi
exec 3<&0 # answers come from the terminal even inside the `while read ... done < <(...)` listing loops

absolute() {
  case $1 in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$PWD" "$1" ;;
  esac
}

# Same rule as partex.paths.state_dir(): a relative XDG_STATE_HOME is ignored.
if [ -z "$state_dir" ]; then
  if [ -n "${PARTEX_STATE_DIR:-}" ]; then
    state_dir=$PARTEX_STATE_DIR
  else
    case ${XDG_STATE_HOME:-} in
      /*) state_dir=$XDG_STATE_HOME/partex ;;
      *) state_dir=$HOME/.local/state/partex ;;
    esac
  fi
fi
state_dir=$(absolute "$state_dir")

now=$(date +%s)
freed_kb=0
removed=0

mtime() { stat -c %Y -- "$1" 2>/dev/null || stat -f %m -- "$1"; }

age_days() { echo $(((now - $1) / 86400)); }

size_kb() { # total KB of the existing paths given
  local total=0 path kb
  for path in "$@"; do
    if [ -e "$path" ] || [ -L "$path" ]; then
      kb=$(du -sk -- "$path" 2>/dev/null | awk '{print $1}')
      total=$((total + ${kb:-0}))
    fi
  done
  echo "$total"
}

human() { awk -v kb="$1" 'BEGIN { if (kb >= 1048576) printf "%.1f GB", kb / 1048576; else if (kb >= 1024) printf "%.1f MB", kb / 1024; else printf "%d KB", kb }'; }

in_use() { # 0 when a process has any of the given files open
  local path
  for path in "$@"; do
    [ -e "$path" ] || continue
    if command -v lsof >/dev/null 2>&1; then
      lsof -t -- "$path" >/dev/null 2>&1 && return 0
    elif command -v fuser >/dev/null 2>&1; then
      [ -n "$(fuser -- "$path" 2>/dev/null)" ] && return 0
    fi
  done
  return 1
}

finish() {
  echo
  echo "removed $removed item(s), freed about $(human "$freed_kb")"
  exit 0
}

confirm() { # 0 = delete, 1 = keep; `q` or end of input stops the whole run
  local answer
  while true; do
    printf '%s [y/N/q] ' "$1"
    if ! IFS= read -r answer <&3; then
      echo
      finish
    fi
    case $answer in
      y | Y | yes | YES) return 0 ;;
      '' | n | N | no | NO) return 1 ;;
      q | Q | quit) finish ;;
      *) echo '  answer y (delete), n (keep) or q (stop)' ;;
    esac
  done
}

# ── databases ────────────────────────────────────────────────────────────────

db_files() { printf '%s\n' "$1" "$1-wal" "$1-shm" "$1-journal"; }
db_dirs() { printf '%s\n' "$1.artifacts" "$1.reports" "$1.clai2"; }

offer_db() {
  local db=$1 newest=0 path t kb info='' version runs uri parts=() refused=''
  while IFS= read -r path; do
    [ -e "$path" ] || [ -L "$path" ] || continue
    [ -L "$path" ] && refused="$path is a symlink"
    parts+=("$path")
    t=$(mtime "$path")
    [ "$t" -gt "$newest" ] && newest=$t
  done < <(db_files "$db"; db_dirs "$db")
  [ "$(age_days "$newest")" -ge "$older_than" ] || return 0

  kb=$(size_kb "${parts[@]}")
  if [ -s "$db-wal" ]; then
    info=', schema and runs not shown (writes still pending in the -wal file)'
  elif command -v sqlite3 >/dev/null 2>&1; then
    # immutable=1: SQLite opens no journal, never checkpoints or deletes the -wal/-shm files, writes nothing.
    uri="file:$(printf '%s' "$db" | sed 's/%/%25/g; s/?/%3f/g; s/#/%23/g; s/ /%20/g')?mode=ro&immutable=1"
    version=$(sqlite3 "$uri" 'PRAGMA user_version' 2>/dev/null) || version=''
    runs=$(sqlite3 "$uri" 'SELECT count(*) FROM runs' 2>/dev/null) || runs=''
    info=", schema v${version:-?}, ${runs:-?} run(s)"
  fi
  echo
  echo "[db]  $db"
  echo "      $(human "$kb"), last changed $(age_days "$newest") day(s) ago$info"
  for path in "${parts[@]:1}"; do
    echo "      + ${path##*/}$([ -d "$path" ] && printf '/ (%s)' "$(human "$(size_kb "$path")")")"
  done
  if [ -n "$refused" ]; then
    echo "      skipped: $refused (not following it)"
    return 0
  fi
  if in_use "$db" "$db-wal"; then
    echo '      skipped: a process has this database open'
    return 0
  fi
  [ "$dry_run" -eq 1 ] && return 0
  if confirm '      delete this database and everything listed with it?'; then
    for path in "${parts[@]}"; do
      if [ -d "$path" ]; then rm -rf -- "$path"; else rm -f -- "$path"; fi
    done
    freed_kb=$((freed_kb + kb))
    removed=$((removed + 1))
    echo '      deleted'
  fi
}

if [ "$want_dbs" -eq 1 ]; then
  candidates=()
  for db in "$state_dir"/*.db; do
    [ -e "$db" ] || [ -L "$db" ] || continue
    candidates+=("$db")
  done
  for db in ${extra_dbs[@]+"${extra_dbs[@]}"}; do
    db=$(absolute "$db")
    [ -e "$db" ] || [ -L "$db" ] || die "no database at $db"
    candidates+=("$db")
  done
  if [ ${#candidates[@]} -eq 0 ]; then
    echo "no databases in $state_dir"
  else
    echo "databases (deleting one removes all of its runs; export first: uv run partex show RUN_ID --format json)"
    while IFS=$'\t' read -r _ db; do
      if [ -L "$db" ] || [ ! -f "$db" ]; then
        echo
        echo "[db]  $db"
        echo '      skipped: not a regular file (symlinks are not followed)'
        continue
      fi
      offer_db "$db"
    done < <(for db in "${candidates[@]}"; do printf '%s\t%s\n' "$(mtime "$db")" "$db"; done | sort -n | uniq)
  fi
fi

# ── trace logs ───────────────────────────────────────────────────────────────

if [ "$want_logs" -eq 1 ]; then
  logs_dir=$state_dir/logs
  echo
  if [ -L "$logs_dir" ] || [ ! -d "$logs_dir" ]; then
    echo "no trace log directory at $logs_dir"
  else
    echo "trace logs in $logs_dir"
    while IFS=$'\t' read -r t log; do
      [ -n "$log" ] || continue
      [ "$(age_days "$t")" -ge "$older_than" ] || continue
      kb=$(size_kb "$log")
      printf '[log] %s  %s, %s day(s) old\n' "${log##*/}" "$(human "$kb")" "$(age_days "$t")"
      [ "$dry_run" -eq 1 ] && continue
      if confirm '      delete?'; then
        rm -f -- "$log"
        freed_kb=$((freed_kb + kb))
        removed=$((removed + 1))
      fi
    done < <(for log in "$logs_dir"/*.jsonl; do
      [ -f "$log" ] && [ ! -L "$log" ] && printf '%s\t%s\n' "$(mtime "$log")" "$log"
    done | sort -n)
  fi
fi

if [ "$dry_run" -eq 1 ]; then
  echo
  echo 'dry run: nothing deleted'
  exit 0
fi
finish
