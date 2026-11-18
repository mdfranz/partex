#!/usr/bin/env bash
# Check that ssh-agent and GitHub SSH access work for partex development.
# Usage: scripts/check-ssh-agent.sh
set -u

ok()   { printf '  [ok]   %s\n' "$*"; }
warn() { printf '  [warn] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*"; rc=1; }
rc=0

echo '1. ssh-agent reachable'
if [ -z "${SSH_AUTH_SOCK:-}" ]; then
  fail 'SSH_AUTH_SOCK is not set; start one with: eval "$(ssh-agent -s)"'
elif [ ! -S "$SSH_AUTH_SOCK" ]; then
  fail "SSH_AUTH_SOCK=$SSH_AUTH_SOCK is not a socket (stale agent?)"
else
  ssh-add -l >/dev/null 2>&1
  case $? in
    0) ok 'agent running with identities loaded'; ssh-add -l | sed 's/^/         /' ;;
    1) fail 'agent running but has no identities; run: ssh-add ~/.ssh/id_rsa' ;;
    *) fail 'cannot talk to agent' ;;
  esac
fi

echo '2. GitHub SSH auth'
out=$(timeout 15 ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -T git@github.com 2>&1)
if printf '%s' "$out" | grep -q 'successfully authenticated'; then
  ok "$(printf '%s' "$out" | head -1)"
else
  fail "SSH to github.com failed: $(printf '%s' "$out" | head -1)"
  echo '         fallback: git -c credential.helper= -c credential.helper='"'"'!gh auth git-credential'"'"' push https://github.com/mdfranz/partex.git <branch>'
fi

echo
[ "$rc" -eq 0 ] && echo 'All checks passed.' || echo 'Some checks failed.'
exit "$rc"
