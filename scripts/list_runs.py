"""Print the saved runs from ``partex runs --json`` (stdin) as a table; used by ``partex.sh list``.

Usage: ``partex runs --db DB --json | python3 scripts/list_runs.py DB SCRIPT``
"""

import json
import sys

db, script = sys.argv[1], sys.argv[2]
runs = [r for r in json.load(sys.stdin) if r['state'] != 'invalid']
if not runs:
    print('no saved runs')
    sys.exit(0)
print(f'{len(runs)} saved run(s) in {db} (newest last)')
print(f'  {"RUN ID":<36}  {"STARTED (UTC)":<19}  {"STATE":<15}  {"FND":>3}  {"REQ":>3}  TARGET')
for r in runs:
    target = ','.join(r.get('hosts') or []) or f'{r["input_kind"]}:{r["input_ref"].rsplit("/", 1)[-1]}'
    when = r['created_at'][:19].replace('T', ' ')
    print(
        f'  {r["id"]:<36}  {when:<19}  {r["state"]:<15}  {r["findings_count"]:>3}  '
        f'{r.get("requests_spent", 0):>3}  {target}'
    )
print(
    f'continue testing: {script} --resume RUN_ID -k   (no RUN_ID = the latest); chat only, no traffic: --read-only RUN_ID'
)
