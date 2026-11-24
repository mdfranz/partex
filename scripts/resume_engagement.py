"""Rebuild an engagement file from an earlier run's stored engagement record; used by ``partex.sh --resume``.

Usage: ``python3 scripts/resume_engagement.py DB RUN_ID [--max-requests N] [--max-rps N] [--insecure] [--target]``

Prints the engagement JSON (target, scope, authorization) the run was started with, so a new session can
continue testing the same target under the same written authorization; ``--target`` prints only the base
URL. The flags override the stored budget / TLS policy. Reads the database read-only.
"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('db')
parser.add_argument('run_id')
parser.add_argument('--max-requests', type=int)
parser.add_argument('--max-rps', type=int)
parser.add_argument('--insecure', action='store_true')
parser.add_argument('--target', action='store_true')
args = parser.parse_args()

conn = sqlite3.connect(f'{Path(args.db).resolve().as_uri()}?mode=ro', uri=True)
row = conn.execute(
    'SELECT e.name, e.base_url, e.scope, e.attestation, e.operator FROM runs r '
    'JOIN engagements e ON e.id = r.engagement_id WHERE r.id = ?',
    (args.run_id,),
).fetchone()
if row is None:
    sys.exit(f'{args.run_id} has no stored engagement (a bundle run, or an unknown run): use --read-only')
name, base_url, scope_json, attestation, operator = row
if args.target:
    print(base_url)
    sys.exit(0)
scope = json.loads(scope_json)
if args.max_requests is not None:
    scope['max_requests'] = args.max_requests
if args.max_rps is not None:
    scope['max_rps'] = args.max_rps
engagement: dict[str, object] = {
    'schema_version': 1,
    'target': {'name': name, 'base_url': base_url},
    'scope': scope,
    'authorization': {'attestation': attestation, 'operator': operator},
    'suggested_checks': ['version-disclosure'],
}
if args.insecure:
    engagement['tls'] = {'verify': False}
print(json.dumps(engagement))
