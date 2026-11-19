"""banner-leak — fixture passive check shipped as a separate distribution (PLAN §13.2)."""

import re
from collections.abc import Sequence

from partex.models import Evidence, FindingDraft, HttpEvidence, get_header

_VERSIONED = re.compile(r'\d+(?:\.\d+)+')


class BannerLeakCheck:
    check_id = 'banner-leak'
    version = '1.0'
    title = 'Version Banner Leak'
    description = 'Flag Server / X-Powered-By headers that expose an explicit software version.'

    def applies_to(self, evidence: Sequence[Evidence]) -> bool:
        return any(isinstance(item, HttpEvidence) for item in evidence)

    def review(self, evidence: Sequence[Evidence]) -> Sequence[FindingDraft]:
        drafts: list[FindingDraft] = []
        for item in evidence:
            if not isinstance(item, HttpEvidence):
                continue
            for header in ('Server', 'X-Powered-By'):
                value = get_header(item.http.response.headers, header)
                if value and _VERSIONED.search(value):
                    drafts.append(
                        FindingDraft(
                            check_id=self.check_id,
                            check_version=self.version,
                            severity='low',
                            subject=f'header:{header.lower()}',
                            title=f'{header} header discloses a version',
                            description=f'{header}: {value}',
                            evidence_ids=[item.id],
                            remediation=f'Remove the version from the {header} header.',
                        )
                    )
        return drafts


banner_leak_check = BannerLeakCheck()
