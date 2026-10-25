import json
from collections import Counter
from typing import List

from .models import OWASP, Finding


def to_text(findings: List[Finding]) -> str:
    if not findings:
        return "No findings."
    out = []
    for f in findings:
        loc = f.path if f.rule_id.startswith("OWS-WEB-") else f"{f.path}:{f.line}"
        out.append(f"[{f.severity.name}] {f.rule_id}  {OWASP[f.owasp]}\n"
                   f"  {loc}  {f.title}\n"
                   f"    > {f.snippet}\n"
                   f"    fix: {f.fix}\n")
    by_sev = Counter(f.severity.name for f in findings)
    summary = ", ".join(f"{n} {s}" for s, n in by_sev.items())
    out.append(f"{len(findings)} finding(s): {summary}")
    return "\n".join(out)


def to_json(findings: List[Finding]) -> str:
    return json.dumps({"count": len(findings), "findings": [f.to_dict() for f in findings]}, indent=2)
