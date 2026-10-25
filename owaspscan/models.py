from dataclasses import dataclass, asdict
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.upper()]


# OWASP Top 10:2021 labels. Swap this mapping to retarget another edition.
OWASP = {
    "A01": "A01 Broken Access Control",
    "A02": "A02 Cryptographic Failures",
    "A03": "A03 Injection",
    "A04": "A04 Insecure Design",
    "A05": "A05 Security Misconfiguration",
    "A06": "A06 Vulnerable and Outdated Components",
    "A07": "A07 Identification and Authentication Failures",
    "A08": "A08 Software and Data Integrity Failures",
    "A09": "A09 Security Logging and Monitoring Failures",
    "A10": "A10 Server-Side Request Forgery",
}


@dataclass
class Finding:
    rule_id: str
    owasp: str
    severity: Severity
    title: str
    path: str
    line: int
    snippet: str
    fix: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["owasp"] = OWASP[self.owasp]
        return d
