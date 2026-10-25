import re
from dataclasses import dataclass, field
from typing import FrozenSet

from ..models import Severity

PY = frozenset({".py"})


@dataclass(frozen=True)
class RegexRule:
    id: str
    owasp: str
    severity: Severity
    title: str
    pattern: str
    fix: str
    exts: FrozenSet[str] = PY
    regex: "re.Pattern" = field(init=False, compare=False, repr=False)

    def __post_init__(self):
        object.__setattr__(self, "regex", re.compile(self.pattern))
