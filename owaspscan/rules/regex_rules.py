from ..models import Severity as S
from .base import PY, RegexRule

ANY_CODE = frozenset({".py", ".js", ".ts", ".php", ".java", ".rb", ".go", ".env", ".yml", ".yaml"})
WEB = frozenset({".py", ".js", ".ts", ".php"})

REGEX_RULES = [
    # A01
    RegexRule("OWS-A01-001", "A01", S.HIGH, "Possible path traversal (user input in file path)",
              r"\b(open|send_file|send_from_directory)\(\s*[^\"')]*request\.(args|form|values|json)",
              "Normalise the path and verify it stays inside an allowed base directory."),
    # A02
    RegexRule("OWS-A02-001", "A02", S.MEDIUM, "Weak hash algorithm (MD5/SHA-1)",
              r"hashlib\.(md5|sha1)\(",
              "Use SHA-256+ for integrity, and bcrypt/scrypt/argon2 for passwords."),
    RegexRule("OWS-A02-002", "A02", S.HIGH, "Non-cryptographic RNG used for a secret/token",
              r"(?i)(token|secret|password|session|otp|nonce)\w*\s*=.*\brandom\.\w+\(",
              "Use the `secrets` module (secrets.token_urlsafe)."),
    RegexRule("OWS-A02-003", "A02", S.HIGH, "TLS certificate verification disabled",
              r"verify\s*=\s*False",
              "Remove verify=False; trust a proper CA bundle instead."),
    RegexRule("OWS-A02-004", "A02", S.CRITICAL, "Hard-coded secret or credential",
              r"(?i)\w*(password|passwd|secret|api_?key|access_?key|token)\w*\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']",
              "Load secrets from environment variables or a secrets manager.", ANY_CODE),
    # A03
    RegexRule("OWS-A03-001", "A03", S.CRITICAL, "SQL built with string formatting/concatenation",
              r"\b(execute|executemany|raw)\s*\(\s*(f[\"']|[\"'].*[\"']\s*(%|\+)|[\"'].*[\"']\.format\()",
              "Use parameterised queries: cursor.execute(sql, params)."),
    RegexRule("OWS-A03-002", "A03", S.HIGH, "Shell command execution",
              r"subprocess\.\w+\(.*shell\s*=\s*True|\bos\.(system|popen)\(",
              "Pass an argument list to subprocess without shell=True; validate input."),
    RegexRule("OWS-A03-003", "A03", S.HIGH, "Dynamic code evaluation (eval/exec)",
              r"(?<![\w.])(eval|exec)\s*\(",
              "Avoid eval/exec; use ast.literal_eval or explicit dispatch.", WEB),
    RegexRule("OWS-A03-004", "A03", S.MEDIUM, "Template rendered from string (possible SSTI/XSS)",
              r"render_template_string\(|Markup\(\s*(f[\"']|request\.)|\|\s*safe\b",
              "Render static templates and keep autoescaping on."),
    # A05
    RegexRule("OWS-A05-001", "A05", S.MEDIUM, "Debug mode enabled",
              r"(?i)\bdebug\s*=\s*True",
              "Disable debug outside local development."),
    RegexRule("OWS-A05-002", "A05", S.MEDIUM, "Wildcard CORS policy",
              r"(?i)Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*|origins\s*=\s*[\"']\*[\"']",
              "Restrict CORS to an explicit list of trusted origins.", WEB),
    # A07
    RegexRule("OWS-A07-001", "A07", S.HIGH, "JWT signature verification disabled / 'none' algorithm",
              r"verify_signature[\"']?\s*[:=]\s*False|algorithms\s*=\s*\[\s*[\"']none",
              "Always verify signatures and pin the expected algorithms."),
    # A08
    RegexRule("OWS-A08-001", "A08", S.HIGH, "Unsafe deserialisation (pickle/marshal/shelve)",
              r"\b(pickle|cPickle|marshal|shelve)\.loads?\(",
              "Use a safe format such as JSON; never deserialise untrusted data."),
    RegexRule("OWS-A08-002", "A08", S.HIGH, "yaml.load without a safe loader",
              r"\byaml\.load\((?!.*Loader\s*=\s*(yaml\.)?(Safe|CSafe))",
              "Use yaml.safe_load()."),
    # A09
    RegexRule("OWS-A09-001", "A09", S.MEDIUM, "Sensitive data written to logs",
              r"(?i)\blog(ger|ging)?\.\w+\(.*(password|passwd|secret|token|api_?key)",
              "Never log credentials or tokens; redact sensitive fields."),
    # A10
    RegexRule("OWS-A10-001", "A10", S.HIGH, "Outbound request using user-controlled URL (SSRF)",
              r"(requests\.\w+|urlopen|httpx\.\w+)\(\s*[^\"')]*request\.(args|form|values|json)",
              "Validate against an allow-list of hosts and block internal IP ranges."),
]
