import tempfile
import unittest
from pathlib import Path

from owaspscan.scanner import scan_paths


def scan_snippet(code: str, name="t.py"):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / name
        p.write_text(code)
        return {f.rule_id for f in scan_paths([str(p)])}


class RuleTests(unittest.TestCase):
    def test_sql_injection(self):
        self.assertIn("OWS-A03-001", scan_snippet('cur.execute("SELECT * FROM t WHERE a=" + x)\n'))

    def test_parameterised_sql_is_clean(self):
        self.assertNotIn("OWS-A03-001", scan_snippet('cur.execute("SELECT * FROM t WHERE a=?", (x,))\n'))

    def test_hardcoded_secret_with_prefix(self):
        self.assertIn("OWS-A02-004", scan_snippet('DB_PASSWORD = "SuperSecret123"\n'))

    def test_pickle(self):
        self.assertIn("OWS-A08-001", scan_snippet("pickle.loads(data)\n"))

    def test_safe_yaml(self):
        self.assertNotIn("OWS-A08-002", scan_snippet("yaml.safe_load(s)\n"))

    def test_idor_route(self):
        code = '@app.route("/u/<id>")\ndef f(id):\n    return id\n'
        self.assertIn("OWS-A01-002", scan_snippet(code))

    def test_authed_route_clean(self):
        code = '@app.route("/u/<id>")\n@login_required\ndef f(id):\n    return id\n'
        self.assertNotIn("OWS-A01-002", scan_snippet(code))

    def test_suppression(self):
        self.assertEqual(scan_snippet("eval(x)  # noscan\n"), set())

    def test_comments_ignored(self):
        self.assertEqual(scan_snippet("# eval(x)\n"), set())

    def test_unpinned_requirements(self):
        self.assertIn("OWS-A06-001", scan_snippet("flask\n", name="requirements.txt"))


if __name__ == "__main__":
    unittest.main()
