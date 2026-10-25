"""Python-AST rules for issues that a single-line regex can't express."""
import ast
from typing import Iterator, Tuple

from ..models import Severity as S

# (line, rule_id, owasp, severity, title, fix)
AstHit = Tuple[int, str, str, S, str, str]

ROUTE_ATTRS = {"route", "get", "post", "put", "delete", "patch"}
AUTH_HINTS = ("login_required", "jwt_required", "auth", "permission", "requires", "roles_required")
AUTH_BODY_HINTS = ("current_user", "session", "abort", "has_permission", "is_authenticated")


def _names(node: ast.AST) -> Iterator[str]:
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            yield n.id
        elif isinstance(n, ast.Attribute):
            yield n.attr


def _route_path(dec: ast.expr):
    if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
            and dec.func.attr in ROUTE_ATTRS and dec.args
            and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str)):
        return dec.args[0].value
    return None


def check_missing_authz(tree: ast.AST) -> Iterator[AstHit]:
    """A01: route taking an object identifier with no visible auth decorator/check."""
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        paths = [p for p in (_route_path(d) for d in fn.decorator_list) if p]
        if not any("<" in p for p in paths):
            continue
        deco_names = [n.lower() for d in fn.decorator_list for n in _names(d)]
        body_names = [n.lower() for s in fn.body for n in _names(s)]
        if any(h in n for n in deco_names for h in AUTH_HINTS):
            continue
        if any(h in n for n in body_names for h in AUTH_BODY_HINTS):
            continue
        yield (fn.lineno, "OWS-A01-002", "A01", S.HIGH,
               f"Route '{fn.name}' exposes an object ID with no visible authentication/ownership check",
               "Require authentication and verify the caller owns/may access the object (prevent IDOR).")


def check_swallowed_exceptions(tree: ast.AST) -> Iterator[AstHit]:
    """A09: exceptions silently ignored."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            body = node.body
            if len(body) == 1 and isinstance(body[0], (ast.Pass, ast.Continue)):
                yield (node.lineno, "OWS-A09-002", "A09", S.LOW,
                       "Exception silently swallowed",
                       "Log the exception (logger.exception) or handle it explicitly.")


AST_CHECKS = [check_missing_authz, check_swallowed_exceptions]
