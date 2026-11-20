"""Every analyser's output in one format, each finding with a fingerprint, and only what the merge base lacks is new (spec 1237, 9 Nov
2026: the owner's Code Quality Gate v3 §1.3, §4). No per-tool baseline file and no "clean the whole file you touched": that rule cost
38 extra build rounds in one day (20 Oct 2026, WEAKNESSES.md side-checks-block-features). This module imports nothing of the fleet and
runs no git (spec 1255 runs it on developers' machines). The caller hands it the trees and the runner, `runner(cmd, cwd)` ->
(returncode, stdout, stderr); the gate's runner runs in the gate container."""

import ast
import hashlib
import json
import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from fnmatch import fnmatchcase
from functools import partial
from pathlib import Path
from typing import Any

import tomllib

REGISTRY = Path(__file__).resolve().parents[2] / "share" / "gate.toml"
# A `configs` folder this machine lacks is the image's: its key holds what share/ builds those from, the learned rules, semgrep's as setup
# fetches them and the Containerfile's pin (the review, 17 Nov 2026: a key of the absent /opt folder kept stale findings when a rule changed)
BUILT = ("semgrep/learned", "../tools/semgrep-rules", "agent-base/Containerfile")
# Where each JSON tool puts a finding's fields, read from its registry `cmd`'s real output. `records` walks to the findings (* takes each
# item of a list), and each record also holds the fields of the items it sits in (osv: the vulnerability, its package and its source).
# A key that is a number takes that item of a list (SARIF's first location). A tool that has no severity field reports errors only (SARIF's
# absent level is a warning, its own default), and a tool that has no line field gives line 0.
JSON = {  # adapter: (records, file, line, rule, severity, message)
    "shellcheck": ("*", "file", "line", "code", "level", "message"),
    "ruff": ("*", "filename", "location.row", "code", "severity", "message"),
    "basedpyright": (
        "generalDiagnostics.*",
        "file",
        "range.start.line",
        "rule",
        "severity",
        "message",
    ),
    "semgrep": (
        "results.*",
        "path",
        "start.line",
        "check_id",
        "extra.severity",
        "extra.message",
    ),
    "gitleaks": ("*", "File", "StartLine", "RuleID", None, "Description"),
    "osv": (
        "results.*.packages.*.vulnerabilities.*",
        "source.path",
        None,
        "id",
        None,
        "summary",
    ),  # a lockfile holds no function: symbol ""
    "actionlint": ("*", "filepath", "line", "kind", None, "message"),
    "hadolint": ("*", "file", "line", "code", "level", "message"),
    "infer": (
        "*",
        "file",
        "line",
        "bug_type",
        "severity",
        "qualifier",
    ),  # its report.json (spec 1248)
    "sarif": (
        "runs.*.results.*",
        "locations.0.physicalLocation.artifactLocation.uri",
        "locations.0.physicalLocation.region.startLine",
        "ruleId",
        "level",
        "message.text",
    ),  # SARIF 2.1.0: SpotBugs with FindSecBugs, PMD (spec 1248), the kit's one SARIF reader
    "biome": (
        "diagnostics.*",
        "location.path",
        "location.range.start.line",
        "code.value",
        "severity",
        "message",
    ),  # rdjson, 1-based (spec 1610)
    "cite": (
        "*",
        "file",
        "line",
        "rule",
        "severity",
        "message",
    ),  # the kit's own `cite check` (spec 1568)
    "sqlfluff": (
        "*.violations.*",
        "filepath",
        "start_line_no",
        "code",
        None,
        "description",
    ),  # `lint --format json` (spec 1249)
    "squawk": (
        "*",
        "file",
        "line",
        "rule_name",
        "level",
        "message",
    ),  # `--reporter json`, its lines from 0 (spec 1249)
}
ABSENT = {
    "sarif": "warning"
}  # the severity of a finding that names none, where it is not an error
FROM_ZERO = {"basedpyright", "squawk"}  # counts its lines from 0
QUIET = {
    "osv": 128
}  # osv-scanner's exit for a lockfile that holds no package: there is nothing to find, so it is not a crash
EXITS = {
    "vulture": (0, 3),
    "pylint": tuple(range(32)),
    "trufflehog": (0,),
}  # its exits on a scan, where not 0 and 1: vulture's 1 is input it could not read, a crash (spec 1644). pylint's exit is a mask of the kinds
# it printed, 32 alone its usage error (13 Nov 2026: django's one test file of bad syntax added 2 to the cycles' 8, and every replay "crashed")
# trufflehog exits 0 with its secrets and 1 on a fatal error, a bad argument or an unreadable path: a crash (spec 1881, the review)
# a mined rule's semgrep check_id ends <stack>.<id>, semgrep-learned/<stack>/mined-<id>.yaml dotted (spec 1828)
MINED = re.compile(r"(?P<stack>[\w-]+)\.(?P<id>[\w-]+)$")
NOTES = 20  # the most notes a brief carries (spec 1238)
DEFS = ast.FunctionDef | ast.AsyncFunctionDef  # what annotates counts (spec 1931)
MINIFIED = 1000  # bytes: a longer line is a generated file's (spec 1932)
ENDING = re.compile(rb"\r?\n\Z")  # one line end alone, no CR the line holds
NOISE = re.compile(r"(\[error])?\s*(.*:)?|.*(\[help|re-run maven).*", re.IGNORECASE)
CCN = 15  # lizard's own warning threshold (-C); its XML lists every function, so the adapter applies it
SYMBOL = {
    ".py": re.compile(r"(\s*)(?:async\s+)?(?:def|class)\s+(\w+)"),
    ".gd": re.compile(r"(\s*)(?:static\s+)?func\s+(\w+)"),
    ".sh": re.compile(r"(\s*)(?:function\s+([\w.:-]+)|([\w.:-]+)\s*\(\))"),
}  # the name is the last group that matched


def parts(registry: Path) -> list[Path]:
    """gate.toml, then gate.toml.d/*.toml in name order, as analyze.assembled reads them (9 Nov 2026: 1505 moved every entry into the
    fragments, and reading gate.toml alone raised KeyError: 'tool' on every run)."""
    return [registry, *sorted(registry.parent.glob(registry.name + ".d/*.toml"))]


TEST_NAME = re.compile(r"^(test_.*|.*_test\..*|.*-test\..*|test-.*\.sh|.*\.test\..*)$")


def is_test_path(p: str) -> bool:
    """Spec 16 box 2's test path: under a tests/ or test/ directory at any depth, Tests/ and Test/ too (Unity's Assets/**/Tests; live dba56f797,
    1 Nov 2026: lowercase alone counted a project's tests as code), a bare `tests/` naming no file, or a file name matching test_*, *_test.*,
    *-test.*, test-*.sh or *.test.*. The kit's one rule: the pick, rule 4, the size stop and the free review (1921) read it, by spec's name too."""
    return bool(
        re.match(r"^(.*/)?[Tt]ests?/.+", p) or TEST_NAME.match(p.rsplit("/", 1)[-1])
    )


def tools(registry=REGISTRY):
    """The registry as {name: tool}."""
    return {
        t["name"]: t
        for p in parts(registry)
        for t in tomllib.loads(p.read_text()).get("tool", [])
    }


def review(registry: Path | None = None) -> dict[str, list[str]]:
    """The registry's [review] table (spec 1626): `quiet`, the review categories whose findings block no more for their measured precision,
    and `held`, those the owner keeps as they are. Read from REGISTRY at the call: the gate's registry is the kit's main of the moment."""
    tables = [
        tomllib.loads(p.read_text()).get("review", {})
        for p in parts(registry or REGISTRY)
    ]
    return {k: [c for t in tables for c in t.get(k, [])] for k in ("quiet", "held")}


def rule_book(stack: str) -> list[dict]:
    """<stack>'s review rules, share/review-rules/<stack>.toml beside REGISTRY at the call (spec 1787); a rule that cites no fixed issue
    raises, so a hand edit cannot slip one in (owner, 14 Nov 2026: every rule comes from a PR issue that was fixed)."""
    f = REGISTRY.parent / "review-rules" / f"{stack}.toml"
    if not f.exists():
        return []
    rules = tomllib.loads(f.read_text(encoding="utf-8")).get("rule", [])
    if bare := [r.get("id") for r in rules if not r.get("evidence")]:
        raise ValueError(f"{f}: {bare} cite no fixed issue")
    return rules


Books = dict[str, list[dict[str, Any]]]  # {stack: its rules}
Found = list[dict[str, Any]]  # findings, as run lists them


def books(stacks: list[str]) -> Books:
    """The rule books of <stacks>, read once a review: what it cites and caps by (spec 1829)."""
    return {s: rule_book(s) for s in stacks}


def booked(found: list[dict[str, str]]) -> None:
    """Puts each semgrep finding of a mined rule of <found> at its tier in its stack's book, by its check_id's last two dotted segments, the
    stack and the rule id (spec 1828: the book alone keeps a mined rule's tier, its YAML's severity the one it was first written with)."""
    books: dict[str, dict[str, str]] = {}
    for f in found:
        if f["tool"] == "semgrep" and (m := MINED.search(f["rule"])):
            if m["stack"] not in books:
                books[m["stack"]] = {r["id"]: r["tier"] for r in rule_book(m["stack"])}
            f["severity"] = books[m["stack"]].get(m["id"], f["severity"])


def matches(path, globs):
    """analyze.matches, which selected the tool (this module imports nothing of the fleet): a glob matches the path or a tail of it."""
    parts = path.split("/")
    return any(
        fnmatchcase("/".join(parts[i:]), g) for g in globs for i in range(len(parts))
    )


def records(node, path, outer=None):
    outer = {**(outer or {}), **node} if isinstance(node, dict) else outer or {}
    if not path:
        return [outer]
    key, _, rest = path.partition(".")
    return [
        r
        for item in (node if key == "*" else [node.get(key) or []])
        for r in records(item, rest, outer)
    ]


def dig(record, path):
    if path is None:
        return None  # a field the tool does not give
    for key in path.split("."):
        if isinstance(record, list) and key.isdigit():
            record = record[int(key)] if int(key) < len(record) else None
        else:
            record = record.get(key) if isinstance(record, dict) else None
    return record


def read_json(adapter, out, err):
    at, *fields = JSON[adapter]
    # SARIF ends with its document: a summary line after it (golangci-lint's `0 issues.`) is no crash, text before it is (spec 1855, 16 Nov 2026)
    doc = (
        json.JSONDecoder().raw_decode(out.lstrip())[0]
        if adapter == "sarif"
        else json.loads(out)
    )
    rows = [
        dict(
            zip(
                ("file", "line", "rule", "severity", "message"),
                (dig(r, f) for f in fields),
            )
        )
        for r in records(doc, at)
    ]
    shift = 1 if adapter in FROM_ZERO else 0
    return [
        {
            **r,
            "line": 0 if r["line"] is None else r["line"] + shift,
            "severity": r["severity"] or ABSENT.get(adapter, "error"),
        }
        for r in rows
    ]


def read_gdlint(
    out, err
):  # "game/player.gd:5: Error: Function name "Move_Player" is not valid (function-name)", on stderr
    return [
        {"file": f, "line": int(n), "severity": s, "message": m, "rule": r}
        for f, n, s, m, r in re.findall(
            r"^(.+?):(\d+): (Error|Warning): (.*) \((\S+)\)$", err, re.MULTILINE
        )
    ]


def read_godot(
    out, err
):  # "res://game/player.gd:6: UNTYPED_DECLARATION: Variable "x" has no static type.": Godot's warnings as the godot cmd's loader prints them
    return [
        {"file": f, "line": int(n), "severity": "warning", "rule": r, "message": m}
        for f, n, r, m in re.findall(
            r"^(.+?):(\d+): ([A-Z0-9_]+): (.*)$", out, re.MULTILINE
        )
    ]


def read_trufflehog(out: str, err: str) -> list[dict[str, object]]:
    """One JSON line a secret: a key its provider accepts is the error that blocks, one it could not check a note (spec 1881). The
    message names the detector, and why the key is unknown, never the key."""
    return [
        {
            "file": dig(s, "SourceMetadata.Data.Filesystem.file"),
            "line": dig(s, "SourceMetadata.Data.Filesystem.line"),
            "severity": "error" if s["Verified"] else "warning",
            "rule": "trufflehog-verified" if s["Verified"] else "trufflehog-unknown",
            "message": f"{s['DetectorName']}: {s.get('VerificationError', 'live')}",
        }
        for s in map(json.loads, out.splitlines())
    ]


def read_javac(
    out, err
):  # "/work/src/App.java:13: error: [NullAway] dereferenced expression ...": Error Prone's checks in javac's diagnostics, on stderr
    return [
        {"file": f, "line": int(n), "severity": s, "rule": r, "message": m}
        for f, n, s, r, m in re.findall(
            r"^(.+?\.java):(\d+): (error|warning): \[(\w+)\] (.*)$", err, re.MULTILINE
        )
    ]


def copies(rule, at, lines, tokens):
    """A finding at every place (path, line) a copy occurs, naming the others: CPD's and jscpd's alike."""
    return [
        {
            "file": path,
            "line": line,
            "rule": rule,
            "severity": "warning",
            "message": f"{lines} lines ({tokens} tokens) "
            f"also at {', '.join(f'{p}:{n}' for p, n in at if (p, n) != (path, line))}",
        }
        for path, line in at
    ]


def read_cpd(
    out, err
):  # PMD's copy-paste detector, `--format xml` (it writes no SARIF)
    return [
        r
        for dup in ET.fromstring(out).iterfind("{*}duplication")
        for r in copies(
            "CPD",
            [(f.get("path"), int(f.get("line"))) for f in dup.iterfind("{*}file")],
            dup.get("lines"),
            dup.get("tokens"),
        )
    ]


def read_jscpd(
    out, err
):  # jscpd's `--reporters json` (spec 1643): one pair a duplicate, firstFile and secondFile
    return [
        r
        for d in json.loads(out)["duplicates"]
        for r in copies(
            "duplicate",
            [(d[k]["name"], d[k]["start"]) for k in ("firstFile", "secondFile")],
            d["lines"],
            d["tokens"],
        )
    ]


def read_vulture(out: str, err: str) -> list[dict[str, str | int]]:
    """ "a.py:1: unused function 'helper' (60% confidence)": its kind is the rule, unused-function (spec 1644). An unused import is
    ruff's F401: one flaw, one finding."""
    return [
        {
            "file": f,
            "line": int(n),
            "rule": f"{a}-{b}",
            "severity": "warning",
            "message": m,
        }
        for f, n, m, a, b in re.findall(
            r"^(.+?):(\d+): ((\S+) (\S+) .*)$", out, re.MULTILINE
        )
        if (a, b) != ("unused", "import")
    ]


def read_pylint(out: str, err: str) -> list[dict[str, str | int]]:
    """pylint's cyclic-import, "Cyclic import (pkg.a -> pkg.b)", sits at the module pylint read last; the finding is at the cycle's first
    module, which run() finds as the tracked file Python imports by that name, never by a shared basename, nor from the root of the module
    pylint reported (the review, 11 Nov 2026: src/shop and tools are two roots). The cycle is its symbol, so a changed cycle is a new finding
    (spec 1650, 11 Nov 2026). A cycle has no line of its own."""
    return [
        {
            "module": cycle.split(" -> ")[0],
            "line": 0,
            "rule": m["symbol"],
            "severity": "warning",
            "message": m["message"],
            "symbol": cycle,
        }
        for m in json.loads(out)
        if m["symbol"] == "cyclic-import"  # a file it could not parse is said too
        for cycle in [m["message"].removeprefix("Cyclic import (").removesuffix(")")]
    ]


def read_lizard(
    out, err
):  # <item name="tangled(...) at app.py:12"><value>Nr.</value><value>NCSS</value><value>CCN</value></item>
    measure = ET.fromstring(out).find("measure[@type='Function']")
    at, rows = [l.text for l in measure.iter("label")].index("CCN"), []
    for item in measure.iter("item"):
        name, file, line = re.fullmatch(
            r"(.*?)\(.*\) at (.+):(\d+)", item.get("name")
        ).groups()
        ccn = int(item.findall("value")[at].text)
        if ccn > CCN:
            rows.append(
                {
                    "file": file,
                    "line": int(line),
                    "rule": "CCN",
                    "severity": "error",
                    "message": f"{name} has cyclomatic complexity {ccn}, over {CCN}",
                }
            )
    return rows


ADAPTERS = {
    "cpd": read_cpd,
    "gdlint": read_gdlint,
    "godot": read_godot,
    "javac": read_javac,
    "jscpd": read_jscpd,
    "lizard": read_lizard,
    "pylint": read_pylint,
    "trufflehog": read_trufflehog,
    "vulture": read_vulture,
} | {a: partial(read_json, a) for a in JSON}


def module(tree: str | Path, path: str) -> str:
    """The dotted name Python imports a .py file by: its stem (none for an __init__.py) under each folder above it that holds an
    __init__.py, so each file is named from its own source root: pkg/a.py is pkg.a, server/app.py is app (spec 1650)."""
    at = Path(path)
    name = [] if at.name == "__init__.py" else [at.stem]
    for folder in at.parents[:-1]:
        if not Path(tree, folder, "__init__.py").is_file():
            break
        name.insert(0, folder.name)
    return ".".join(name)


def located(
    given: str, name: object, mine: list[str], modules: dict[str, str]
) -> str | None:
    """The tracked file a row is at: the one the module it names is (pylint's; a package before a file of its name, as Python imports
    it, so one cycle is one finding), else the path as the tool gave it, relative as passed or absolute in whatever mount the runner used."""
    if name is not None:
        return min(
            (f for f in mine if modules[f] == name),
            key=lambda f: (Path(f).name != "__init__.py", f),
            default=None,
        )
    return max(
        (f for f in mine if given == f or given.endswith("/" + f)),
        key=len,
        default=None,
    )


def symbol(lines, line, path):
    """The innermost def/class (python), func (gdscript) or name() / function name (bash) whose span holds the line, "" outside any.
    The span is a rule over whole lines, not a parse (spec 1237, 9 Nov): python and gdscript end before the next line that is not blank,
    not a comment and indented no deeper than the header; bash runs to the first later lone } at the header's indentation, that line
    included. It need not be exact: base and head get the same rule, so new() stays right."""
    ext, opened = os.path.splitext(path)[1], []
    for n, text in enumerate(lines[:line] if ext in SYMBOL else (), 1):
        indent, body = len(text) - len(text.lstrip()), text.strip()
        if ext != ".sh" and body and body[0] != "#":
            opened = [o for o in opened if o[0] < indent]
        if m := SYMBOL[ext].match(text):
            opened.append((indent, m[m.lastindex]))
        if ext == ".sh" and body == "}" and n < line:
            opened = [
                o for o in opened if o[0] != indent
            ]  # the } line is still the function's
    return opened[-1][1] if opened else ""


def fingerprint(tool, rule, path, symbol, source):
    """The line number stays out, so an edit above a finding does not make it new."""
    return hashlib.sha256(
        "\0".join((tool, rule, path, symbol, " ".join(source.split()))).encode()
    ).hexdigest()


def finding(tool, row, path, lines):
    line = int(row["line"])
    source, sym = (
        lines[line - 1] if 0 < line <= len(lines) else "",
        row.get("symbol") or symbol(lines, line, path),
    )  # an adapter's own symbol: pylint's cycle (spec 1650)
    rule, severity = (
        "" if row["rule"] is None else str(row["rule"]),
        "error" if str(row["severity"]).lower() == "error" else "warning",
    )
    return {
        "tool": tool,
        "rule": rule,
        "severity": severity,
        "file": path,
        "line": line,
        "symbol": sym,
        "fingerprint": fingerprint(tool, rule, path, sym, source),
        "message": row["message"] or "",
    }


def read(tool, rc, out, err):
    """The tool's findings, or None for a crash: an exit that is neither clean nor findings, or output its adapter cannot read, whatever the
    exit said (gitleaks exits 1 on a leak and on a fatal error alike)."""
    if rc == QUIET.get(tool["adapter"]):
        return []
    try:
        return (
            ADAPTERS[tool["adapter"]](out, err)
            if rc in EXITS.get(tool["adapter"], (0, 1))
            else None
        )
    except (ValueError, LookupError, TypeError, AttributeError, ET.ParseError):
        return None  # JSON, a field or the XML not as captured


def recorded(
    tree: Path,
    name: str,
    rows: list[dict],
    mine: dict[str, Path | None],
    lines: dict[str, list[str]],
    held: list[dict[str, Any]],
) -> list[dict[str, str | int]]:
    """<name>'s findings of <rows> on <mine> and <held>, booked in tree/findings/<name>.jsonl, then kept unbooked by file; `lines`: those read."""
    modules = (
        {f: module(tree, f) for f in mine}
        if any("module" in row for row in rows)
        else {}
    )
    found, files = [*held], list(mine)
    for row in rows:
        path = located(str(row.get("file")), row.get("module"), files, modules)
        if not path:
            continue
        if path not in lines:
            lines[path] = Path(tree, path).read_text(errors="replace").splitlines()
        found.append(finding(name, row, path, lines[path]))
    fresh = {p: [{**x} for x in found if x["file"] == f] for f, p in mine.items() if p}
    booked(found)
    found.sort(
        key=lambda f: (f["file"], f["line"], f["rule"], f["fingerprint"], f["message"])
    )
    (tree / "findings" / f"{name}.jsonl").write_text(
        "".join(json.dumps(f, sort_keys=True) + "\n" for f in found)
    )
    run = os.urandom(8).hex()
    for at, record in fresh.items():  # once written: a crash keeps nothing
        keep(at, {"run": run, "findings": record})
    if fresh:  # the run's mark last, after each of its files' entries: a crash before it keeps none of them (see ended)
        keep(mark(next(iter(fresh)).parent, run), [])
    return found


def filled(
    cmd: list[str],
    files: list[str],
    plan: dict[str, object],
    configs: dict[str, list[str]] | None = None,
) -> list[str]:
    """A registry command with its `{files}`, its `{engine}`, the plan's sql engine: sqlfluff's --dialect (spec 1249), and its `{configs}`:
    `--config` and each of the tool's folders whose globs match one of <files> (spec 1838)."""
    fill = {"{files}": files, "{engine}": [str(plan.get("engine"))]}
    fill["{configs}"] = [
        a
        for d, g in (configs or {}).items()
        if any(matches(f, g) for f in files)
        for a in ("--config", d)
    ]
    return [a for arg in cmd for a in fill.get(arg, [arg])]


def configured(tool: dict[str, Any], tree: Path) -> list[str]:
    """<tool>'s cmd, its `{config}` `--config` and the kit's `config.file` unless the first of `config.names` at <tree>'s root has
    `config.key` at `config.value`, a config the tool reads as it is: golangci-lint 2.x stops on a v1 one (spec 1890)."""
    own = tool.get("config", {})
    at = [tree / n for n in own.get("names", []) if (tree / n).is_file()][:1]
    kept = at and rooted(at[0], own["key"]) == own["value"]
    kit = [] if kept else ["--config", str(REGISTRY.parents[1] / own.get("file", ""))]
    return [a for arg in tool["cmd"] for a in (kit if arg == "{config}" else [arg])]


def rooted(path: Path, key: str) -> str:
    """<key> at the root of the config at <path>, "" when absent or unread: JSON and TOML parsed, YAML (the standard library reads none)
    in its block style, the key at the first column (the review, 17 Nov 2026: a text match took a nested key and missed JSON's),
    bare or in one pair of quotes (1890's review, 17 Nov 2026: a quoted "version" read as v1 and the repository's config was lost)."""
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yml", ".yaml"):
        m = re.search(rf"^([\"']?){key}\1\s*:\s*[\"']?([^\"'\s#]*)", text, re.MULTILINE)
        return m[2] if m else ""
    try:
        root = (json.loads if path.suffix == ".json" else tomllib.loads)(text)
    except ValueError:
        return ""  # a config golangci-lint cannot read either: the kit's is read
    return str(root.get(key, "")) if isinstance(root, dict) else ""


def sums(path: Path) -> list[str]:
    """Each file at or under <path>, by its name there, and its bytes' sha256; none when absent (spec 1857)."""
    paths = sorted(path.rglob("*")) if path.is_dir() else [path]
    named = {str(q.relative_to(path)): q.read_bytes() for q in paths if q.is_file()}
    return [f"{n} {hashlib.sha256(b).hexdigest()}" for n, b in named.items()]


def cached(
    cache: Path | None,
    tree: Path,
    plan: dict[str, Any],
    tool: dict[str, Any],
    mine: list[str],
) -> tuple[dict[str, Path | None], list[dict[str, Any]]]:
    """The files of <mine> <tool> runs on, each where <cache> keeps its findings by its key, and the others' kept (spec 1857)."""
    if cache is None or "alone" not in tool:
        return dict.fromkeys(mine), []
    built = [sums(REGISTRY.parent / p) for p in BUILT]
    rules = {d: sums(Path(d)) or built for d in tool.get("configs", {})}

    def digest(f: str) -> str:
        cmd = filled(tool["cmd"], [f], plan, tool.get("configs"))
        key = [sums(tree / f), tool["name"], tool["version"], cmd, *map(rules.get, cmd)]
        key += [sums(tree / d / n) for d in Path(f).parents for n in tool["alone"]]
        return hashlib.sha256(json.dumps(key).encode()).hexdigest()

    at = {f: cache / f"findings-entry-{digest(f)}.json" for f in mine}
    kept = {f: ended(p) for f, p in at.items()}
    todo: dict[str, Path | None] = {f: p for f, p in at.items() if kept[f] is None}
    return todo, [x for k in kept.values() for x in k or []]


def mark(cache: Path, run: str) -> Path:
    """Where <cache> holds the mark of <run>, written once each of its files' findings are kept there."""
    return cache / f"findings-run-{run}.json"


def ended(entry: Path) -> list[dict[str, Any]] | None:
    """The findings kept at <entry>, if a run kept them and ended: its mark beside them. No undo of a crashed run's entries can be trusted:
    the disk that failed one write fails the removals too (the review, 17 Nov 2026: a cache gone read-only at b.sh's entry kept a.sh's)."""
    if not entry.is_file():
        return None
    kept = json.loads(entry.read_text())
    return kept["findings"] if mark(entry.parent, kept["run"]).is_file() else None


def generated(tree: Path | str, tool: dict[str, Any], name: str) -> bool:
    """<name> in <tree>, handed to <tool> at `{files}`, has a line longer than MINIFIED bytes: machine output; an unread one has not (spec 1932)."""
    if "{files}" not in tool["cmd"]:
        return False
    try:
        with open(Path(tree, name), "rb") as f:
            return any(len(ENDING.sub(b"", line)) > MINIFIED for line in f)
    except OSError:
        return False


def skip_line(skipped: list[str]) -> str:
    """What a run's `skipped` says, the first three named, or "" when none (spec 1932)."""
    named = ", ".join(skipped[:3])
    return f"skipped {len(skipped)} minified files: {named}" if skipped else ""


def run(
    tree: Path | str,
    plan: dict[str, Any],
    files: list[str],
    runner: Any,
    cache: Path | None = None,
    together: bool = False,
) -> dict[str, Any]:
    """Each tool of the plan on those of `files` (a whole tool: of the plan's list for it) in its globs and in `tree`, through `runner`. Writes tree/findings/<tool>.jsonl and returns
    {"findings", "crashed", "seconds", "skipped"}. A tool that exits on a crash, not on findings, adds none: `crashed` maps it to its fault's evidence (spec 1535).
    `seconds` maps each tool that ran, a crashed one too, to its runner call's wall, not the reading after it: only here is the tool's name
    beside its run (spec 1683). A tree removed under a tool's step, its runner, its output's files or its findings' file (a late run's: the
    gate removed its scratch), is that tool's crash, so the run ends and returns the seconds of each tool (the review, 12 Nov 2026: one guard
    a round lost them at the next touch). A file or a link at findings is each tool's crash at its runner, never the analysis' raise (spec 1777).
    A tool with `alone` reads from `cache` the findings of each file kept there and runs on the others alone, if any (spec 1857). A generated
    file is handed at `{files}` to no tool and named once in `skipped` (spec 1932: four minified bundles in one biome run took 25 GB).
    `together` runs the tools side by side, those that `builds` in the tree one at a time (two write one target/ or obj/), each one's seconds
    from its turn; the findings join in the plan's order (spec 2023, 19 Nov 2026: a Java check waited 15-20 s on tools in line). Without it no
    thread starts: the gate's tools run as before."""
    registry, crashed, lines, seconds, skips = tools(), {}, {}, {}, set[str]()
    built = threading.Lock()
    out = Path(tree) / "findings"
    if not (out.exists() or out.is_symlink()):
        out.mkdir()
    for old in out.glob("*.jsonl"):
        old.unlink()  # the folder holds this run alone: no file of a tool that did not run now (review, 9 Nov)

    def one(name: str) -> list[dict[str, Any]]:
        tool = registry[name] | {"cmd": configured(registry[name], Path(tree))}
        mine = inputs(Path(tree), plan, name, files, tool["globs"])
        skips.update(minified := set(filter(partial(generated, tree, tool), mine)))
        if not (mine := sorted(set(mine) - minified)):
            return []
        todo, held = cached(cache, Path(tree), plan, tool, mine)
        with built if tool.get("builds") else threading.Lock():  # its own: no wait
            started, rows = time.monotonic(), []
            try:
                if todo:
                    cmd = filled(tool["cmd"], list(todo), plan, tool.get("configs"))
                    rc, o, e = runner(cmd, tree)
                    seconds[name] = round(time.monotonic() - started, 1)
                    if (rows := read(tool, rc, o, e)) is None:
                        said = e or o
                        crashed[name] = f"{said[-1500:]}\n{cause(said)}\nexit {rc}"
                        return []  # the exit last, its cause before it: a fault keeps a log's end (review, 9 Nov)
                return recorded(Path(tree), name, rows, todo, lines, held)
            except OSError as err:  # a runner that raised: its wall till then; one that returned keeps its own
                seconds.setdefault(name, round(time.monotonic() - started, 1))
                crashed[name] = f"{type(err).__name__}: {err}"
                return []

    with ThreadPoolExecutor(len(plan["tools"]) or 1) as pool:
        ran = list((pool.map if together else map)(one, plan["tools"]))
    found = [f for rows in ran for f in rows]
    crashed, seconds = (
        {n: d[n] for n in plan["tools"] if n in d} for d in (crashed, seconds)
    )
    return dict(findings=found, crashed=crashed, seconds=seconds, skipped=sorted(skips))


def inputs(
    tree: Path, plan: dict[str, Any], name: str, files: list[str], globs: list[str]
) -> list[str]:
    """What <name> reads: a whole tool the plan's tracked files, any other <files>; in its globs and in <tree>, so a deleted file by none (spec 2013)."""
    picked = plan.get("whole", {}).get(name, files)
    return sorted(f for f in picked if matches(f, globs) and (tree / f).is_file())


def cause(output: str) -> str:
    """Why a tool failed: its first error line, not a footer or a heading (`NOISE`), else its last line (spec 1997: Maven's, MSBuild's, uv's end is a hint)."""
    lines = [line.strip() for line in output.splitlines() if line.strip()] or [""]
    errors = (x for x in lines if "error" in x.lower() and not NOISE.fullmatch(x))
    return next(errors, lines[-1])


def annotates(tree: Path) -> bool:
    """At least half the functions in the tree's Python files carry a return type or a typed parameter, a file `ast` cannot parse adding none."""
    marks = []
    for path in held(tree, ["*.py"]):
        try:
            nodes = ast.walk(ast.parse(Path(tree, path).read_bytes()))
        except (SyntaxError, ValueError):
            continue
        for fn in (n for n in nodes if isinstance(n, DEFS)):
            params = [a for a in ast.walk(fn.args) if isinstance(a, ast.arg)]
            marks.append(fn.returns is not None or any(a.annotation for a in params))
    return 2 * sum(marks) >= len(marks)


def new(head: Found, base: Found, tree: Path | None = None) -> Found:
    """The head's findings main lacks: none whose fingerprint main has, nor one on a line the change edited in place whose tool, rule, file,
    symbol, line and message main has, one for one among main's findings no head fingerprint took (spec 1568, 11 Nov 2026: one name added to
    a test's import line made the line's 44 old findings new and red, the fingerprint holding the line's text; the review: without the line,
    a new uncited paragraph paired with main's old one the branch had cited). A head tree that does not annotate drops ruff's ANN (spec 1931)."""
    if tree is not None and not annotates(tree):
        head = [f for f in head if f["tool"] != "ruff" or f["rule"][:3] != "ANN"]
    mine, seen = {f["fingerprint"] for f in head}, {f["fingerprint"] for f in base}
    said = lambda f: (
        f["tool"],
        f["rule"],
        f["file"],
        f["symbol"],
        f["line"],
        f["message"],
    )
    left, fresh = [said(f) for f in base if f["fingerprint"] not in mine], []
    for f in head:
        if f["fingerprint"] in seen:
            continue
        if said(f) in left:
            left.remove(said(f))
        else:
            fresh.append(f)
    return fresh


def held(tree: Path, globs: list[str]) -> list[str]:
    """A checked-out tree's own files in <globs>: a whole tool on main reads main's files, not the head's list (the review, 11 Nov 2026: a
    change that deleted b.py, the helper's one caller, left main's vulture without it, and the newly dead helper read as old)."""
    paths = (
        q.relative_to(tree).as_posix() for q in Path(tree).rglob("*") if q.is_file()
    )
    return sorted(p for p in paths if ".git" not in Path(p).parts and matches(p, globs))


def base(cache, sha, checkout, plan, found: Found, runner, crashed: dict | None = None):
    """Main's findings beside the head's `found`: each tool on the files it has a head finding in, as one pairs only with its own tool (spec
    2020, 19 Nov 2026: Math-2's base ran SpotBugs for PMD's findings); a whole tool reads main's whole tree. Kept in `cache` per (main sha,
    plan, tool versions) with each tool's files done: a second feature on the same main runs no tool again on them (the quality bar: zero
    redo). A caller's `crashed` takes the tools that failed on the base; their files are tried again next call (spec 1758)."""
    registry, cache, wanted, whole = tools(), Path(cache), {}, plan.get("whole", {})
    versions = sorted((t, registry[t]["version"]) for t in plan["tools"])
    # "per tool": the record of spec 2020's shape, never read in the old one
    key = hashlib.sha256(json.dumps(["per tool", sha, versions]).encode("utf-8"))
    kept = cache / f"findings-base-{key.hexdigest()[:16]}.json"
    record = json.loads(kept.read_text()) if kept.is_file() else {}
    for x in found:
        wanted.setdefault(x["tool"], set()).add(x["file"])
        record.setdefault(x["tool"], {"files": [], "findings": []})
    if todo := {
        t: left for t in wanted if (left := sorted(wanted[t] - set(record[t]["files"])))
    }:
        tree = checkout()
        own = todo | {t: held(tree, registry[t]["globs"]) for t in todo.keys() & whole}
        ran = run(tree, {**plan, "tools": [*todo], "whole": own}, [], runner, cache)
        # each tool ran on its own list; a whole tool on main's whole tree, its findings kept for its files
        for x in ran["findings"]:
            if x["file"] in todo[x["tool"]]:
                record[x["tool"]]["findings"].append(x)
        for t in todo.keys() - ran["crashed"]:
            record[t]["files"] = sorted({*record[t]["files"], *todo[t]})
        keep(kept, record)
        if crashed is not None:
            crashed.update(ran["crashed"])
    return [x for t in wanted for x in record[t]["findings"] if x["file"] in wanted[t]]


def keep(path: Path, record: object) -> None:
    """<record> as JSON at <path> through a .tmp of its own: two checks at once (an IDE and an agent) renamed one shared .tmp away (spec 1733)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    own = path.with_suffix(f".{os.urandom(8).hex()}.tmp")
    own.write_text(json.dumps(record, sort_keys=True))
    own.replace(path)


def blocking(f, blocks):
    """An error of a rule in its tool's `blocks` ({tool: [rule]}) makes the gate red (spec 1238); `*` is every error of that tool (spec 1557:
    a shellcheck error or a gitleaks secret is a flaw by definition)."""
    rules = blocks.get(f["tool"], [])
    return f["severity"] == "error" and (f["rule"] in rules or "*" in rules)


def brief(new, blocks):
    """The gate's lines for the new findings (spec 1238), each file:line, tool, rule and message: the blocking ones, which make the gate red,
    and at most NOTES of the rest, the builder's notes, one per rule before any repeat."""
    said = lambda f: (
        f"{f['file']}:{f['line']} {f['tool']} {f['rule']}: {' '.join(f['message'].split())}"
    )
    red = [f for f in new if blocking(f, blocks)]
    rest = [f for f in new if f not in red]
    first = {
        (f["tool"], f["rule"]): f for f in reversed(rest)
    }  # each rule's first finding (spec 1641: one busy rule filled all 20)
    notes = sorted(
        rest, key=lambda f: f is not first[f["tool"], f["rule"]]
    )  # those first, in the order found, then the repeats
    return [said(f) for f in red], [said(f) for f in notes][:NOTES]


def outcomes(last: list[dict], new: list[dict], changed: set[str]) -> list[str]:
    """The fingerprints of the last gated head's findings that were `correct` (spec 1253): gone on the new head, in a <changed>
    file, one the builder's own commits changed and main's did not."""
    now = {f["fingerprint"] for f in new}
    return sorted(
        {
            f["fingerprint"]
            for f in last
            if f["fingerprint"] not in now and f["file"] in changed
        }
    )


def event(f, blocks):
    """A new finding as the feature's ledger keeps it, for the run's graph (spec 1251); no second family judges an analyser's."""
    return {
        "event": "finding",
        "fingerprint": f["fingerprint"],
        "source": f["tool"],
        "rule": f["rule"],
        "severity": f["severity"],
        "verdict": None,
        "blocking": blocking(f, blocks),
    }


# 1239's rule, the gate's and rudnik-review's one copy (spec 1255, 11 Nov 2026: review.py imports the fleet, so the CLI could not read it there).
# A blocking finding blocks unless a second family refuted it: one no verifier answered for blocks unconfirmed (safety wins over speed).
# One of a category the day's precision pass made `quiet` is a note (spec 1626).
BLOCKING = {
    "CRITICAL",
    "BLOCKER",
    "DATA-LOSS",
    "HIGH",
    "SECURITY",
    "BUG",
    "BLOAT",
    "ERROR",
}
# The tiers (spec 1784, owner 14 Nov 2026: "errors are blocking, warnings are not, info are not"): a severity claims `error` in BLOCKING,
# `warning` in WARNS, else `info`; upper-cased, so an analyser's error or warning claims a warning or more and its note or info an info.
WARNS = BLOCKING | {
    "MEDIUM",
    "MED",
    "FINDING",
    "PERF",
    "TEST-GAP",
    "SPEC",
    "DISAGREEMENT",
    "WARNING",
}
# rudnik-review's and the corpus's one prompt, so the corpus measures what ships (1784: humans raised 2.4 defects a PR, its old prompt 0.2)
REVIEW = """You review a code change an agent wrote. Report every defect a careful human reviewer would raise on it, each with its tier as
its severity: ERROR (wrong behaviour, a crash, a security hole or data loss; name the input that goes wrong), WARNING (a likely bug, a
performance or resource problem, a risky design, a changed branch no test runs), INFO (clarity, naming, a simpler form). Answer one JSON
object alone: {"findings": [{"severity": "ERROR", "category": "LOGIC", "file": "path", "line": 1, "claim": "one sentence", "scenario":
"the input"}]}, [] when none.
"""
CITED = 60  # rules of a stack a review is asked to cite, at most (spec 1802)
TIERS = ("error", "warning", "info")  # the highest first
LOCAL_ISSUES, LOCAL_REPOS = 5, 3  # the local model's bar, 16 Nov 2026 (spec 1848)


def cite(books: Books) -> str:
    """The block after REVIEW asking a review to cite the rules of <books>, a line each: the gate's, the corpus's and
    rudnik-review's one (spec 1829), stacks in sorted order, each stack's at most CITED by standing; no rules, none."""
    rules = [r for s in sorted(books) for r in sorted(books[s], key=standing)[:CITED]]
    lines = "".join(f"- [{r['id']}] ({r['tier']}) {r['look_for']}\n" for r in rules)
    said = 'When a finding is an instance of one of these rules, put the rule\'s id in its "rule" field:\n'
    return said + lines if rules else ""


def standing(rule: dict[str, Any]) -> tuple[int, int, float]:
    """The measured rules first, those whose `measured` has the corpus's tier, by tier then precision, so CITED keeps the proven (spec 1797);
    then the unmeasured in book order, cited so the citations measure them where no semgrep can (spec 1802)."""
    if not measured(rule):
        return (1, 0, 0)
    return (0, TIERS.index(rule["tier"]), -rule["measured"]["precision"])


def measured(rule: dict[str, Any]) -> bool:  # the corpus's tier, not a guess (1934)
    return "tier" in rule.get("measured", {})


def repos(rule: dict[str, Any]) -> set[str]:  # the `owner/name` of each evidence URL
    return {"/".join(e["url"].split("/")[3:5]) for e in rule["evidence"]}


def thin(rule: dict[str, Any]) -> bool:  # under the local model's bar
    return len(rule["evidence"]) < LOCAL_ISSUES or len(repos(rule)) < LOCAL_REPOS


def capped(found: list[dict[str, Any]], books: Books) -> list[dict[str, Any]]:
    """<found>, each `cap` the highest tier its `rule` has in <books>, any cap the answer carried dropped first: a supplied cap never
    raises the book's tier and a rule no book holds has none (spec 1829). blocks and tier read that cap alone."""
    tiers: dict[str, str] = {}
    for r in (r for b in books.values() for r in b):
        tiers[r["id"]] = min(r["tier"], tiers.get(r["id"], "info"), key=TIERS.index)
    kept = ({k: v for k, v in x.items() if k != "cap"} for x in found)
    return [
        x | ({"cap": tiers[x["rule"]]} if x.get("rule") in tiers else {}) for x in kept
    ]


# A builder's answer to a finding it finds wrong (spec 1253), in its commits or Claude's reply (spec 1669): the fingerprint, then why.
NOTE_WRONG = r"(?m)^NOTE-WRONG: ([0-9a-f]{12,64}): (.+)$"


def blocks(x: dict) -> bool:
    return (
        x.get("severity", "").upper() in BLOCKING
        and x.get("verdict") != "refute"
        and x.get("category") not in review()["quiet"]
        and x.get("cap", "error") == "error"
    )


def level(severity: str) -> str:
    s = severity.upper()
    return "error" if s in BLOCKING else "warning" if s in WARNS else "info"


def tier(x: dict[str, object]) -> str:
    """A finding's tier: `error` when its caller found it blocking, and only then; `info` when refuted; else its claim's, short of `error`,
    and never above its `cap`, the tier of the rule it cites (spec 1797)."""
    if x.get("blocking") and x.get("cap", "error") == "error":
        return "error"
    claimed = level(str(x.get("severity", "")))
    info = x.get("verdict") == "refute" or "info" in (claimed, x.get("cap"))
    return "info" if info else "warning"


def claim_of(x: dict) -> str:
    """What the verifier sees of a finding: severity, file:line, claim and scenario, never the reviewer's other text."""
    where = x.get("file", "?") + (f":{x['line']}" if x.get("line") else "")
    return f"{x.get('severity', 'NOTE').upper()} | {where} | {x.get('claim', '')} | {x.get('scenario', '')}"


def print_of(x: dict[str, object]) -> str:
    """A review finding's fingerprint: its claim as the verifier sees it, the one its `finding` and `outcome` records carry."""
    return hashlib.sha256(claim_of(x).encode()).hexdigest()


def whole(v: object) -> bool:
    """A whole number as JSON gives it, 1.0 too; never a boolean, though Python's True == 1 (the review, 12 Nov 2026).
    An int is whole as it stands: one too large for a float is a whole number too, never an OverflowError."""
    if isinstance(v, bool):
        return False
    return isinstance(v, int) or (isinstance(v, float) and v.is_integer())


def verdicts(
    claims: list[dict], rows: list[dict], model: str
) -> list[tuple[dict, dict]]:
    """The verifier's answer read: each claim's verdict by its n, set on the claim, and the (claim, verdict) pairs it answered."""
    answered = []
    for n, x in enumerate(claims, 1):
        said = [
            r
            for r in rows
            if isinstance(r, dict)
            and whole(r.get("n"))
            and r.get("n") == n
            and r.get("verdict") in ("confirm", "refute")
        ]  # the schema's integer takes 1.0; rows that disagree on one claim are no answer (safety wins); a model's trace may be missing (spec 1734)
        if said and len({r["verdict"] for r in said}) == 1:
            v = {
                "verdict": said[0]["verdict"],
                "trace": said[0].get("trace", ""),
                "model": model,
            }
            x.update(v)
            answered.append((x, v))
    return answered
