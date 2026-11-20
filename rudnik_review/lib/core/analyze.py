"""A checkout's stacks and the analysers that apply (spec 1235, 8 Nov 2026: the owner's Code Quality Gate v3 §1.7, §3.1, A8 -- the gate
configures itself, nobody lists a project's languages by hand). `detect(tree, tracked)` returns the plan, with no network, no model and no
git: each stack with its roots, the share/gate.toml tools that apply, and the stacks no stack tool names (gaps, said and never a stop).
The caller lists the tracked paths (the gate through state.git, spec 1238; a developer's CLI through its own git, 1255): no module of
lib/core but state.py runs git (Astra, 21 Oct), and this one imports nothing of the fleet (1255). Run: git ls-files -z | python3 -m core.analyze"""

import configparser
import json
import os
import re
import sys
from fnmatch import fnmatchcase
from pathlib import Path

import tomllib

REGISTRY = Path(__file__).resolve().parents[2] / "share" / "gate.toml"
SIGNALS = {
    "bash": ["*.sh"],
    "python": ["pyproject.toml", "requirements*.txt", "*.py"],
    "gdscript": ["project.godot", "*.gd"],
    "csharp": ["*.sln", "*.csproj"],
    "unity": ["ProjectSettings/ProjectVersion.txt"],
    "java": ["build.gradle", "build.gradle.kts", "pom.xml"],
    "sql": [
        "migrations/*.sql",
        "alembic.ini",
        "flyway.conf",
        "flyway.toml",
        "liquibase.properties",
    ],
    "docker": ["Dockerfile", "Containerfile"],
    "actions": [".github/workflows/*.yml", ".github/workflows/*.yaml"],
    "javascript": ["package.json", "tsconfig.json", "*.ts", "*.tsx", "*.js", "*.mjs"],
    "php": ["composer.json", "*.php"],
    "lua": ["*.rockspec", "*.lua"],
    "prose": ["reports/*.md", "docs/*.md"],
}
# A project's own file: a top-level folder holding one is a root of its own (a Godot client beside a Python server); a bare *.py is not.
MANIFESTS = [
    "pyproject.toml",
    "requirements*.txt",
    "project.godot",
    "*.sln",
    "*.csproj",
    "ProjectSettings/ProjectVersion.txt",
    "build.gradle",
    "build.gradle.kts",
    "pom.xml",
    "package.json",
    "tsconfig.json",
]
# The sql stack's engine, in sqlfluff's dialect names (spec 1249): the scheme of the migration tool's database URL (JDBC's after `jdbc:`), known by
# its start (postgresql+psycopg, mariadb), first; then a driver, a requirement known by its name alone.
CONFIGS, DEPENDENCIES = (
    ["alembic.ini", "flyway.conf", "flyway.toml"],
    ["pyproject.toml", "requirements*.txt"],
)
SCHEMES = {
    "postgres": "postgres",
    "mysql": "mysql",
    "mariadb": "mysql",
    "sqlite": "sqlite",
}
DRIVERS = dict.fromkeys(
    ["psycopg", "psycopg2", "psycopg-binary", "psycopg2-binary"], "postgres"
) | {"mysqlclient": "mysql", "sqlite": "sqlite"}
PIP_COMMENT = re.compile(
    r"(^|\s)#.*"
)  # pip's: a # at a line's start or after whitespace
SHEBANG = re.compile(
    rb"#!\s*\S*/(env(\s+-\S+|\s+\w+=\S*)*\s+(-S)?)?(ba)?sh(\s|$)"
)  # env's options and settings before it, -S joined too


def matches(path, globs):
    """A glob matches the path or a tail of it, its * across folders too (`migrations/*.sql` takes `db/migrations/v1/pg/002.sql`)."""
    parts = path.split("/")
    return any(
        fnmatchcase("/".join(parts[i:]), g) for g in globs for i in range(len(parts))
    )


def named(tree, tracked):
    """The paths, a bash or sh script that lacks the suffix named as one with it (`bin/fleet` is `bin/fleet.sh`)."""
    return [
        p + ".sh" if os.access(Path(tree, p), os.X_OK) and script(Path(tree, p)) else p
        for p in tracked
    ]


def script(file):
    try:
        with open(file, "rb") as f:
            return bool(SHEBANG.match(f.readline(200)))
    except OSError:
        return False


def root(path, roots):
    top = path.split("/", 1)[0]
    return top if "/" in path and top in roots else "."


def assembled(f):
    """share/gate.toml as one text: the file, then gate.toml.d/*.toml in name order (spec 1505, 9 Nov 2026: one fragment a tool), each
    on its own lines: a fragment need not end in a newline."""
    f = Path(f)
    return "\n".join(
        p.read_text() for p in [f, *sorted(f.parent.glob(f.name + ".d/*.toml"))]
    )


def covered(tools: list[dict]) -> set[str]:
    """The stacks a stack tool names: a cross-stack tool (`stacks = ["*"]`) applies to any stack and closes no gap, being no stack's own;
    nor does a formatter alone, a tool with no `cmd` (spec 1704, 12 Nov 2026: shfmt formats bash and analyses nothing)."""
    return {
        s for t in tools if t["stacks"] != ["*"] and "cmd" in t for s in t["stacks"]
    }


def signals(tools: list[dict]) -> dict[str, list[str]]:
    """SIGNALS, and beside them the files a tool's own `signals` name for each of its stacks (spec 1704, 12 Nov 2026: a developers' fragment
    carries its stack with it, so Go needs no row here)."""
    found = {s: list(g) for s, g in SIGNALS.items()}
    for t in (t for t in tools if "signals" in t):
        for s in t["stacks"]:
            found[s] = found.get(s, []) + t["signals"]
    return found


def urls(tree, path):
    """The database URLs a migration tool's config names, its URL keys alone (review, 11 Nov 2026: a search of the whole text took comments and
    other settings' values): alembic.ini's sqlalchemy.url in any section, read as alembic reads it; flyway.toml's [flyway] and [environments.*]
    url; flyway.conf's flyway.url property."""
    file = Path(tree, path)
    text = file.read_text(errors="replace")
    if file.name == "alembic.ini":
        ini = configparser.ConfigParser(interpolation=None, strict=False)
        ini.read_string(text)
        return [
            ini[s]["sqlalchemy.url"]
            for s in ini.sections()
            if "sqlalchemy.url" in ini[s]
        ]
    if file.name == "flyway.toml":
        doc = tomllib.loads(text)
        envs = doc.get("environments")
        return [
            t.get("url")
            for t in [
                doc.get("flyway"),
                *(envs.values() if isinstance(envs, dict) else []),
            ]
            if isinstance(t, dict)
        ]
    return re.findall(r"^[ \t]*flyway\.url[ \t]*[=: \t][ \t]*(\S+)", text, re.MULTILINE)


def declared(node, key=""):
    """The requirements a parsed pyproject.toml declares, under any key ending `dependencies` or `dependency-groups` (review, 11 Nov 2026: each
    round's reader knew one form fewer than the next review): [project]'s, PEP 735's groups, Poetry's main, dev and group tables, PDM's, uv's.
    There a list holds requirement strings; a table, lists of them or Poetry's `name = version`. A key of another shape is no requirement."""
    if key.endswith(("dependencies", "dependency-groups")):
        rows = node.items() if isinstance(node, dict) else [("", node)]
        return [
            r
            for k, v in rows
            for r in (
                [x for x in v if isinstance(x, str)] if isinstance(v, list) else [k]
            )
        ]
    return (
        [r for k, v in node.items() for r in declared(v, k)]
        if isinstance(node, dict)
        else []
    )


def pip_lines(file, tree, seen):
    """A requirements file's requirements as pip reads them: lines joined at `\\`, comments cut, `-e`'s target taken, `-r`'s file read too
    when the checkout holds it."""
    if file in seen or not file.is_file() or not file.resolve().is_relative_to(tree):
        return []
    seen.add(file)
    said = []
    for line in PIP_COMMENT.sub(
        "", file.read_text(errors="replace").replace("\\\n", " ")
    ).splitlines():
        option, _, rest = (
            re.sub(r"^\s*(--?[\w-]+)[\s=]*", r"\1 ", line).strip().partition(" ")
        )
        said += (
            pip_lines(file.parent / rest, tree, seen)
            if option in ("-r", "--requirement")
            else [rest]
            if option in ("-e", "--editable")
            else [line]
        )
    return said


def names(requirement):
    """The package names a requirement may install, PEP 503's spelling: PEP 508's name, a URL's #egg=, an archive's name-version.whl or .tar.gz."""
    found = [
        m[1]
        for m in [
            re.match(
                r"\s*([A-Za-z0-9][\w.-]*)\s*(\[[^]]*\]\s*)?($|[<>=!~;@(\s])",
                requirement,
            ),
            re.search(r"[#&]egg=([A-Za-z0-9][\w.-]*)", requirement),
            re.search(
                r"([A-Za-z0-9][\w.]*(-[A-Za-z][\w.]*)*)-\d[^/#]*\.(whl|tar\.gz|zip)\b",
                requirement,
            ),
        ]
        if m
    ]
    return [re.sub(r"[-_.]+", "-", n).lower() for n in found]


def requirements(tree, path):
    """The package names a manifest requires: pyproject.toml's dependency tables, a requirements file's lines."""
    file = Path(tree, path)
    said = (
        declared(tomllib.loads(file.read_text(errors="replace")))
        if file.suffix == ".toml"
        else pip_lines(file, Path(tree).resolve(), set())
    )
    return [n for r in said for n in names(r)]


def known(url):
    s = re.match(r"(?:jdbc:)?([a-z]+)", url) if isinstance(url, str) else None
    return next(
        (e for start, e in SCHEMES.items() if s and s[1].startswith(start)), None
    )


def engine(tree, files):
    """The sql stack's engine: the first URL a config names whose scheme SCHEMES knows, then the first driver among the dependencies; `ansi` with
    none. A file its format refuses names nothing (review, 11 Nov 2026: a TOML date crashed detect); a key of another shape is passed over,
    never the file it sits in (review, 11 Nov 2026: `[tool] poetry = "unused"` lost [project]'s driver)."""
    for read, name, globs in (
        (urls, known, CONFIGS),
        (requirements, DRIVERS.get, DEPENDENCIES),
    ):
        for p in (p for p in files if matches(p, globs)):
            try:
                found = read(tree, p)
            except (tomllib.TOMLDecodeError, configparser.Error):
                continue
            if e := next(filter(None, map(name, found)), None):
                return e
    return "ansi"


def detect(tree, tracked, registry=REGISTRY):
    files = named(tree, tracked)
    roots = {
        p.split("/", 1)[0]
        for p in files
        if "/" in p and matches(p.split("/", 1)[1], MANIFESTS)
    }
    tools = tomllib.loads(assembled(registry))["tool"]
    stacks, known_signals = {}, signals(tools)
    for p in files:
        for stack, globs in known_signals.items():
            if matches(p, globs):
                stacks.setdefault(stack, set()).add(root(p, roots))
    # a cross-stack tool (`stacks = ["*"]`) applies wherever a tracked file is in its globs, stack or no stack, and closes no gap:
    # it is no stack's own analyser, and a secret is a secret whatever the repository is written in (spec 1742, 12 Nov 2026)
    # an engine-bound tool (squawk: `engines = ["postgres"]`) applies to its engines alone; no postgres, no dry-run (spec 1249)
    sql = engine(tree, files) if "sql" in stacks else None
    applies = [
        t
        for t in tools
        if (t["stacks"] == ["*"] or stacks.keys() & set(t["stacks"]))
        and sql in t.get("engines", [sql])
        and any(matches(p, t["globs"]) for p in files)
    ]
    gaps = stacks.keys() - covered(tools) | (
        {"sql-dry-run"} if sql not in (None, "postgres") else set()
    )
    # a whole tool (cite, spec 1568) runs on every tracked file in its globs, whatever the change: a changed file breaks an unchanged doc's quote of it
    whole = {
        t["name"]: sorted(p for p in tracked if matches(p, t["globs"]))
        for t in applies
        if t.get("whole")
    }
    return {
        "stacks": {s: sorted(stacks[s]) for s in sorted(stacks)},
        "tools": sorted(t["name"] for t in applies),
        "gaps": sorted(gaps),
        **({"engine": sql} if sql else {}),
        **({"whole": whole} if whole else {}),
    }


if __name__ == "__main__":
    print(
        json.dumps(
            detect(
                sys.argv[1] if len(sys.argv) > 1 else ".",
                sys.stdin.read().split("\0")[:-1],
            )
        )
    )
