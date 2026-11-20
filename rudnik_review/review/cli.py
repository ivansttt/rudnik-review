"""rudnik-review: the gate's review in a developer's agent loop (spec 1255; owner, 8 Nov 2026 18:21: Cursor and Claude Code write his
developers' code). Nothing of the gate is copied: the plan is analyze.detect's, the findings, what is new and what blocks are findings.py's,
and the shipped registry says which rules block, the fleet's measurement and never a local choice; a tool's shipped developers' table,
where it sets `blocks`, says it for a developer's machine (spec 1740). Where the gate passes its container and records folder, this
passes a local runner and ~/.cache/rudnik-review; a tool that crashes is said where the gate files a fault.
  rudnik-review setup | update | check [--base REF] [--files PATH...] [--llm] [--local URL[#MODEL]] [--author MODEL] [--format text|json|sarif|github] [--all] [--hook]
  rudnik-review fmt [--files PATH...] [--all]       (spec 1703: each plan tool's formatter on the change; 2 when one failed)
  rudnik-review init [cursor | claude | codex | jetbrains | agents] (spec 1257: Cursor's loop; 1708: Claude Code's plugin; 1709: Codex's hook;
                                                    1710: Junie, the IDE; 1760: AGENTS.md; 1766: alone, each signed)
  rudnik-review hook cursor-stop | cursor-reply     (spec 1257: Cursor's agent loop; 1737: its reply, kept for the stop)
  rudnik-review hook claude-post | claude-stop      (spec 1256: Claude Code's, from the plugin in claude-plugin/)
  rudnik-review hook codex-stop                     (spec 1709: Codex's, from .codex/hooks.json)
  rudnik-review mcp                                 (spec 1640: check and explain as an agent's tools, MCP over stdio)
Exit 0 when no new finding blocks, 1 when one does, 2 when the check could not run or was refused.
--hook is the fleet builder's Claude Code Stop hook (spec 1624): the lines on stderr, a stop refused (2) once for any new finding (Claude
Code's `stop_hook_active` on stdin lets the second go: the gate judges after), and let go (0) by a check that could not run."""

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import redirect_stdout, suppress
from functools import cache, partial
from itertools import accumulate, chain, groupby
from operator import itemgetter
from pathlib import Path
from typing import Any, TypeGuard

import tomllib

# the kit's tree, or the wheel's copy of it: lib/core/ and share/ beside review/
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib/core"))
import analyze  # analyze and findings import nothing of the fleet (spec 1235, 1237)
import findings  # 1239's rule, written once
from findings import blocks, claim_of, is_test_path, print_of, verdicts, whole

D = dict[str, Any]  # a finding, or a hook's JSON

# The tools live with the release that pinned them, an uninstall takes them. An upgrade brings only its registry: the tools stay the old
# release's until its setup, so setup marks them with the registry's sha256 and a check names another's, or no mark's (spec 1713).
TOOLS, CACHE = ROOT / "tools", Path.home() / ".cache/rudnik-review"
MARK = TOOLS / "registry.sha256"
CONF = Path.home() / ".config/rudnik-review/review.toml"
WIN = os.name == "nt"
# The image's folders an analyser's argument names (structure-tools.sh, the Containerfile), each read as this machine's where the image's
# is not: the wheel's copy of the same rules, and the image's semgrep rules as setup fetched them (spec 1702, 1741, 12 Nov 2026)
RULES = TOOLS / "semgrep-rules"
IMAGE = {
    "/opt/analysers": ROOT / "share/agent-base",
    "/opt/semgrep-rules": RULES,
    "/opt/analysers/semgrep-learned": ROOT / "share/semgrep/learned",
}
OS = {"Darwin": "darwin", "Windows": "windows"}.get(platform.system(), "linux")
SYSTEM = {"darwin": "macOS", "windows": "Windows"}.get(OS, "Linux")
ARCH = "x86_64" if platform.machine().lower() in ("x86_64", "amd64") else "arm64"
PATH = [TOOLS / "venv" / ("Scripts" if WIN else "bin"), TOOLS / "bin"]
PIN = f"sha256_{platform.machine()}" if OS == "linux" else f"sha256_{OS}_{ARCH}"
JVM_BUILD = {"image": "agent-jvm", "builds": True}  # builds by mvn or gradle (1880)
# A vendor's release asset in its own words for this machine (the [desktop] table's `release`), as structure-tools.sh's release_url names Linux's.
# system and bits are Trivy's words, its asset says Linux-64bit or macOS-ARM64 (spec 1882, 17 Nov 2026)
WORDS = dict(
    os=OS,
    mac=OS.replace("darwin", "macos"),
    arch=ARCH,
    exe=".exe" if WIN else "",
    system=SYSTEM,
    bits="64bit" if ARCH == "x86_64" else "ARM64",
)
WORDS |= dict(gnu=ARCH.replace("arm64", "aarch64"), go=ARCH.replace("x86_64", "amd64"))
WORDS |= dict(x64=ARCH.replace("x86_64", "x64"), ext="zip" if WIN else "tar.gz")
# google-java-format's asset says x86-64 (spec 1707, 12 Nov 2026)
WORDS["dash"] = ARCH.replace("_", "-")
# Each family's API and the other names its models go by: OpenAI's chat API for three, Anthropic's own Messages API for its keys, as
# its compatibility layer is for trying things (spec 1738, 12 Nov 2026).
API = {
    "openai": "https://api.openai.com/v1",
    "deepseek": "https://api.deepseek.com",
    "anthropic": "https://api.anthropic.com/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
}
# 1841: the one JSON object a model the developer hosts answers about a rule and a hunk, by the json_schema those servers honour
FIELDS = {"applies": "boolean", "line": "integer", "why": "string"}
LOCAL = f"Answer with one JSON object, {json.dumps(FIELDS)}: whether the question holds of the change, at which added line, and why.\n"
EXAMPLES = "It holds of the first example, not of the second:\n"


def schema(fields: dict[str, str]) -> D:  # one object, each field required, its type
    typed = {k: {"type": v} for k, v in fields.items()}
    answer = {"type": "object", "required": [*fields], "properties": typed}
    return {"type": "json_schema", "json_schema": {"name": "answer", "schema": answer}}


FORMAT = schema(FIELDS)
# 1884: the answer's token probabilities, its yes weighed by them
SCORED = {"logprobs": True, "top_logprobs": 5}
RULE_ASK = {"response_format": FORMAT} | SCORED
# 1921 (owner, 18 Nov 2026: "local qwen freely reviewing plus rules reviewing"): the rules are mostly hygiene, so each changed file is
# also reviewed freely, unthinking, and a thinking model traces each claim; the prototype's kept only real ones over 0.9
FREE = """Review this change as a principal engineer. The lines below are an excerpt of one file of a project that builds, each led by
its number, an added one marked + and a removed one -: a name, type or import not shown is defined elsewhere, so a defect is never that one is undefined
or missing. Answer one JSON object with at most three defects the change brings in: {"defects": [{"line": 3, "claim": "what is wrong",
"scenario": "an input or state, what the code should do and what it does"}]}. Ignore style and naming; report none when the change is
correct: a false alarm costs as much as a missed bug.\n"""
TRACE = """Trace a reviewer's claim through the code below, an excerpt of one file of a project that builds, each line led by its number,
an added one marked + and a removed one -: a name, type or import not shown is defined elsewhere. Answer one JSON object, the trace first: {"trace": "the
lines followed and what they do", "real": true when the code shown misbehaves as the claim's scenario says}. `real` is false when the code already does
what the claim asks, when the claim misreads the code or rests on code not shown, when its scenario cannot happen, or when the behaviour is intended.\n"""
# 1940 (Scorecard v5, 18 Nov 2026): neither said its lines are an excerpt, so both took a constant of another file for undefined
# FREE and TRACE give its shape; 1924: at the prototype's temperature 0, a free finding's fingerprint, a hash of the model's prose,
# holds its dismissal from run to run
OBJECT = {"response_format": {"type": "json_object"}, "temperature": 0}
FREE_ASK = OBJECT | {"reasoning_effort": "none"}
# 2024 (the GPU box, 19 Nov 2026): finished traces took at most 11874 tokens, thinking counted; 9 of 37 thought to the 65536 window, 685-1141 s
TRACE_CAP = {"max_tokens": 12288}
TRACE_ASK = OBJECT | {"reasoning_effort": "medium"} | SCORED | TRACE_CAP
# 2036 (scorecard v10, 20 Nov 2026: six claims dropped with KeyError('real'), Csv-1's real bug among them)
TRACE_ASK["response_format"] = schema({"trace": "string", "real": "boolean"})
SHORT = TRACE_ASK | {"reasoning_effort": "low"}  # 2017: a cut trace's second ask
Server = tuple[str, str]  # a model's URL and name
FREE_BAR = 0.9  # a traced claim's least chance of `real`
REGION = 120  # a free review's most lines (1924)
UNUSED = re.compile(  # an unused assignment's rule:message as its adapter gives it; golangci-lint's SARIF names staticcheck, its message SA4006 (spec 2011); roslyn's S1481 (2027)
    r"(F841|RUF059|unused-variable|ineffassign|wastedassign|reportUnusedVariable|staticcheck:SA4006|S1481):"
)
KEY = os.environ.get("RUDNIK_REVIEW_LOCAL_KEY")  # 2017: oMLX, vLLM with --api-key
BEARER = {"Authorization": f"Bearer {KEY}"} if KEY else {}
HEAD = {"Content-Type": "application/json"} | BEARER  # never printed
SECONDS = int(os.environ.get("RUDNIK_REVIEW_LOCAL_SECONDS") or 600)  # its wait (2017)
HUNK = re.compile(r"(?m)^@@ -\S+ \+(\d+).*\n?")  # splits: header, start, rows, start...
FILES = re.compile(
    r"(?ms)^\+\+\+ (.*?)$(.*?)(?=^diff --git |\Z)"
)  # a diff's files: path, hunks
VERSION = "2026-10-21"  # the anthropic-version the Messages API is asked in
FAMILY = {
    "anthropic": ("claude",),
    "openai": ("gpt", "o1", "o3", "o4", "codex"),
    "gemini": ("google",),
}
# spec 1715 (12 Nov 2026): the CLI a developer is signed in to, a row a family, the prompt on stdin and the answer on stdout; no key of ours
CLI = {
    "openai": ["codex", "exec", "--sandbox", "read-only", "--skip-git-repo-check", "-"],
    "anthropic": ["claude", "-p", "--tools", ""],
}
VERIFY = """You check a reviewer's claims about a code change; you wrote neither. Follow each claim from its input in the diff yourself:
"confirm" when the wrong behaviour happens, or a warning's risk follows from its input, "refute" when not, with your trace. Answer one
JSON object alone, one verdict a claim by its n: {"verdicts": [{"n": 1, "verdict": "confirm", "trace": "the input, the lines followed,
what happens"}]}. The claims:
"""


class Refused(Exception):
    """The check cannot run as asked: exit 2."""


class Run(threading.Event):
    def __init__(self, last: D | None = None) -> None:
        super().__init__()
        self.cut: set[str] = set()
        self.late: list[str] = []
        self.last = last
        self.answers: list[object] = []

    def for_last(self, prompt: str) -> bool:  # 2014: a cut claim goes to the last word
        return prompt in self.cut and bool(self.last) and not self.is_set()


def run(
    cmd: Sequence[str | Path], text: bool = True, **kw: Any
) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(cmd, capture_output=True, text=text, **kw)


def failed(e: object) -> None:
    print(f"rudnik-review: {getattr(e, 'stderr', None) or e}", file=sys.stderr)


def git(*a, env=None):
    return run(["git", *a], check=True, env=env).stdout.strip()


def repository() -> str:
    """The repository's top, else refused in words: git's own `fatal:` names an environment variable no newcomer set (spec 2000)."""
    if (top := run(["git", "rev-parse", "--show-toplevel"])).returncode:
        raise Refused(f"run it inside a git repository (here: {Path.cwd()})")
    return top.stdout.strip()


def released() -> str:
    """The installed package's version; run from the kit's tree, unpackaged, no distribution is (spec 2000)."""
    with suppress(importlib.metadata.PackageNotFoundError):
        return importlib.metadata.version("rudnik-review")
    return "unreleased"


def path() -> str:
    """Where a tool is looked up: this release's folder first, each distribution's bin/ in it (spec 1858), then the machine's PATH."""
    return os.pathsep.join(map(str, [*PATH, *TOOLS.glob("*/bin"), os.environ["PATH"]]))


def runner(
    cmd: list[str], cwd: str, added: dict[str, str] | None = None
) -> tuple[int, str, str]:
    """findings' runner: the tool from this release's folder first, then the machine's; <added> to the environment."""
    env = {**os.environ, **(added or {}), "PATH": path()}
    cmd = [local(a) for a in cmd]
    exe = shutil.which(cmd[0], path=env["PATH"]) or cmd[0]
    seconds = float(os.environ.get("RUDNIK_REVIEW_TOOL_SECONDS", "300"))
    try:
        p = subprocess.Popen(
            [exe, *cmd[1:]],
            cwd=cwd,
            env=env,
            text=True,
            start_new_session=os.name != "nt",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as e:
        return 127, "", f"{e} (rudnik-review setup installs it)"
    with p:
        try:
            out, err = p.communicate(timeout=seconds)
        except subprocess.TimeoutExpired:
            # a tool that hangs held a check, a hook or an MCP call for ever (spec 1732): it and what it started go, its own group on
            # Linux and macOS (jscpd runs under `sh -c`); on Windows the tool itself, all that Python's subprocess can end there.
            # Exit 124, timeout(1)'s: findings reads it as a crash, so the tool is named as not checked
            if os.name == "nt":
                p.kill()
            else:
                with suppress(ProcessLookupError):
                    os.killpg(p.pid, signal.SIGKILL)
            p.wait()
            return 124, "", f"timed out after {seconds:g} s"
    return p.returncode, imaged(out), err


def imaged(out: str) -> str:
    """<out> with the rules of an image's folder named as the gate names them: semgrep's rule id is its file's path, dotted (13 Nov 2026: the
    trial's ids began tmp.….site-packages.rudnik_review.tools.semgrep-rules., so no `blocks` entry of the gate's could ever name one here)."""
    dotted = lambda p: ".".join(
        Path(p).parts[1:]
    )  # parts[0] is the root: "/" or a drive
    for image, here in IMAGE.items():
        out = out.replace(dotted(here) + ".", dotted(image) + ".")
    return out


def local(arg: str) -> str:
    """<arg> as this machine's where it names an image's folder that is not here, alone or as a `-` option's value (`--config-path=`); a
    folder in one goes in its here (spec 1838: /opt/semgrep-rules/bash). The text alone decides, never the tree: a tracked file of the
    argument's name kept Biome's config the image's (the review, 16 Nov 2026). A changed file is a path under the tree, never led by a `-`
    (every tool reads that as an option), so `src=/opt/semgrep-rules/app.py` and `src/opt/analysers/app.ts` go as they are."""
    option, eq, folder = arg.rpartition("=") if arg.startswith("-") else ("", "", arg)
    image = folder if folder in IMAGE else folder.rpartition("/")[0]
    if image not in IMAGE or Path(folder).is_dir():
        return arg
    return f"{option}{eq}{IMAGE[image]}{folder[len(image) :]}"


def snapshot(staged: bool = False) -> str:
    """The working tree as a git tree, new files too: an agent's edits are checked before they are committed, the developer's index untouched.
    <staged>: the index alone, what a commit holds (spec 1712: work not staged stopped a commit that did not hold it)."""
    with tempfile.TemporaryDirectory() as d:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(d, "index"))}
        # a copy of the developer's index, so only what changed is hashed again
        if (index := Path(git("rev-parse", "--git-path", "index"))).is_file():
            shutil.copy(index, env["GIT_INDEX_FILE"])
        if not staged:
            git("add", "-A", env=env)
        return git("write-tree", env=env)


def unpack(rev, into):
    # the tree, not the commit: a commit's archive opens with its id in a pax header, and of an empty first commit that header alone is
    # what Python's tarfile refuses as no tar (spec 1746: the trial's `check` on master over one empty commit, 13 Nov 2026)
    git("archive", "-o", f"{into}.tar", f"{rev}^{{tree}}")
    into.mkdir()  # git's empty tree archives to nothing, and the folder is still the base (spec 1731)
    shutil.unpack_archive(f"{into}.tar", into, filter="data")
    return into


def plan(tree: str | Path, rev: str) -> D:
    files = git("ls-tree", "-r", "-z", "--name-only", rev).split("\0")
    return analyze.detect(tree, [p for p in files if p])


def here(wanted: D, tree: Path) -> tuple[D, list[str]]:
    """The plan with the analysers this machine has, by name, which is the program (spec 1701, 12 Nov 2026): one never installed printed
    "crashed ... exit 127" on every check, nine such lines a developer learnt to ignore. And the ones `setup` would install, which the
    check names as not checked (spec 1730: a machine where setup never ran checked nothing and was green); those with no way here are
    named in one line; a tool with no `cmd` is no analyser. One of agent-jvm that `builds` with the tree's mvn or gradle is named once where
    none is here (spec 1880, 2034); one with no way to any developer's machine is the gate's alone, never named, as no developer can get it (spec 1984)."""
    registry = tools()
    analysers = [n for n in wanted["tools"] if registry[n].get("cmd")]
    unset, lacks = missing(analysers, registry)
    named = gettable(lacks, registry)
    absent(
        [n + unmet(registry[n]) for n in named], why=f" (no build for {SYSTEM} {ARCH})"
    )  # setup cannot mend these (13 Nov 2026: the trial was told to run it for jscpd)
    absent([], ("tools are another release's",) if stale() else ())
    kept = [n for n in analysers if n not in unset + lacks]
    build = "mvn" if (tree / "pom.xml").is_file() else "gradle"
    built = os.access(tree / f"{build}w", os.X_OK) or shutil.which(build, path=path())
    off = [n for n in kept if not built and JVM_BUILD.items() <= registry[n].items()]
    if off:
        print(f"not checked here: {', '.join(off)} (needs {build})", file=sys.stderr)
    return {**wanted, "tools": [n for n in kept if n not in off]}, unset


def stale() -> bool:
    marked = MARK.read_text(encoding="utf-8") if MARK.is_file() else ""
    return TOOLS.is_dir() and marked != registry_sum()


def absent(
    lacks: list[str],
    more: tuple[str, ...] = (),
    why: str = ". Run: rudnik-review setup",
) -> None:
    """1701's one line: the tools this machine lacks, not run, and what else setup mends; <why> what to do about them."""
    said = ([f"not installed: {', '.join(lacks)}"] if lacks else []) + list(more)
    if said:
        print(f"{'; '.join(said)}{why}", file=sys.stderr)


def missing(names: list[str], registry: dict[str, D]) -> tuple[list[str], list[str]]:
    """The <names> on no PATH here, short of their `needs` (1858: an installed pmd, no java) or rules (1865): those setup would install, and the rest."""
    ruled = Path(local("/opt/semgrep-rules")).is_dir()
    lack = [n for n in names if unmet(registry[n]) or not shutil.which(n, path=path())]
    gone = [n for n in names if n in lack or ("rules" in registry[n] and not ruled)]
    can = [n for n in gone if installable(registry[n])]
    return can, [n for n in gone if n not in can]


def unfound(cmds: list[list[str]]) -> list[str]:
    """The programs of <cmds> on no PATH here."""
    return [c[0] for c in cmds if not shutil.which(c[0], path=path())]


def installable(tool: D) -> bool:
    """`setup` has a way to put the tool on this machine: pip, or a release pinned for it, where the tool's `platforms`, if any, name
    this machine (spec 1706, 12 Nov 2026: PyPI has no taplo wheel for Linux arm64, which would fail the whole pip batch). A release with
    a link needs its pin here as one alone does (spec 1868: Infer, pinned for two platforms, crashed setup on Linux arm64)."""
    here = f"{OS}/{ARCH}" in tool.get("platforms", [f"{OS}/{ARCH}"])
    pinned = tool.get(PIN) if "release" in tool else "link" in tool
    way = {"pip", "runs"} & tool.keys() or pinned
    return here and not unmet(tool) and bool(way)


def unmet(tool: D) -> str:
    """' without' the programs the tool `needs` that no PATH here has, or nothing (spec 1858: PMD runs on the developer's own java). javac
    is had at the image's JDK release or later, as javac-ep passes it flags no JDK 8 takes: the pin moves the floor (spec 1871)."""
    lack = [p for p in tool.get("needs", []) if not shutil.which(p, path=path())]
    if "javac" in tool.get("needs", []) and ("javac" in lack or javac() < jdk()):
        lack = [p for p in lack if p != "javac"] + [f"javac {jdk()} or later"]
    return f" without {', '.join(lack)}" if lack else ""


@cache
def javac() -> int:
    """The major release the javac here reports: `javac 21.0.5` is 21, JDK 8's `javac 1.8.0_402` 1."""
    said = run([shutil.which("javac", path=path()) or "javac", "-version"])
    found = re.search(r"javac (\d+)", said.stdout + said.stderr)
    return int(found[1]) if found else 0


def jdk() -> int:
    """The major release of the JDK the agent-jvm image pins."""
    pin = tomllib.loads(analyze.assembled(findings.REGISTRY))["agent-jvm"]["jdk"]
    return int(pin.partition(".")[0])


def fragments() -> list[Path]:
    """The developers' registry beside the gate's, one fragment a spec in name order (spec 1757, 12 Nov 2026)."""
    return sorted(findings.REGISTRY.parent.glob("gate.toml.d/desktop.toml.d/*.toml"))


def registry_sum() -> str:
    """The shipped registry's sha256, the gate's assembled text then the developers' fragments: review-release attaches it to the
    release, and a changed desktop pin changes it (spec 1757)."""
    text = "\n".join(
        [
            analyze.assembled(findings.REGISTRY),
            *(p.read_text(encoding="utf-8") for p in fragments()),
        ]
    )
    return hashlib.sha256(text.encode()).hexdigest()


def desktop() -> dict[str, D]:
    """The [desktop.<name>] tables, each fragment's keys over the assembled registry's (a fixture's names its own) and the earlier ones'.
    Merged, not joined: TOML refuses one tool's table defined twice; a key two fragments set is refused, both named (spec 1757)."""
    tables = tomllib.loads(analyze.assembled(findings.REGISTRY)).get("desktop", {})
    setter: dict[tuple[str, str], str] = {}
    for p in fragments():
        for name, keys in (
            tomllib.loads(p.read_text(encoding="utf-8")).get("desktop", {}).items()
        ):
            for key in keys:
                if (first := setter.setdefault((name, key), p.name)) != p.name:
                    raise Refused(
                        f"[desktop.{name}] {key} is set by both {first} and {p.name}: one fragment sets each key"
                    )
            tables[name] = tables.get(name, {}) | keys
    return tables


def tools() -> dict[str, D]:
    """The registry's tools, each with its [desktop.<name>] table laid over (spec 1700): the developers' registry, staged into the wheel,
    says how this machine gets the tool (`pip`, `release`) and pins its Windows and macOS builds."""
    ways = desktop()
    return {n: t | ways.get(n, {}) for n, t in findings.tools().items()}


def gettable(names: list[str], registry: dict[str, D]) -> list[str]:
    """The <names> setup can install here, or with a [desktop] table, a `from` or no `cmd` (a developers' formatter): an analyser with none
    is the gate's alone, as inspectcode, jscpd and cite are (spec 1984), whatever `pip`, `release` or `platforms` it holds for other
    machines (spec 1991: those were still named)."""
    tables = desktop()
    return [
        n
        for n in names
        if n in tables
        or "from" in registry[n]
        or "cmd" not in registry[n]
        or installable(registry[n])
    ]


def setup(a: argparse.Namespace, only: list[str] | None = None) -> int:
    """The plan's analysers at the registry's versions: pip into the release's venv, else the vendor's binary checked by its
    sha256 (Linux's in the tool's fragment when the image vendors it, else in its [desktop] table with Windows' and macOS'); a tool with
    no way here is said once, a gap. <only>: these tools alone, no command's setup (spec 1865). A `deep` tool only with --deep, unnamed
    otherwise (spec 1998: Infer's 1.2 GB fetched for every Java developer, run only by check --deep)."""
    os.chdir(git("rev-parse", "--show-toplevel"))
    wanted = shallow(plan(".", snapshot()), getattr(a, "deep", False))[0]
    registry, pips = tools(), {}
    PATH[1].mkdir(parents=True, exist_ok=True)
    for name in gettable(wanted["tools"] if only is None else only, registry):
        tool = registry[name]
        # spec 1768: the developer's toolchain brings it, never a gap; said where its program is not
        if "from" in tool:
            for program in unfound(tool.get("fmt", [[name]])):
                print(
                    f"{name}: from the developer's {tool['from']}: {program} is not on the PATH"
                )
        elif not installable(tool):
            print(
                f"{name}: cannot be installed on {SYSTEM} {ARCH}{unmet(tool)}, so its checks are skipped here"
            )
        elif "pip" in tool:
            pips[name] = f"{tool['pip']}=={tool['version']}"
            if "rules" in tool:
                checkout(name, tool)
        elif "runs" in tool:
            launch(name, tool["runs"])
        else:  # both for a table with both: SpotBugs' distribution and the analyse that starts it (spec 1867)
            if "release" in tool:
                fetch(name, tool)
            if "central" in tool:
                jars(name, tool["central"])
            if "link" in tool:  # and its aliases: error-prone's javac-ep (spec 1871)
                for alias in [name, *tool.get("aliases", [])]:
                    link(alias, ROOT / tool["link"])
    if pips:
        install(pips)
    for stack in wanted["gaps"]:
        print(f"{stack}: no analyser yet; it is formatted and scanned for secrets only")
    MARK.write_text(registry_sum(), encoding="utf-8")
    return 0


def set_up_lacking(a: argparse.Namespace) -> None:
    """What the repository's plan lacks, set up quietly in one line; nothing said when nothing lacks. The bare command's start, and init's
    end (spec 2043, 20 Nov 2026: the .claude/settings.json init wrote called for trivy, which setup never installed, so every check said
    `not checked` and a clean change exited 2)."""
    os.chdir(repository())
    wanted, registry = shallow(plan(".", snapshot()), False)[0], tools()
    every = [n for n in wanted["tools"] if installable(registry[n])]
    if lacking := every if stale() else missing(wanted["tools"], registry)[0]:
        print(f"setting up for {', '.join(wanted['stacks'])}: {', '.join(lacking)}")
        # each tool's own line is the one above, a tool with no way here check's closing line; a failure is still raised
        with open(os.devnull, "w", encoding="utf-8") as quiet, redirect_stdout(quiet):
            setup(a, lacking)


def setup_and_check(a: argparse.Namespace) -> int:
    set_up_lacking(a)
    return check(parser().parse_args(["check"]))


def install(pips: dict[str, str]) -> None:
    """The pins into the release's venv through uv where the PATH has it, else the venv and pip of the Python this runs in (spec 1739,
    12 Nov 2026): uv installed the program, but no shell, IDE or agent that later runs setup is told where uv is. A step that fails is
    said in words, with the installer's `findings.cause`, not as Python's error."""
    venv = TOOLS / "venv"
    if shutil.which("uv"):
        make, pip = (
            ["uv", "venv", "-q", "--allow-existing", venv],
            ["uv", "pip", "install", "-q", "--python", venv],
        )
    else:
        make, pip = (
            [sys.executable, "-m", "venv", venv],
            [PATH[0] / f"python{WORDS['exe']}", "-m", "pip", "install", "-q"],
        )
    for step in (make, [*pip, *pips.values()]):
        if (done := run(step)).returncode:
            why = findings.cause(done.stderr or done.stdout)
            raise Refused(f"could not install {', '.join(pips)}: {why}")


def update(_: argparse.Namespace) -> int:
    """The release repository's later release, then its setup in a new process: this one runs the old release's code (spec 1713). The
    upgrade writes the new cli.py where this one was, so this interpreter runs it from there: no PATH need hold the tool's folder (the review)."""
    subprocess.run(["uv", "tool", "upgrade", "rudnik-review"], check=True)
    return subprocess.run([sys.executable, __file__, "setup"], check=False).returncode


def fetch(name: str, tool: D) -> None:
    """The vendor's binary into the tool folder, refused unless its sha256 is the registry's. A distribution's `folder` is kept whole as
    <tools>/<name>, at another version replaced: PMD's bin/pmd starts the jars in the lib/ beside it (spec 1858, 17 Nov 2026)."""
    version, pin = tool["version"], tool[PIN]
    asset = tool.get(f"release_{OS}", tool["release"]).format(v=version, **WORDS)
    url, exe = f"https://github.com/{asset}", name + WORDS["exe"]
    to = TOOLS / name if "folder" in tool else PATH[1] / exe
    data = downloaded(name, url, pin)
    with tempfile.TemporaryDirectory() as d:
        (got := Path(d, url.rpartition("/")[2])).write_bytes(data)
        if got.suffix in (".zip", ".gz", ".tgz", ".xz"):  # else the asset is it
            shutil.unpack_archive(got, d)
            got = next(Path(d).rglob(tool.get("folder", exe).format(v=version)))
        shutil.rmtree(to, ignore_errors=True)  # the folder at another version
        shutil.move(got, to)
    for x in [to, *to.glob("bin/*")]:  # a zip unpacks with no modes
        x.chmod(0o755)
    print(f"{name} {version}: {to}")


def jars(name: str, central: dict[str, str]) -> None:
    """Each jar the image takes from Maven Central, by its URL and sha256, into <tools>/<name>, which keeps no other version (spec 1871)."""
    shutil.rmtree(to := TOOLS / name, ignore_errors=True)
    to.mkdir()
    for url, pin in central.items():
        (to / url.rpartition("/")[2]).write_bytes(downloaded(name, url, pin))
    print(f"{name}: {to}")


def downloaded(name: str, url: str, pin: str) -> bytes:
    """The whole <url> as it is, refused unless its sha256 is <pin>."""
    data = urllib.request.urlopen(url, timeout=300).read()
    if (sha := hashlib.sha256(data).hexdigest()) != pin:
        raise Refused(f"{name}: {url} has sha256 {sha}, expected sha256 {pin}")
    return data


def launch(name: str, runs: list[str]) -> None:
    """<name> beside the other tools as a launcher of <runs> with the caller's arguments: cpd is `pmd cpd`, as in the image (spec 1858)."""
    line, to = " ".join(runs), PATH[1] / (name + ".cmd" * WIN)
    to.write_text(f"@{line} %*\n" if WIN else f'#!/bin/sh\nexec {line} "$@"\n', "utf-8")
    to.chmod(0o755)


def link(name: str, script: Path) -> None:
    """<name> beside the other tools as a symlink to the package's <script>, whose basename case picks the tool, kept executable as a wheel
    may unpack it without its mode: roslyn is share/agent-dotnet/analyse, as in the image (spec 1860, 17 Nov 2026)."""
    script.chmod(0o755)
    (to := PATH[1] / name).unlink(missing_ok=True)
    to.symlink_to(script)


def checkout(name: str, tool: D) -> None:
    """The tool's rules at their pinned commit into the tools folder, as the Containerfile fetches the image's, once a release: only the
    folders it names, since semgrep reads the whole folder and a root file such as .pre-commit-config.yaml fails its scan (spec 1741,
    12 Nov 2026). Refused unless HEAD is the commit, git's own check. Kept only at the commit with the folders it names: an upgrade that
    names more at the same commit checks them out again (spec 1856, 16 Nov 2026)."""
    commit, at = tool["rules_commit"], ["git", "-C", RULES]
    head, listed = [*at, "rev-parse", "HEAD"], [*at, "sparse-checkout", "list"]
    kept = RULES.is_dir() and run(head).stdout.strip() == commit
    if kept and run(listed).stdout.split() == tool["rules_folders"]:
        return
    shutil.rmtree(RULES, ignore_errors=True)
    for step in (
        ["init", "-q", RULES],
        ["-C", RULES, "sparse-checkout", "set", "--no-cone", *tool["rules_folders"]],
        ["-C", RULES, "fetch", "-q", "--depth", "1", tool["rules"], commit],
        ["-C", RULES, "checkout", "-q", "FETCH_HEAD"],
    ):
        if (done := run(["git", *step])).returncode:
            raise Refused(
                f"{name}: no rules at {commit} from {tool['rules']}: {done.stderr.strip()}"
            )
    if (got := run(head).stdout.strip()) != commit:
        raise Refused(f"{name}: {tool['rules']} gave {got}, expected {commit}")
    print(f"{name} rules {commit[:12]}: {RULES}")


def found(
    a: argparse.Namespace,
) -> tuple[list[D], str, Future[list[D]], str, list[str], str]:
    """The gate's analysis (steps.analysis) against the merge base, its runner local and its records this cache: the analysers' new
    findings, the change's diff for the model review, which is another step (a refused review keeps them, the review, 11 Nov 2026), the
    --local lane, started beside the analysers once the change is known (1957), the line of what was not checked, or none (spec 1730; one setup would install only where it reads a file, 2013), the change's stacks,
    whose rules the review cites (spec 1797), and what was checked; the rules not shown, those --local does not ask among them, said once (1934)."""
    mb, rev, names = change(a)
    shipped = {n: t.get("blocks", []) for n, t in tools().items()}
    named = lambda f: f["rule"] in shipped.get(f["tool"], [])
    # as git writes it: bytes, so no \r in a line is read as its end (text=True's universal newlines did)
    diff = run(
        ["git", "diff", "--no-renames", mb, rev], text=False, check=True
    ).stdout.decode(errors="replace")
    with tempfile.TemporaryDirectory() as d:
        tree = unpack(rev, Path(d, "head"))
        planned, later = shallow(plan(tree, rev), getattr(a, "deep", False))
        wanted, unset = here(planned, tree)
        reads = lambda t: findings.inputs(tree, wanted, t, names, tools()[t]["globs"])
        unset = list(filter(reads, unset))
        pool, stacks = ThreadPoolExecutor(1), list(wanted["stacks"])
        pending = pool.submit(lane, a, diff, rev, stacks)
        pool.shutdown(wait=False)
        head: D = findings.run(tree, wanted, names, runner, CACHE, together=True)
        checkout = partial(unpack, mb, Path(d, "base"))
        based: dict[str, str] = {}
        old = findings.base(
            CACHE, mb, checkout, wanted, head["findings"], runner, based
        )
        # a tool that failed on the base has nothing its head findings can be new against: none is a row, and it is not checked (spec 1758)
        lost = {
            t: why
            for t, why in based.items()
            if any(f["tool"] == t for f in head["findings"])
        }
        new = [*moved(findings.new(head["findings"], old, tree), diff)]
        checked = checked_by(tree, names, set(head["crashed"])) if names else ""
        checked += f" ({', '.join(later)}: with --deep)" if checked and later else ""
        gone = upheld()
        books = findings.books(list(wanted["stacks"]))
        rows = [  # a rule `blocks` names blocks as a warning too: Error Prone and Roslyn say a defect so (spec 1996, 19 Nov 2026)
            {**f, "blocking": named(f) or findings.blocking(f, shipped)}
            for f in new
            if f["fingerprint"] not in gone and f["tool"] not in lost
            if not unshown(f, books)
        ]
    not_shown(new, books, diff if getattr(a, "local", None) else "")
    return rows, diff, pending, not_checked(head, unset, lost), stacks, checked


def moved(new: list[D], diff: str) -> Iterator[D]:
    """<new>, an unused assignment on a line the change did not add (<to>, the added lines from its own to 5 below) at the nearest added line 1 to 5 below, its message naming its own line and its fingerprint kept for upheld() and the base (spec 2011, 19 Nov 2026: v8's wrong-variable defects sat under the F841 that named them)."""
    added = {(h["file"], n) for h in hunks(diff) for n in h["added"]}
    for f in new:
        to = [n for n in range(f["line"], f["line"] + 6) if (f["file"], n) in added]
        if not UNUSED.match(f"{f['rule']}:{f['message']}") or f["line"] in to or not to:
            yield f
            continue
        yield {**f, "line": to[0], "message": f"{f['message']} (at line {f['line']})"}


def shallow(planned: D, deep: bool) -> tuple[D, list[str]]:
    """The plan short of its `deep` tools unless <deep>, and those, which a plain check names (spec 1868: Infer captures the whole build,
    minutes on a real project, so only check --deep runs it)."""
    registry = tools()
    later = [] if deep else [n for n in planned["tools"] if registry[n].get("deep")]
    return {**planned, "tools": [n for n in planned["tools"] if n not in later]}, later


def checked_by(tree: Path, names: list[str], crashed: set[str]) -> str:
    """A text check's closing line before its counts (spec 1866): the files by each stack owning them, by its signals or a one-stack tool's globs (2000: `.java` was `other`), else `other`, and the analysers run."""
    registry = tools().values()
    own = [{**t, "signals": t["globs"]} for t in registry if t["stacks"] != ["*"]]
    stacks, files = analyze.signals([*registry, *own]), analyze.named(tree, names)
    owners = {f: [s for s, g in stacks.items() if analyze.matches(f, g)] for f in files}
    kinds = Counter(s for f in files for s in owners[f] or ["other"])
    by = ", ".join(f"{s} {n}" for s, n in kinds.items())
    booked = {p.stem for p in tree.glob("findings/*.jsonl")}
    ran = ", ".join(sorted(booked | crashed))
    return f"checked {len(names)} changed file{'s' * (len(names) != 1)} ({by}) with {ran or 'no analyser'}"


def not_checked(head: D, unset: list[str], lost: dict[str, str]) -> str:
    """One line of what a check did not look at, or none: the tools of <head>, findings.run's result, that failed, each with its exit and the last line it said before (a
    crash's evidence ends in `exit <rc>`; 1732: `timed out after 300 s`), those `setup` would install (spec 1730), and those that failed
    on the base (spec 1758), and the files skipped as minified (spec 1932). A `deep` one's setup is setup --deep (spec 1998)."""
    deep = {n for n, t in tools().items() if t.get("deep")}
    skipped = [
        *(f"{t} failed {crash_line(why)}" for t, why in head["crashed"].items()),
        *(f"{t} failed on the base {crash_line(why)}" for t, why in lost.items()),
        *(
            f"{t} is not installed (run: rudnik-review setup{' --deep' * (t in deep)})"
            for t in unset
        ),
        *filter(None, [findings.skip_line(head["skipped"])]),
    ]
    return f"not checked: {'; '.join(skipped)}" if skipped else ""


def crash_line(why: str) -> str:
    """A crash's evidence as `(exit 3): its last line with text`, or `(<the runner's error>)` where no exit ended it."""
    *before, last = [line for line in why.splitlines() if line.strip()] or [""]
    return (
        f"({last}): {before[-1]}"
        if last.startswith("exit ") and before
        else f"({last})"
    )


def change(a: argparse.Namespace) -> tuple[str, str, list[str]]:
    """From the repository's top: the merge base, the working tree as a tree, and the files the change touches, or --files."""
    top = Path(repository()).resolve()
    files = [Path(f).resolve().relative_to(top).as_posix() for f in a.files or []]
    os.chdir(top)
    base = a.base or upstream(getattr(a, "hook", False))
    mb, rev = merged(base), snapshot(getattr(a, "staged", False))
    # raw, as git() strips a name's own leading space (the review, 19 Nov 2026: a tracked ` file.py` was refused)
    listed = run(["git", "ls-tree", "-z", "--name-only", rev, "--", *files], check=True)
    held = listed.stdout.split("\0")
    why = lambda f: "ignored by git" if Path(f).exists() else "no such file"
    if lost := [f"{f} ({why(f)})" for f in files if f not in held]:
        raise Refused(f"never checked, as the change's tree lacks: {', '.join(lost)}")
    return (
        mb,
        rev,
        files or git("diff", "--name-only", "--no-renames", mb, rev).splitlines(),
    )


def fmt(a: argparse.Namespace) -> int:
    changed, broke, lacks = formats(a)
    absent(lacks)
    for f in changed:
        print(f)
    for name, why in broke.items():
        failed(f"{name} could not format: {why}")
    return 2 if broke else 0


def formats(a: argparse.Namespace) -> tuple[list[str], dict[str, str], list[str]]:
    """Each plan tool's `fmt` (spec 1703, owner 12 Nov 2026: each language's standard formatter) on the change's files in its globs, or
    --files, or with --all every tracked file, in the working tree: the files it changed, each tool that failed with why, and those this
    machine lacks. No command passes a style: each formatter finds the repository's own config from the file, else its defaults."""
    rev, names = formattable(a)
    wanted, registry = plan(".", rev), tools()
    mine = {n: registry[n] for n in wanted["tools"] if "fmt" in registry[n]}
    lacks = [n for n, t in mine.items() if unfound(t["fmt"])]
    changed, broke = [], {}
    for name in [n for n in mine if n not in lacks]:
        mended, broke[name] = formatted(mine[name], names, wanted, rev)
        changed += [f for f in mended if f not in changed]
    return changed, {n: why for n, why in broke.items() if why}, lacks


def formattable(a: argparse.Namespace) -> tuple[str, list[str]]:
    """From the repository's top: the working tree as a tree, and the change's files, or with --all every tracked file."""
    if not getattr(a, "all", False):
        return change(a)[1:]
    os.chdir(git("rev-parse", "--show-toplevel"))
    return snapshot(), git("ls-files", "-z").split("\0")


def formatted(tool: D, names: list[str], wanted: D, rev: str) -> tuple[list[str], str]:
    """<tool>'s `fmt` on those of <names> in its globs: the files it changed, and why it failed, if it did."""
    files = [
        f for f in names if findings.matches(f, tool["globs"]) and Path(f).is_file()
    ]
    if not files:
        return [], ""
    if not any("{files}" in c for c in tool["fmt"]):
        return copied_back(tool["fmt"], files, wanted, rev)
    before = {f: Path(f).read_bytes() for f in files}
    # ./-prefixed, as build.formats passes them: a file named `--example.py` is a file, never an option (the review, 12 Nov 2026)
    why = ran(tool["fmt"], [f"./{f}" for f in files], wanted)
    return [f for f in files if Path(f).read_bytes() != before[f]], why


def copied_back(
    cmds: list[list[str]], files: list[str], wanted: D, rev: str
) -> tuple[list[str], str]:
    """A whole-tree `fmt` (spec 1768: `cargo fmt --all` formats every file of the crate) on a copy of the working tree: only those of
    <files> it changed come back, so no file outside the selection, and none outside the repository, is written."""
    with tempfile.TemporaryDirectory() as d:
        # a tracked link out of the repository, which cargo would follow, is refused by unpack's filter
        try:
            tree = unpack(rev, Path(d, "tree")).resolve()
        except tarfile.FilterError as e:
            return [], f"{e}: fmt writes nothing outside the repository"
        if why := ran(cmds, [], wanted, str(tree), {"RUSTFMT": guard(tree)}):
            return [], why
        mended = [
            f
            for f in files
            if (tree / f).is_file() and (tree / f).read_bytes() != Path(f).read_bytes()
        ]
        for f in mended:
            shutil.copyfile(tree / f, f)
    return mended, ""


def guard(tree: Path) -> str:
    """A rustfmt for cargo fmt's `$RUSTFMT`, beside <tree>: rustfmt's own list of the files it would write (`--check -l`, the modules it
    follows included), and the real run only when each is in <tree>. The review, 12 Nov 2026, twice: a `[lib] path`, then a raw-string
    `#[path]`, named a file outside that cargo fmt formatted in place; parsing cargo's inputs to foresee that was wrong both ways."""
    script = tree.with_name("rustfmt")
    script.write_text(
        "#!/bin/sh\n"
        'rustfmt --check -l "$@" | while IFS= read -r f; do\n'
        f'  case "$(realpath "$f")" in {shlex.quote(str(tree))}/*) ;;\n'
        '  *) echo "$f is outside the repository, which fmt never writes" >&2; exit 1 ;; esac\n'
        "done || exit 1\n"
        'exec rustfmt "$@"\n',
        encoding="utf-8",
    )
    script.chmod(0o700)
    return str(script)


# sqlfluff's --dialect overrides the repository's own config, so it goes only where sqlfluff finds none, as the plan's engine (spec 1727)
NO_DIALECT = "No dialect was specified"


def ran(
    cmds: list[list[str]],
    files: list[str],
    wanted: D,
    cwd: str = ".",
    env: dict[str, str] | None = None,
) -> str:
    """<cmds> in turn, as a `fix`'s are, on <files> in <cwd> with <env> added; the first that fails ends them, and its last line says why."""
    for cmd in cmds:
        rc, out, err = runner(findings.filled(cmd, files, wanted), cwd, env)
        if rc and NO_DIALECT in err:
            rc, out, err = by_folder(cmd, files, wanted, cwd, env)
        if rc:
            said = (err or out).strip().splitlines()
            return said[-1] if said else f"exit {rc}"
    return ""


def by_folder(
    cmd: list[str], files: list[str], wanted: D, cwd: str, env: dict[str, str] | None
) -> tuple[int, str, str]:
    """<cmd> on <files> in <cwd> one folder at a time, since sqlfluff reads each file's config from its folder up, with `--dialect` only on a
    folder that still finds none: one bare file in a batch fails the whole batch, unchanged, and must not override another folder's
    dialect (the review, 12 Nov 2026). The first that fails ends them."""
    folders: dict[Path, list[str]] = {}
    for f in files:
        folders.setdefault(Path(f).parent, []).append(f)
    for group in folders.values():
        rc, out, err = runner(findings.filled(cmd, group, wanted), cwd, env)
        if rc and NO_DIALECT in err:
            dialected = [*cmd, "--dialect", "{engine}"]
            rc, out, err = runner(findings.filled(dialected, group, wanted), cwd, env)
        if rc:
            return rc, out, err
    return 0, "", ""


def check(a: argparse.Namespace) -> int:
    if a.hook and json.load(sys.stdin).get("stop_hook_active"):
        return 0  # 1673 (12 Nov 2026): the second stop is let go before any analysis, not after a whole one
    # 1921: never silently ignored, or the developer would think a verifier ran
    if a.local_verifier and not a.local:
        raise Refused("--local-verifier needs --local")
    rows, diff, pending, unchecked, stacks, checked = found(a)
    if unchecked:  # said before the model is asked: a review that raises never hides it (spec 1730)
        print(unchecked, file=sys.stderr)
    try:
        rows += llm(diff, stacks, a.author, rows, "") if a.llm else []
        rows += pending.result()
    except Exception as e:  # said, and the exit still decided (spec 1730)
        if a.hook:
            raise  # main's handler lets the stop go: the gate judges after
        failed(e)
        return exit_code(rows, unchecked=True)
    finally:  # the analysers' findings are printed whatever the review does (spec 1715)
        printed(a, rows, checked)
    top = Path.cwd()
    if a.format == "sarif":
        print(f"SARIF: {sarif(rows, top / rudnik('review.sarif'))}")
    if a.hook:  # 11 Nov 2026: the builder learnt of a finding only when the gate went red, a whole round later. Refused once, then let
        # go: a session that may not fix the finding (a spec's tests-only acceptance, 11 Nov 16:00) was refused every stop and ended empty
        return 2 if rows else 0
    return exit_code(rows, unchecked=bool(unchecked))


def lane(a: argparse.Namespace, diff: str, rev: str, stacks: list[str]) -> list[D]:
    """--local's findings on the change, none without it: <diff>, <rev> the tree analysed, whose files it reviews freely (1921), and <stacks>' rules."""
    if not getattr(a, "local", None):
        return []
    # 1934: a measured rule alone, thin or not once the corpus measured it `local` (1905)
    books = laptop(findings.books(stacks), findings.measured)
    # 1924: the variable is --local's default alone: by itself it refused every plain check
    env = os.environ.get("RUDNIK_REVIEW_LOCAL_VERIFIER", "")
    return hosted(a.local, diff, books, rev, a.local_verifier or env)


def printed(a: argparse.Namespace, rows: list[D], checked: str) -> None:
    """check's rows in its --format, on stderr for the hook; the text ends in what was checked (spec 1866), ruff's unproven notes counted
    by rule, most first, ties in name order (spec 1869: Counter.most_common keeps a tie in the order it met it); blocking counts places
    to fix (spec 2005, 19 Nov 2026: basedpyright's and ruff's lines for one typo read "2 blocking")."""
    listed = [r for r in rows if not unlisted(a, r)]
    hidden = Counter(sorted(r["rule"] for r in rows if unlisted(a, r)))
    lines = [*map(command if a.format == "github" else said, listed)]
    tally = ", ".join(f"{rule} x{n}" for rule, n in hidden.most_common())
    lines += [f"notes not listed: ruff {tally} (--all lists them)"] if tally else []
    stops = [(r["file"], r.get("line")) for r in filter(itemgetter("blocking"), rows)]
    more = f", {hidden.total()} not listed" if tally else ""
    counts = f": {len(set(stops))} blocking, {len(listed) - len(stops)} notes{more}"
    ending = checked + counts if checked else "nothing to check: no changed file"
    lines += [ending] if a.format == "text" else []
    text = json.dumps(rows, indent=1) if a.format == "json" else "\n".join(lines)
    print(text or "no new finding", file=sys.stderr if a.hook else sys.stdout)


def unlisted(a: argparse.Namespace, r: D) -> bool:
    """A note the text counts by rule without --all (spec 1869): ruff's, its rule not in `blocks`, where spec 1626's precision pass puts
    a rule it proved (owner, 17 Nov 2026: 245 of a day's 268 notes were ruff's); a model's finding is never one."""
    ruffs = r.get("tool") == "ruff" and "source" not in r
    return a.format == "text" and not a.all and ruffs and not r["blocking"]


def command(r: D) -> str:
    """A finding as GitHub's workflow command (spec 1714): shown on the pull request's changed line on every plan, where SARIF needs
    GitHub's paid code scanning on a private repository; ::error, ::warning or ::notice by its tier (spec 1784)."""
    tool = "source" not in r
    title = f"{r['tool']} {r['rule']}" if tool else f"review {r.get('severity')}"
    where = f"file={escaped(r.get('file', ''), ':,')},line={r.get('line', '')},title={escaped(title, ':,')}"
    kind = {"error": "error", "warning": "warning", "info": "notice"}[findings.tier(r)]
    return f"::{kind} {where}::{escaped(r['message'] if tool else r['claim'])}"


def escaped(text: str, also: str = "") -> str:
    """Text as GitHub's commands take it: `%`, CR and LF always, a property's `:` and `,` too, each as %XX."""
    return "".join(f"%{ord(c):02X}" if c in "%\r\n" + also else c for c in str(text))


def exit_code(rows: list[D], unchecked: bool) -> int:
    """1 for a blocking finding, the stronger word; else 2 when something was not checked, which 0 must never mean (spec 1730)."""
    return 1 if any(r["blocking"] for r in rows) else 2 if unchecked else 0


# What `init <tool>` wires (spec 1708; Cursor's three, 1257), a row a file: the file, its tool, its template beside this file (so in
# the wheel) and the tool's signs, by which `init` alone wires it: a path in the repository (a folder ends in /, 1760's AGENTS.md is a
# file) or a program on the PATH (1766: a developer with two tools ran init twice and had to know their names). 1714 adds rows and no
# code (1772: GitHub's pull request workflow). A row of no tool is every repository's, at the path git names (1712: the commit's
# hook, in the team's own folder where core.hooksPath names one).
# JetBrains' (1710): Junie reads Cursor's mcp.json shape from .junie/, and the IDE runs `fmt` on a saved file by its File Watcher, for
# the developer's typing and Junie's edits alike.
TEMPLATES = Path(__file__).resolve().parent / "templates"
CURSOR, CLAUDE, CODEX, JETBRAINS, AGENTS = (
    (".cursor/", "cursor"),
    (".claude/", "claude"),
    (".codex/", "codex"),
    (".idea/", ".junie/"),
    ("AGENTS.md", ".codex/", ".junie/", ".idea/", "codex"),
)
WIRES = {
    ".cursor/hooks.json": ("cursor", "cursor-hooks.json", CURSOR),
    ".cursor/rules/rudnik-review.mdc": ("cursor", "cursor-rule.mdc", CURSOR),
    ".cursor/mcp.json": ("cursor", "cursor-mcp.json", CURSOR),
    ".claude/settings.json": ("claude", "claude-settings.json", CLAUDE),
    ".codex/hooks.json": ("codex", "codex-hooks.json", CODEX),
    ".codex/config.toml": ("codex", "codex-config.toml", CODEX),
    ".junie/mcp/mcp.json": ("jetbrains", "cursor-mcp.json", JETBRAINS),
    ".idea/watcherTasks.xml": ("jetbrains", "jetbrains-watcher.xml", JETBRAINS),
    "AGENTS.md": ("agents", "agents.md", AGENTS),  # Codex and Junie (spec 1760)
    ".junie/AGENTS.md": ("agents", "agents.md", AGENTS),
    "hooks/pre-commit": (None, "pre-commit", ()),
    ".github/workflows/rudnik-review.yml": ("github", "github-workflow.yml", ()),
}
WIRED = sorted({tool for tool, *_ in WIRES.values() if tool})
# 1709: Codex runs a project's hook only once that definition is trusted, so writing it says how
TOLD = {".codex/hooks.json": ": Codex runs its Stop hook once you trust it in /hooks"}
# Junie reads .junie/AGENTS.md in place of the root's, so init lands it only where the repository holds one and never makes it (spec 1760)
WHERE_HELD = {".junie/AGENTS.md"}
FOLLOWUP = """rudnik-review found new blocking findings in your change. Fix each; one you find wrong, answer in your reply with
NOTE-WRONG: <fingerprint>: <why>
"""


def init(a: argparse.Namespace) -> int:
    """The named tool's files into the repository, or with none named each signed tool's, each landed by its kind and printed; one the
    developer made their own stays theirs, and is named. The tools with no sign are named in one line."""
    top, changed = Path(git("rev-parse", "--show-toplevel")), []
    signed = signs(top)
    wanted = ({a.what} if a.what else signed) | {None}
    for into, (tool, name, _) in WIRES.items():
        if tool not in wanted or (into in WHERE_HELD and not (top / into).exists()):
            continue
        at = into if tool else git("-C", str(top), "rev-parse", "--git-path", into)
        if kept := wire(top, at, (TEMPLATES / name).read_bytes()):
            changed.append(kept)
    if not a.what and (unsigned := sorted(set(WIRED) - signed)):
        print(
            f"no sign of {', '.join(unsigned)} here: `init <tool>` wires one all the same"
        )
    # 1710: AI Assistant keeps its MCP servers in the IDE's settings, which no repository file holds
    if "jetbrains" in wanted:
        servers = json.dumps(json.loads((TEMPLATES / "cursor-mcp.json").read_bytes()))
        print(
            f"AI Assistant: paste into Settings | Tools | AI Assistant | Model Context Protocol (MCP): {servers}"
        )
    set_up_lacking(a)
    if changed:
        raise Refused(f"changed here, so left as they are: {', '.join(changed)}")
    return 0


def signs(top: Path) -> set[str | None]:
    """The tools a sign shows here, a file of theirs in <top> or their command on PATH (2000: apart from init, held under lizard's 15)."""
    return {
        t
        for t, _, marks in WIRES.values()
        if any((top / s).exists() or shutil.which(s) for s in marks)
    }


def wire(top: Path, into: str, template: bytes) -> str | None:
    """<template> landed at <into> and printed, a script executable; for a file that stays the developer's, its name to say, a script
    of theirs with our last two lines, to add by their hand (spec 1712)."""
    path = top / into
    held = path.read_bytes() if path.exists() else None
    text = landed(path.suffix, held, template)
    script = template.startswith(b"#!")
    if text is None:
        ours = template.decode().splitlines()[-2:] if script else []
        return "\n".join([into, *ours])
    if text != held:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text)
        if script:
            path.chmod(0o755)
        print(f"wrote {into}{TOLD.get(into, '')}")
    return None


def landed(kind: str, held: bytes | None, template: bytes) -> bytes | None:
    """What a file holds once its template lands (spec 1708): a .json file gains the template's keys and keeps every other as it was, any
    other is the template whole; None for a file that stays the developer's. A JSON file is a team's, shared with its own servers and
    hooks: 1257 refused one that differed, so a repository's own MCP server kept ours out. A .md file is the developer's words to every
    agent, so ours is one marked block in it (spec 1760). A .xml file is a JetBrains team's File Watchers, so ours is one more task (1745),
    and a .toml file a team's Codex config, so ours is one more table (1775)."""
    if held is None or held == template:
        return template
    if kind == ".md":
        return with_block(held, template)
    if kind == ".xml":
        return with_task(held, template)
    if kind == ".toml":
        return with_table(held, template)
    if kind != ".json":
        return None
    try:  # no JSON (UTF-8, JSON: ValueError) or a table of ours held as another kind (TypeError): theirs, named
        text = held.decode()
        kept = json.loads(text)
        joined = with_keys(kept, json.loads(template))
        if joined == kept:
            return held
        if as_written(text) != as_written(json.dumps(kept)):
            return None  # Python's json cannot write it back as it was: a key twice, a number that loses its digits
        return (json.dumps(joined, indent=2, ensure_ascii=False) + "\n").encode()
    except (ValueError, TypeError):
        return None


class Dropped(ET.TreeBuilder):
    """Reads a watcherTasks.xml and notes what ET.tostring would not write back: a comment, a processing instruction or a DOCTYPE
    (and so an entity), wherever expat met it (spec 1745). The review, 13 Nov 2026: a text pattern for the part before <project
    missed a comment there, then refused a byte order mark; the parser, not a pattern, says what the file holds."""

    seen: bool = False

    def comment(self, text: str | None) -> ET.Element:
        self.seen = True
        return super().comment(text)

    def pi(self, target: str, text: str | None = None) -> ET.Element:
        self.seen = True
        return super().pi(target, text)

    def doctype(self, *_: str | None) -> None:  # expat's name, public and system ids
        self.seen = True


def with_task(held: bytes, template: bytes) -> bytes | None:
    """A watcherTasks.xml with the template's one task after the developer's, in its first ProjectTasksOptions component, where no
    option runs rudnik-review (spec 1745). None for one xml.etree cannot read, with no such component, or that xml.etree would not write
    back as it was (a comment, a DOCTYPE, an entity: the XML twin of as_written), so init never drops what the developer wrote. The text
    before <project, the IDE's <?xml ...?> line (and a byte order mark), is kept as the file had it: with nothing Dropped, nothing else
    can stand there."""
    try:  # not UTF-8 (ValueError), no XML (ParseError), an encoding Python lacks (LookupError), nested past Python's stack
        # xml.etree, not defusedxml: expat (2.4+) fetches no external entity and refuses an entity bomb, and the file is the repository's own
        text, read = held.decode(), Dropped()
        root = ET.fromstring(held, ET.XMLParser(target=read))
        if any(
            o.get("name") == "program" and o.get("value") == "rudnik-review"
            for o in root.iter("option")
        ):
            return held
        tasks = root.find("component[@name='ProjectTasksOptions']")
        start = text.find("<project")
        as_read = ET.tostring(root, encoding="unicode")
        if tasks is None or read.seen or start < 0 or as_read != text[start:].rstrip():
            return None
        tasks.extend(ET.fromstring(template).iter("TaskOptions"))
        ET.indent(root)  # the IDE's two spaces
        return (text[:start] + ET.tostring(root, encoding="unicode") + "\n").encode()
    except (ValueError, ET.ParseError, LookupError, RecursionError):
        return None


def with_block(held: bytes, template: bytes) -> bytes | None:
    """An .md file with the template, its first and last lines the markers, as its one block (spec 1760): the span from one opening
    marker to the one closing marker after it is replaced, a file with neither gains it after one empty line, any other is the
    developer's (None). Bytes are spliced, never rewritten, so CRLF or LF alike a second run changes nothing (the review, 12 Nov 2026:
    a block found by its line ending, then one written in a guessed ending, each failed a case)."""
    lines = template.splitlines()
    mark, unmark = lines[0], lines[-1]
    start, end = held.find(mark), held.find(unmark)
    if start == end == -1:
        return appended(held, template)
    if (held.count(mark), held.count(unmark)) != (1, 1) or end < start:
        return None
    return held[:start] + template.rstrip(b"\r\n") + held[end + len(unmark) :]


def with_table(held: bytes, template: bytes) -> bytes | None:
    """A config.toml with the template's one table at its end, where tomllib finds no server of ours (spec 1775): the standard library
    reads TOML and does not write it, so the developer's bytes stay as they were. None for one that is no TOML, or that would not read
    back with ours added (an inline `mcp_servers = {...}`, a key of that name of another kind, an array of tables that would take ours
    as its last item's), so init names it."""

    def served(text: bytes) -> bool:
        servers = tomllib.loads(text.decode()).get("mcp_servers")
        return isinstance(servers, dict) and "rudnik-review" in servers

    try:  # not UTF-8 or no TOML: both ValueError
        if served(held):
            return held
        joined = appended(held, template)
        return joined if served(joined) else None
    except ValueError:
        return None


def appended(held: bytes, template: bytes) -> bytes:
    """The template after what a file held: its last line ended (an empty file has none), then one empty line (the review, 13 Nov 2026)."""
    ended = held if not held or held.endswith(b"\n") else held + b"\n"
    return ended + b"\n" + template


def as_written(text: str) -> object:
    """A JSON text as it was written: each table its key pairs in order, each number its own digits (spec 1708's read-back check)."""
    return json.loads(text, object_pairs_hook=list, parse_int=str, parse_float=str)


def with_keys(held: object, template: object) -> object:
    """The template's keys into what a JSON file held: tables merged, a list gaining the items it lacks, every other value kept. A table or
    list the developer holds as another kind cannot take ours (12 Nov 2026: `"mcpServers": []` kept it out and init said nothing)."""
    if isinstance(held, dict) and isinstance(template, dict):
        return held | {
            k: with_keys(held[k], v) if k in held else v for k, v in template.items()
        }
    if isinstance(held, list) and isinstance(template, list):
        return held + [t for t in template if t not in held]
    if isinstance(template, dict | list):
        raise TypeError  # landed() names the file
    return held


def stop(_: argparse.Namespace) -> int:
    """Cursor's stop hook: a turn that completed with a new blocking finding gets it back as the agent's next message (Cursor sends a
    followup_message, up to the hook's loop_limit); a developer's stop (aborted, error) stands, and analysers that cannot run stop nothing."""
    # bytes: CRLF or LF alike
    event, stops, told, unchecked = json.loads(sys.stdin.buffer.read()), [], [], ""
    if event.get("status") == "completed":
        said = remembered(REPLIES).get(event.get("conversation_id"), "")
        stops, why, unchecked = red(event.get("model", ""), said, told.append)
        if why:
            failed(why)
    # where the diff went (spec 1743) and what was not checked (spec 1758), once a conversation
    for line, topic in ((told[0] if told else "", "sent"), (unchecked, "unchecked")):
        if line and (said := once(event, line, topic)):
            print(said["systemMessage"], file=sys.stderr)
    out = {"followup_message": FOLLOWUP + listed(stops)} if stops else {}
    # bytes, so LF on every OS: Windows' text mode would write CRLF
    sys.stdout.buffer.write(json.dumps(out).encode() + b"\n")
    return 0


REPLIES = "replies.json"


def cursor_reply(_: argparse.Namespace) -> int:
    """Cursor's afterAgentResponse hook: the message's text kept under its conversation, the last one alone, for that conversation's stop
    to judge its NOTE-WRONG answers (spec 1737: Cursor's stop input holds no reply, so no answer of a Cursor agent was ever judged)."""
    event = json.loads(sys.stdin.buffer.read())
    kept(REPLIES, event["conversation_id"], event.get("text", ""))
    return 0


def red(
    author: str, reply: str, say: Callable[[str], object] = failed
) -> tuple[list[D], Exception | None, str]:
    """A stop hook's red, Cursor's and Claude Code's (spec 1257, 1256): the analysers' new blocking findings, then the model's, why the
    check could not finish, if it could not, and found's line of what was not checked, which stops nothing (spec 1758). The analysers' red
    is kept before the model is asked: a refused or failed review never hides it. The NOTE-WRONG answers in the agent's <reply> are judged
    though the review fails (llm)."""
    stops, unchecked = [], ""
    try:
        # the author is one --author=<model> item, so `-x` or `--llm` is the author's name and never an option; check's arguments are an
        # argv list for this parser alone, never a shell's (the review, 11 Nov 2026)
        a = parser().parse_args(["check", f"--author={author}"])
        a.local = None  # spec 1967: the stop's model review is the agent's own (llm), so RUDNIK_REVIEW_LOCAL starts no lane nobody reads
        # spec 1703: formatted first, so the agent is never sent back for what a formatter mends and the findings name the lines as they will
        # be committed; a formatter that fails stops nothing (its failure is returned, never raised)
        formats(a)
        rows, diff, _, unchecked, stacks, _ = found(a)
        stops = [r for r in rows if r["blocking"]]
        try:
            said = llm(diff, stacks, a.author, rows, reply, say)
            model = [r for r in said if r["blocking"]]
        finally:  # an answer upheld drops its finding though the review failed (spec 1735)
            gone = upheld()
            stops = [r for r in stops if r["fingerprint"] not in gone]
        return stops + model, None, unchecked
    except Exception as e:
        return stops, e, unchecked


def answered(reply: str, rows: list[D]) -> list[D]:
    """The agent's NOTE-WRONG answers to <rows>' findings, each a claim for the verifier holding the finding and the answer alone (1253's)."""
    out = {
        r["fingerprint"]: {
            "severity": "NOTE-WRONG",
            "file": r["file"],
            "line": r.get("line"),
            "claim": f"{said(r)} is wrong",
            "scenario": why,
            "fingerprint": r["fingerprint"],
        }
        for fp, why in re.findall(findings.NOTE_WRONG, reply)
        for r in rows
        if r.get("fingerprint", "").startswith(fp)
    }
    return list(out.values())


# An upheld answer drops its finding on its branch: "<branch> <fingerprint>" in .rudnik/wrong.json, one key each, so two sessions' hooks
# never write over each other's (spec 1669)
WRONG = "wrong.json"


def branch() -> str:
    return (
        git("branch", "--show-current") or "HEAD"
    )  # a branch with no commit yet too (spec 1731)


def dropped(answers: list[D]) -> None:
    """Each upheld answer kept, under this branch."""
    for x in answers:
        if x.get("verdict") == "confirm":
            kept(WRONG, f"{branch()} {x['fingerprint']}", x["scenario"])


def upheld() -> set[str]:
    """The fingerprints this branch's upheld answers dropped."""
    mine = branch() + " "
    return {k.removeprefix(mine) for k in remembered(WRONG) if k.startswith(mine)}


def listed(rows: list[D]) -> str:
    return "\n".join(f"- {said(r)}" for r in rows)


# Claude Code's half (spec 1256): each hook prints Claude Code's JSON, or nothing, and exits 0; a check that cannot run never blocks and is
# said once a session. A stop is refused at most TWICE in a row, then the developer decides (owner, 8 Nov 2026).
TWICE = 2


def claude(a: argparse.Namespace) -> int:
    event, out = {}, {}
    try:  # all of it: outside a repository too, a check that cannot run is said once (the review, 11 Nov 2026)
        event = json.loads(sys.stdin.buffer.read())
        os.chdir(git("rev-parse", "--show-toplevel"))
        out = (
            edited(event)
            if a.what == "claude-post"
            else stopped(event, a.what.removesuffix("-stop"))
        )
    except Exception as e:
        out = once(event, e)
    if out:
        sys.stdout.buffer.write(json.dumps(out).encode() + b"\n")
    return 0


def edited(event: D) -> D:
    """The analysers alone on the edited file: no model asked."""
    rows, *_ = found(
        argparse.Namespace(base=None, files=[event["tool_input"]["file_path"]])
    )
    stops = [r for r in rows if r["blocking"]]
    return {"decision": "block", "reason": FOLLOWUP + listed(stops)} if stops else {}


def stopped(event: D, author: str) -> D:
    """Cursor's red, the hook's tool (claude, codex: spec 1709) its author where the input names no model; blocked TWICE in a row at most,
    counted by session in .rudnik/stop-blocks.json, as Claude Code and Codex tell a stop only `stop_hook_active` (Codex no session: the
    repository's count)."""
    told: list[str] = []  # where the diff went, said once a session (spec 1743)
    stops, why, unchecked = red(event.get("model") or author, reply(event), told.append)
    rows = remembered("stop-blocks.json")
    n = (
        rows.get(event.get("session_id", ""), 0) if event.get("stop_hook_active") else 0
    )  # a new turn, a new row
    n = n + 1 if stops and n < TWICE else 0
    kept("stop-blocks.json", event.get("session_id", ""), n)
    if n:
        out = {"decision": "block", "reason": FOLLOWUP + listed(stops)}
    else:
        out = (
            {"systemMessage": f"rudnik-review: still open, your call:\n{listed(stops)}"}
            if stops
            else {}
        )
    # each once-a-session line under the others, none written over: its mark is spent (spec 1758)
    said = [out.pop("systemMessage", "")] + [
        once(event, line, topic).get("systemMessage", "")
        for line, topic in (
            (why, ""),
            (told[0] if told else "", "sent"),
            (unchecked, "unchecked"),
        )
        if line
    ]
    return out | ({"systemMessage": "\n".join(filter(None, said))} if any(said) else {})


def reply(event: D) -> str:
    """The text of the last reply: Codex's `last_assistant_message` (spec 1709), else the last assistant line of Claude Code's JSONL
    transcript; none when that line holds no text, so an older reply's answers are never asked again (the review, 11 Nov 2026)."""
    if "last_assistant_message" in event:
        return event["last_assistant_message"] or ""
    path = Path(event.get("transcript_path") or "")
    lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    turns = [json.loads(line) for line in lines if line.strip()]
    last = next((t for t in reversed(turns) if t.get("type") == "assistant"), None)
    content = last["message"]["content"] if last else []
    return "\n".join(c["text"] for c in content if c.get("type") == "text")


def once(event: D, why: object, topic: str = "") -> D:
    """<why> as Claude Code's message the first time in a session (Cursor's conversation) and its directory for its <topic>, then nothing."""
    session = event.get("session_id") or event.get("conversation_id")
    key = hashlib.sha256(f"{session} {event.get('cwd')} {topic}".encode())
    mark = Path(tempfile.gettempdir(), f"rudnik-review-{key.hexdigest()[:16]}")
    if mark.exists():
        return {}
    mark.touch()
    return {"systemMessage": f"rudnik-review: {getattr(why, 'stderr', None) or why}"}


def rudnik(name: str) -> Path:
    """A file in .rudnik/, a folder that ignores itself, so no check reads it as a change."""
    Path(".rudnik").mkdir(exist_ok=True)
    Path(".rudnik/.gitignore").write_text("*\n")
    return Path(".rudnik", name)


def remembered(name: str) -> D:
    path = Path(".rudnik", name)
    return json.loads(path.read_text()) if path.is_file() else {}


STALE = 30  # a lock is held for one read and write; older, its hook crashed


def kept(name: str, key: str, value: object) -> None:
    """<key> of .rudnik/<name> set to <value> under a lock file, the file replaced whole: hooks of two sessions in one repository never drop
    each other's (the review, 11 Nov 2026). A lock a crashed hook left goes after STALE seconds."""
    lock = rudnik(name + ".lock")
    while True:
        try:
            os.close(os.open(lock, os.O_CREAT | os.O_EXCL))
            break
        except FileExistsError:
            with suppress(FileNotFoundError):
                if time.time() - lock.stat().st_mtime > STALE:
                    lock.unlink()
            time.sleep(0.05)
    try:
        every = remembered(name)
        every[key] = value
        rudnik(name + ".tmp").write_text(json.dumps(every))
        os.replace(rudnik(name + ".tmp"), rudnik(name))
    finally:
        lock.unlink()


# The MCP server (spec 1640): a tool's arguments are untrusted text, so explain takes plain names only and check's files reach found() as
# a list, never a shell nor check's parser (11 Nov 2026: the review stopped 1257's build on SECURITY).
# 1241's bad/good pairs are in the kit's tree; a wheel holds none.
CORPUS = ROOT / "tests/gate-corpus"
SCHEMA = {
    "check": {"files": {"type": "array", "items": {"type": "string"}}},
    "explain": {"tool": {"type": "string"}, "rule": {"type": "string"}},
}
DESCRIBED = {  # each tool's line beside its schema, as MCP asks (spec 2000)
    "check": "the findings this branch adds, or those of <files>, as check --format json",
    "explain": "what a tool's rule asks, with its bad and good code where the kit has them",
}


def mcp(_):
    """MCP's stdio transport: one JSON-RPC message a line, stdout for them alone; a notification gets no answer."""
    for msg in map(json.loads, sys.stdin):
        if "id" in msg:
            try:
                out = {"result": served(msg["method"], msg.get("params") or {})}
            except LookupError as e:
                out = {"error": {"code": -32601, "message": f"no method: {e}"}}
            print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], **out}), flush=True)
    return 0


def served(method, params):
    if method == "initialize":
        return {
            "protocolVersion": params.get("protocolVersion"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "rudnik-review", "version": released()},
        }
    if method == "tools/list":
        shape = lambda props: {"type": "object", "properties": props}
        return {
            "tools": [
                {"name": n, "description": DESCRIBED[n], "inputSchema": shape(p)}
                for n, p in SCHEMA.items()
            ]
        }
    if method != "tools/call":
        raise LookupError(method)
    error = False
    try:  # an unknown tool or argument is a KeyError or a TypeError: the tool's error, as one that cannot run
        out = CALLS[params["name"]](**params.get("arguments") or {})
    except Exception as e:
        out, error = f"rudnik-review: {e!r}", True
    return {"content": [{"type": "text", "text": json.dumps(out)}], "isError": error}


def explain(tool: str, rule: str) -> D:
    """A rule as the shipped registry and its developers' tables have it, and its bad/good pair where the kit's corpus holds one."""
    for name in (tool, rule):
        if not re.fullmatch(r"\w[\w.-]*", name) or ".." in name:
            raise Refused(f"{name!r} is not a tool or rule name")
    t, pair = tools()[tool], CORPUS / tool / rule
    stops = findings.blocking(
        {"tool": tool, "rule": rule, "severity": "error"}, {tool: t.get("blocks", [])}
    )
    said = "blocks: an error of it stops the change" if stops else "a note"
    text = f"{tool} {t['version']} {rule} {said}"
    files = [*pair.glob("bad.*"), *pair.glob("good.*")]
    fixtures = {p.name: p.read_text() for p in files} if len(files) == 2 else None
    return {"text": text, "fixtures": fixtures}


def checked(files: list[str] | None = None) -> list[D]:
    """check's rows as --format json prints them; none, with something not checked, is the tool's error, never a clean answer (spec 1758)."""
    rows, _, _, unchecked, *_ = found(argparse.Namespace(base=None, files=files))
    if unchecked and not rows:
        raise Refused(unchecked)
    return rows


CALLS = {
    "check": checked,
    "explain": explain,
}


def upstream(hook: bool = False) -> str:
    """The base with no --base: a team's own target, one `git config rudnik-review.base` line (spec 1731, 12 Nov 2026: a branch merging
    into release/2.x had no way to say so to the hooks); else origin/HEAD, the branch a pull request targets, so the finish, the commit
    and the PR agree on what is new (spec 1711: a pushed branch's own upstream hid its pushed defects); else the upstream; else main or
    master; else HEAD itself, what is not committed being the change (1731: a repository on master with no remote ended in `Not a valid
    object name main`, and its stop hooks let every finish go). The builder's check --hook keeps the upstream, else main (spec 1624)."""
    tracked = run(["git", "rev-parse", "--abbrev-ref", "@{upstream}"])
    tracking = tracked.stdout.strip() if tracked.returncode == 0 else ""
    if hook:
        return tracking or "main"
    own = run(["git", "config", "rudnik-review.base"]).stdout.strip()
    # each only where it exists, so a configured base gone is passed over; main and master as branches, never a tag of that name,
    # which git would take first (the review, 12 Nov 2026)
    bases = (own, "origin/HEAD", tracking, "refs/heads/main", "refs/heads/master")
    return next((r for r in bases if r and has(r)), "HEAD")


def has(ref: str) -> bool:
    return run(["git", "rev-parse", "--verify", "-q", ref]).returncode == 0


def merged(base: str) -> str:
    """The merge base of base and HEAD; with no commit yet, git's empty tree, every file new (spec 1731)."""
    if not has("HEAD"):
        return run(
            ["git", "hash-object", "-t", "tree", "--stdin"], input="", check=True
        ).stdout.strip()
    p = run(["git", "merge-base", base, "HEAD"])
    if p.returncode:  # 1 and silent: a shallow clone, or two histories that never met
        raise Refused(
            p.stderr.strip()
            or f"cannot compare with {base}: this clone does not hold its history (git fetch --unshallow)"
        )
    return p.stdout.strip()


def family(name):
    """A provider or model name's family: every provider in API by its own name, as FAMILY's other names too."""
    name = name.lower()
    return next((f for f in API if name.startswith((f, *FAMILY.get(f, ())))), name)


def llm(
    diff: str,
    stacks: list[str],
    author: str | None,
    rows: list[D],
    reply: str,
    say: Callable[[str], object] = failed,
) -> list[D]:
    """1239 with the developer's own keys or signed-in CLIs: an ERROR blocks when the verifier, of another family, confirms it.
    One it gave no answer for is a warning, one it refutes an info (spec 1736: a developer cannot wait or ask again as the gate can), and
    with no verifier no model finding blocks: the analysers alone set the exit. The NOTE-WRONG answers in the
    agent's <reply> ride the verifier's request; an upheld one drops its finding (spec 1669). The review cites the rules of the
    change's <stacks>, and a finding citing a rule of theirs is capped at its tier (findings.cite, findings.capped)."""
    if off():
        return []
    own = family(author or "")
    reviewer, verifier = roles(own)
    if not reviewer:
        failed(
            "no second reviewer: sign in to Codex or Claude Code, whichever did not write this change"
        )
        return []
    # 1239: the verifier is a third family, neither the reviewer's nor the author's (the lock's proof, 32c86f228,
    # refuses a DeepSeek verifier of a DeepSeek author's change)
    named = [
        n for n in (author, *(r["provider"] for r in (reviewer, verifier) if r)) if n
    ]
    families = [family(n) for n in named]
    if len(set(families)) < len(families):
        raise Refused(
            "the reviewer and the verifier must be other vendors' models than the author's: "
            + ", ".join(named)
        )
    say(
        f"this change's diff was sent to {reviewer['model']} for a second review; turn it off with: git config rudnik-review.model off"
    )
    found: list[D] = []
    books = findings.books(stacks)
    prompt = findings.REVIEW + findings.cite(books) + "The diff:\n" + diff
    try:
        said = answer(reviewer, prompt, "findings", Refused)
        found = findings.capped(reviewed(said, reviewer["model"]), books)
    finally:  # spec 1735: the answers are judged whether the review answered or not
        judged(reviewer, verifier, rows, found, reply, diff)
    # an answer this branch upheld drops its finding with a verifier or without (the review, 11 Nov 2026)
    gone = upheld()
    return [
        {
            **x,
            "blocking": bool(verifier) and x.get("verdict") == "confirm" and blocks(x),
        }
        for x in found
        if x.get("fingerprint") not in gone
    ]


def off() -> bool:
    """1743 (12 Nov 2026): the diff went to another vendor unsaid, under a client's confidentiality terms too; one line turns every model off."""
    return run(["git", "config", "rudnik-review.model"]).stdout.strip() == "off"


def unshown(f: D, books: findings.Books) -> str:
    """<f>'s rule id when <f> is a semgrep finding of a mined rule (1828) its stack's book in <books> holds unmeasured, else '' (1934,
    scorecard v5, 18 Nov 2026: every false note of --local came from a rule the corpus never measured; a guessed tier is not shown)."""
    if f["tool"] != "semgrep" or not (m := findings.MINED.search(f["rule"])):
        return ""
    held = {r["id"]: r for r in books.get(m["stack"], [])}
    return m["id"] if m["id"] in held and not findings.measured(held[m["id"]]) else ""


def laptop(books: findings.Books, keep: Callable[[D], bool]) -> findings.Books:
    """The rules of <books> <keep> keeps that --local may ask: a semgrep-form one runs among the analysers (1842); the corpus's model asks all (1843)."""
    return {
        s: [r for r in b if r.get("form") != "semgrep" and keep(r)]
        for s, b in books.items()
    }


def not_shown(new: list[D], books: findings.Books, diff: str) -> None:
    """Says once the rules of <books> not shown (1934): those of the semgrep findings of <new> unshown, and the unmeasured ones a hunk of
    --local's <diff> triggers, which it does not ask."""
    hidden = {unshown(f, books) for f in new} - {""}
    guessed = laptop(books, lambda r: not findings.measured(r))
    hidden |= {r["id"] for r, _ in triggered(hunks(diff), guessed)}
    if hidden and not off():
        failed(f"{len(hidden)} unmeasured rules not shown")


def hosted(
    where: str, diff: str, books: findings.Books, rev: str = "", judge: str = ""
) -> list[D]:
    """1841: each rule of <books> a hunk triggers (1843: the corpus asks every form of its PR's stack), asked of the developer's own OpenAI-compatible server at <where>, URL[#MODEL],
    or else of the first model its /models lists (which a named one needs too). A yes never blocks: the corpus measured the rule with its own
    model, not this one. A failed request is sent once more (1958), and a second failure is said once with <where> and stops the lane. 1883: a hunk's rules are asked
    in a row by one worker, the hunk before each question, so the server's prompt cache keeps the text they share. 1921: given <rev>, the
    tree analysed, each changed code file is also reviewed freely, its claims traced by <judge>'s model or else <where>'s, in the same
    pool and stop; the corpus, which measures rules, gives none."""
    asks, free = triggered(hunks(diff), books), regions(diff, rev)
    if off() or not (asks or free):
        return []
    try:
        reviewer = endpoint(where, "--local")
        verifier = endpoint(judge, "--local-verifier") if judge else reviewer
        width = int(os.environ.get("RUDNIK_REVIEW_LOCAL_WIDTH") or 4)
        conf = tomllib.loads(CONF.read_text()) if CONF.is_file() else {}
        stop = Run(conf.get("verifier"))
        ask = partial(applies, *reviewer, stop)
        jobs = [partial(map, ask, list(g)) for _, g in groupby(asks, itemgetter(1))]
        with ThreadPoolExecutor(width) as pool:
            # 1957: every rule question and free review is answered before any trace, so each model is loaded once a check
            asked = pool.map(lambda job: [*job()], jobs)
            claims = pool.map(partial(freely, reviewer, verifier, stop), free)
            found = [*chain.from_iterable(asked)]
            found += pool.map(lambda trace: trace(), [*chain.from_iterable(claims)])
        if stop.cut:  # 1947: no room is no refutation, and said once for the run, not as a malformed answer per claim
            failed(
                f"{len(stop.cut)} claims the verifier had no room to answer: its max_tokens, {TRACE_CAP['max_tokens']}, reached"
            )
        if late := len(stop.late):  # 2017, 2028: answers the server missed
            failed(f"{late} requests the local server did not answer, skipped")
        if missed := sum(not isinstance(w, bool) for w in stop.answers):
            failed(f"{missed} claims unanswered by review.toml's verifier, kept")
        return findings.capped([x for x in found if x], books)
    except (OSError, ValueError, LookupError, TypeError) as e:
        named = " or ".join(w.partition("#")[0] for w in filter(None, (where, judge)))
        raise Refused(f"{named} gave no answer: {e!r}") from e


def endpoint(where: str, flag: str) -> tuple[str, str]:
    """<flag>'s URL[#MODEL]: its URL and the model it names, or else the first its /models lists (which a named one needs too)."""
    url, _, model = where.partition("#")
    if not url.startswith(("http://", "https://")):
        raise Refused(f"{flag} takes an http URL, not {url}")
    models = urllib.request.Request(url + "/models", headers=HEAD)
    with urllib.request.urlopen(models, timeout=60) as r:
        return url, model or json.load(r)["data"][0]["id"]


def triggered(parts: list[D], books: findings.Books) -> list[tuple[D, D]]:
    """Each rule of <books> with each hunk of <parts> on a file of its stack (one its tools' globs take) whose added lines its trigger matches; a trigger of "" asks every hunk."""
    tools = findings.tools().values()
    globs = {s: [t["globs"] for t in tools if s in t["stacks"]] for s in books}
    return [
        (r, h)
        for h in parts
        for s, book in books.items()
        if any(analyze.matches(h["file"], g) for g in globs[s])
        for r in book
        if any(re.search(r.get("trigger", ""), a) for a in [*h["added"].values(), ""])
    ]


def applies(url: str, model: str, stop: Run, pair: tuple[D, D]) -> D | None:
    """The finding where <model> answers the rule's question yes at an added line of the hunk; another answer is said and none. A request
    that fails sets <stop>; once it is, none is sent and one on the wire is dropped (1883: a worker asks a hunk's rules in a row, which no cancel stops)."""
    rule, hunk = pair
    if stop.is_set():
        return None
    # 1839: a rule of main's word, before it, asks its look_for, with no examples
    shown = "\n---\n".join(rule.get("examples", []))
    asked = f"{rule.get('question') or rule['look_for']}\n" + (
        EXAMPLES + shown if shown else ""
    )
    prompt = f"{LOCAL}{hunk['file']}:\n{hunk['text']}\n\n{asked}"
    try:
        if not (said := chat(url, model, stop, prompt, RULE_ASK)):
            return None
        x, choice = said
        # a no is no finding and has no line to name, so only a yes is held to one (owner, 17 Nov 2026: qwen's every no, at line 0, was refused)
        if x["applies"] is False:
            return None
        line, why = x["line"], x["why"]
        ok = whole(line) and line in hunk["added"] and isinstance(why, str)
        if not (x["applies"] is True and ok):
            raise ValueError(x)
    except (ValueError, LookupError, TypeError) as e:
        failed(f"{model} on {rule['id']}, {hunk['file']}: {e!r}")
        return None
    # 1884 (owner, 17 Nov 2026: >=90% precision): a yes weighed by its own probability, none under the rule's measured threshold
    if (p := p_yes(choice)) is not None and p < rule.get("local_threshold", 0.5):
        return None
    at: D = {"file": hunk["file"], "line": int(line), "rule": rule["id"]}
    at |= {"severity": rule["tier"].upper(), "claim": f"{rule['id']}: {why}"}
    at |= {"source": model, "fingerprint": print_of(at), "blocking": False}
    return at | {"p_yes": p}


def chat(
    url: str, model: str, stop: Run, prompt: str, ask: D, wait: float = 5, late: int = 3
) -> tuple[D, D] | None:
    """<model>'s JSON answer to <prompt> at <url>, and its choice; none once <stop> is set, or cut off by ollama's `length` (1947: its prompt counted once on <stop>, a Run; 2017: a trace's asked once more at SHORT, a shorter think usually fitting, 2035: when its cut answer carried a thought). The server failing is a transport error alone:
    sent once more after <wait> s unless <stop> is set meanwhile, its second failure sets <stop> and is raised. Whatever its response holds is the answer, the caller's to judge. 1924: every request waits SECONDS, 600 s, as
    ollama queues one behind the thinking traces. 2017 (scorecard v9: 11 of 79 runs refused by one late answer): a late answer is the server busy, not down: sent again at once, the queue its wait, <late> sends in all (a failure's resend one of them), then none and its prompt counted on <stop>'s `late`; only a second failure other than a timeout or a 5xx (2028) is the server down."""
    if stop.is_set():
        return None
    said = {"model": model, "messages": [{"role": "user", "content": prompt}]} | ask
    try:
        said = post(url + "/chat/completions", said, HEAD, SECONDS)
    except OSError as e:  # 1958: about 2% of the GPU box's requests dropped (19 Nov 2026); the second failure is a server down
        # 2017: busy, never down, <wait> kept; 2028 (ollama ending a looping answer): a 5xx is that request's, as a late answer is
        busy = isinstance(e, TimeoutError) or getattr(e, "code", 0) >= 500
        if not busy and (wait == 0 or (late > 1 and stop.wait(wait))):
            stop.set()
            raise
        if late == 1:  # no send left, the server not down: that one answer missing
            stop.late.append(prompt)
            return None
        return chat(url, model, stop, prompt, ask, wait if busy else 0, late - 1)
    if stop.is_set():
        return None
    if (choice := said["choices"][0]).get("finish_reason") == "length":
        stop.cut.add(
            prompt
        )  # 2035 (scorecard v10): a model that does not think, qwen3-coder-next, runs to the cap at any effort
        thought = choice["message"].get("reasoning") or choice["message"].get(
            "reasoning_content"
        )
        return (
            chat(url, model, stop, prompt, SHORT)
            if ask is TRACE_ASK and thought
            else None
        )
    stop.cut.discard(prompt)  # answered, so no longer a prompt with no room
    return json.loads(choice["message"]["content"]), choice


def regions(diff: str, rev: str) -> list[D]:
    """1921: the regions of each changed code file (a tool's globs but `*` take it, 1956: a changelog's; no test path) at <rev>, the tree analysed."""
    changed: dict[str, D] = {}
    for h in hunks(diff) if rev else []:
        if not is_test_path(h["file"]) and h["file"] != "/dev/null":
            file = changed.setdefault(h["file"], {"added": {}, "removed": {}})
            file["added"] |= h["added"]
            file["removed"] |= h["removed"]
    globs = [g for t in findings.tools().values() for g in t["globs"] if g != "*"]
    code = [f for f in changed if findings.matches(f, globs)]
    return [r for f in code for r in regions_of(f, rev, changed[f])]


def regions_of(file: str, rev: str, changed: D) -> list[D]:
    """<file> at <rev> from 40 lines before each run of its <changed> lines to 20 after, a run joining the one before where they meet while
    that region stays within REGION lines (1924: an 800-line file overflowed a 4096-token server), each line led by its number, an added
    one marked + and a removed one - (1956, Fable's third pass, 19 Nov 2026: most missed bugs changed a line), 20 a block at most, before
    the line after it: a deletion's changed line, the last where it ends the file (an emptied file's, 0, has none). Claims may be on its
    run's changed lines (1924: the review reports on them alone), a line within 2 moved by `at` to the nearest, the earlier on a tie."""
    shown = run(["git", "show", f"{rev}:{file}"], text=False, check=True).stdout
    rows = shown.decode(errors="replace").removesuffix("\n").split("\n")
    added = changed["added"].keys()
    more = lambda b: [f"... {len(b) - 20} more rows removed"] * (len(b) > 20)
    gone = {n: b[:20] + more(b) for n, b in changed["removed"].items()}
    span = lambda a, b: b - a + 61 + sum(len(gone.get(k, ())) for k in range(a, b + 1))
    runs: list[list[int]] = []
    for n in sorted((added | gone.keys()) - {0}):
        if runs and n - 40 <= runs[-1][-1] + 21 and span(runs[-1][0], n) <= REGION:
            runs[-1].append(n)
        else:
            runs.append([n])
    minus = lambda r, n: "".join(f"     - {x}\n" for x in gone.get(n, []) if n in r)
    numbered = lambda n: f"{n:>5}{'+' if n in added else ' '} {rows[n - 1]}\n"
    text = lambda r, s: "".join(minus(r, n) + numbered(n) for n in s) + minus(r, s.stop)
    show = lambda r: range(max(r[0] - 40, 1), min(r[-1] + 20, len(rows)) + 1)
    focus = lambda n: min(n, len(rows))  # a deletion at the end is on the last line
    at = lambda r: {f + k: f for k in (-2, 2, -1, 1, 0) for f in map(focus, r)}
    return [
        {"file": file, "at": at(r), "text": f"{file}:\n" + text(r, show(r))}
        for r in runs
    ]


def freely(
    reviewer: Server, verifier: Server, stop: Run, region: D
) -> list[Callable[[], D | None]]:
    """1921: the defects, at most three, <reviewer>'s model says the change brings into <region>, each at a line of it, as its trace by
    <verifier>'s (1957: run after every region's review), one elsewhere dropped. 1956: one within 2 of a changed line moves to it by the region's `at`, and of a line's claims,
    read last to first so the first stays, one alone is traced. A malformed answer is said and none."""
    url, model = reviewer
    try:
        said = chat(url, model, stop, FREE + region["text"], FREE_ASK)
        defects = said[0]["defects"][:3][::-1] if said else []
        at = {region["at"].get(d["line"], 0): d for d in defects if whole(d["line"])}
        claims = [d | {"line": n, "source": model} for n, d in sorted(at.items()) if n]
    except (ValueError, LookupError, TypeError) as e:
        failed(f"{model} on {region['file']}: {e!r}")
        return []
    return [partial(traced, verifier, stop, region, d) for d in claims]


def trace_of(verifier: Server, stop: Run, prompt: str) -> tuple[D, D] | None:
    """2036: <verifier>'s trace of <prompt>, or none; one not whole (not JSON, or not a trace: the review, 20 Nov 2026) asked once more, then late on <stop>."""
    for _ in range(2):
        with suppress(json.JSONDecodeError):
            said = chat(*verifier, stop, prompt, TRACE_ASK)
            if said is None or is_trace(said[0]):
                return said
    stop.late.append(prompt)
    return None


def is_trace(answer: object) -> bool:
    """2036: a JSON object, its `trace` a string and its `real` a boolean."""
    a = answer if isinstance(answer, dict) else {}
    return type(a.get("trace")) is str and type(a.get("real")) is bool


def traced(verifier: Server, stop: Run, region: D, defect: D) -> D | None:
    """1921: the reviewer's <defect>, an info finding of rule `free` that never blocks, when <verifier>'s model traces it through <region>
    and weighs `real` at FREE_BAR or over (with no logprobs, answers it true); a malformed answer is said and none. 1960 (scorecard v7: the local
    verifier kept most wrong claims): review.toml's verifier, <stop>'s `last`, has the last word: `real` false drops it, any other answer keeps it.
    2014 (scorecard v8: two real Go bugs cut by qwen3.5:9b's window): a claim cut off goes to the last word alone, kept on its `true` alone."""
    model = verifier[1]
    try:
        claim = f"{defect['claim']} (scenario: {defect['scenario']})"
        prompt = f"{TRACE}{region['text']}\nThe claim, at {defect['line']}: {claim}"
        said = trace_of(verifier, stop, prompt)
        if said is None and not stop.for_last(prompt):
            return None  # 2017: a trace never answered in time is not cut
        p = None if (cut := said is None) else p_yes(said[1], "real")
        if not cut and not (said[0]["real"] is True if p is None else p >= FREE_BAR):
            return None
        word = answer(stop.last, prompt, "real") if stop.last else True
        if not cut:
            stop.answers.append(word)
        elif isinstance(word, bool):
            stop.cut.remove(prompt)  # answered, so no longer a claim with no room
        if word is False or (cut and word is not True):
            return None
    except (ValueError, LookupError, TypeError, AttributeError) as e:
        failed(f"{model} on {region['file']}:{defect['line']}: {e!r}")
        return None
    at: D = {"file": region["file"], "line": int(defect["line"]), "rule": "free"}
    at |= {"severity": "INFO", "claim": f"free: {claim}"}
    at |= {"source": defect["source"], "fingerprint": print_of(at), "p_yes": p}
    return at | {"blocking": False}


def p_yes(choice: D, key: str = "applies") -> float | None:
    """1884: the answer's chance of `true` against `false`, from the top alternatives of the token covering the first character of the
    <key>'s value (`applies`, or 1921's `real`), each stripped of whitespace and `" { } : ,` and counted when a prefix of either word (`tr` of `tr`+`ue` too); None unread.
    1924: a thinking model's tokens come first (ollama 0.40.16) and the content's last, so the characters before the content are skipped."""
    value = re.search(rf'"{key}"\s*:\s*', content := choice["message"]["content"])
    tokens = (choice.get("logprobs") or {}).get("content") or []
    ends = accumulate(len(t["token"]) for t in tokens)
    skip = sum(len(t["token"]) for t in tokens) - len(content)
    start = skip + value.end() if value else math.inf
    at = [t for t, end in zip(tokens, ends, strict=True) if end > start]
    top = next(iter(at), {}).get("top_logprobs") or []
    odds = [(a["token"].strip(' \t\r\n"{}:,'), math.exp(a["logprob"])) for a in top]
    mass = [sum(p for s, p in odds if s and w.startswith(s)) for w in ("true", "false")]
    return mass[0] / sum(mass) if sum(mass) else None


def hunks(diff: str) -> list[D]:
    """<diff>'s hunks as git writes them: the file, its lines each led by its new-file number (a removed one by none), its added lines by
    number and its removed ones by the new-file line after them (1956). A row ends at \n alone: str.splitlines also cut at \f, \v and \x1c-\x1e, which git keeps in a line (the review, 16 Nov 2026)."""
    found: list[D] = []
    for path, body in FILES.findall(diff):
        file = unquoted(path).removeprefix("b/")
        cut = HUNK.split(body)
        for start, part in zip(cut[1::2], cut[2::2], strict=True):
            n, text, added, gone = int(start), "", {}, {}
            for row in part.removesuffix("\n").split("\n"):
                # a removed line, or git's "\ No newline", has no new-file number
                new = row[:1] in (" ", "+")
                text += f"{n if new else '':>5} {row}\n"
                added |= {n: row[1:]} if row[:1] == "+" else {}
                if row[:1] == "-":
                    gone.setdefault(n, []).append(row[1:])
                n += new
            found.append({"file": file, "text": text, "added": added, "removed": gone})
    return found


def unquoted(path: str) -> str:
    """A path as a patch header writes it: git quotes one holding a tab, a quote or a backslash, core.quotePath=false or not, and C-escapes
    it; a non-ASCII byte is escaped or raw by core.quotePath (`"b/a\\tb.py"` is b/a<tab>b.py, `"b/caf\\303\\251.py"` b/café.py)."""
    if not path.startswith('"'):
        return path
    raw = path[1:-1].encode().decode("unicode_escape").encode("latin-1")
    return raw.decode(errors="replace")


def judged(
    reviewer: D,
    verifier: D | None,
    rows: list[D],
    found: list[D],
    reply: str,
    diff: str,
) -> None:
    """The error and warning claims of <found> and the agent's answers in <reply> judged, an upheld answer kept. An answer to an analyser's
    finding is the author's claim about a tool's line, so the reviewer, of another family and writing neither, judges it where no verifier
    is; one to a model's finding needs the verifier, a third family (spec 1735)."""
    judging = found if verifier else []
    wrong = answered(reply, rows + judging)
    verify(verifier or reviewer, judging, wrong, diff)
    dropped(wrong)


def reviewed(entries: list[object], model: str) -> list[D]:
    """The reviewer's findings, each with print_of's fingerprint over any it wrote; the entries that are no finding counted in one line."""
    found = [
        {**x, "source": model, "fingerprint": print_of(x)}
        for x in entries
        if finding(x)
    ]
    if odd := len(entries) - len(found):
        failed(f"the reviewer's answer held {odd} entries that are no finding")
    return found


def finding(x: object) -> TypeGuard[D]:
    """A model's entry is a finding when its severity, file and claim are strings and its line a whole number or absent (spec 1734)."""
    if not isinstance(x, dict):
        return False
    strings = all(isinstance(x.get(k), str) for k in ("severity", "file", "claim"))
    return strings and whole(x.get("line", 0))


def roles(own: str) -> list[D | None]:
    """The reviewer and the verifier: review.toml's, the developer's own; with no [reviewer] there (spec 1715), the signed-in CLIs on the
    PATH of families other than the author's <own>, the first to review and the next to verify (a third family, so 1239 holds)."""
    conf = tomllib.loads(CONF.read_text()) if CONF.is_file() else {}
    if "reviewer" in conf:
        return [conf.get("reviewer"), conf.get("verifier")]
    found = {f: shutil.which(cmd[0]) for f, cmd in CLI.items() if f != own}
    # absolute: a PATH entry like `bin` finds the program here, and no longer in the empty folder the call runs in (the review, 12 Nov 2026)
    clis = [
        {
            "provider": f,
            "model": CLI[f][0],
            "cli": [str(Path(exe).absolute()), *CLI[f][1:]],
        }
        for f, exe in found.items()
        if exe
    ]
    return [*clis, None, None][:2]


def verify(verifier: D, found: list[D], answers: list[D], diff: str) -> None:
    """The verifier's verdicts set on the error and warning claims of <found>, then on the <answers>, numbered after them in one request."""
    # each is unconfirmed until the verifier answers for it, printed a warning with no answer (spec 1736); an info is never sent (1784)
    claims = [x for x in found if findings.level(x.get("severity", "")) != "info"]
    for x in claims:
        x["verdict"] = "unconfirmed"
    if items := claims + answers:
        listed = "".join(f"{n}. {claim_of(x)}\n" for n, x in enumerate(items, 1))
        asked = VERIFY + listed + "The diff:\n" + diff
        verdicts(items, answer(verifier, asked, "verdicts"), verifier["model"])


def answer(role, prompt, field, failed=None):
    """The <field> of the JSON object the model answered, fenced or not. A failed call or another answer raises <failed>, else is none."""
    try:
        text = asked(role["cli"], prompt) if "cli" in role else called(role, prompt)
        return json.loads(text[text.index("{") : text.rindex("}") + 1])[field]
    except (
        OSError,
        ValueError,
        LookupError,
        TypeError,
        subprocess.SubprocessError,
    ) as e:
        if failed:
            raise failed(f"{role['model']} gave no answer: {e!r}") from e
        return []


def asked(cli: list[str], prompt: str) -> str:
    """A signed-in CLI's answer, asked in an empty folder (no repository's files or settings) and marked so this package's hooks, which
    its own session may start, return at once; a CLI signed out exits non-zero, no answer."""
    with tempfile.TemporaryDirectory() as empty:
        env = {**os.environ, "RUDNIK_REVIEW_ASKING": "1"}
        return run(
            cli,
            input=prompt,
            cwd=empty,
            env=env,
            check=True,
            timeout=600,
            encoding="utf-8",
        ).stdout


def called(role: D, prompt: str) -> str:
    """The answer of review.toml's <role> over its vendor's API, with the developer's key from the environment: Anthropic's Messages API,
    whose text blocks are the answer and a refusal or a cut-off none, or else the OpenAI-compatible chat API."""
    key, base = os.environ[role["key_env"]], role.get("url", API.get(role["provider"]))
    ask = {"model": role["model"], "messages": [{"role": "user", "content": prompt}]}
    if role["provider"] != "anthropic":
        head = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        said = post(base + "/chat/completions", ask, head)
        return said["choices"][0]["message"]["content"]
    head = {
        "x-api-key": key,
        "anthropic-version": VERSION,
        "content-type": "application/json",
    }
    said = post(base + "/messages", ask | {"max_tokens": 16000}, head)
    if said["stop_reason"] in ("refusal", "max_tokens"):
        # answer() says: <model> gave no answer: ValueError('refusal')
        raise ValueError(said["stop_reason"])
    return "".join(b["text"] for b in said["content"] if b["type"] == "text")


def post(url: str, ask: D, head: dict[str, str], timeout: int = 600) -> D:
    """The JSON a vendor answers to <ask> posted at <url>."""
    req = urllib.request.Request(url, json.dumps(ask).encode(), head)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def said(r):
    """A finding's one line, ending in its whole fingerprint, the one NOTE-WRONG takes (spec 1734)."""
    mark = findings.tier(r)  # spec 1784: error, warning or info
    # an analyser's; a model's carries its source, and may name a `tool` too (the review, 12 Nov 2026)
    if "source" not in r:
        return f"{mark} {r['file']}:{r['line']} {r['tool']} {r['rule']}: {' '.join(r['message'].split())} {r['fingerprint']}"
    unconfirmed = " (unconfirmed)" if r.get("verdict") == "unconfirmed" else ""
    return f"{mark} {r['file']}:{r.get('line', '')} {r['source']} {r['severity']}: {' '.join(r['claim'].split())}{unconfirmed} {r['fingerprint']}"


def sarif(rows, path):
    """SARIF 2.1.0, which Rider opens with JetBrains' SARIF viewer; its folder ignores itself, so no check reads it as a change."""
    results = [result(r) for r in rows]
    report = {"tool": {"driver": {"name": "rudnik-review"}}, "results": results}
    path.write_text(json.dumps({"version": "2.1.0", "runs": [report]}))
    return path


def result(r):
    """A finding as a SARIF result: its file, line, rule and level."""
    place = {"artifactLocation": {"uri": r.get("file", "")}}
    if r.get("line"):
        place["region"] = {"startLine": r["line"]}
    tool = "source" not in r
    rule = f"{r['tool']}/{r['rule']}" if tool else f"review/{r.get('severity')}"
    level = {"error": "error", "warning": "warning", "info": "note"}[findings.tier(r)]
    at, msg = [{"physicalLocation": place}], {"text": said(r)}
    return {"ruleId": rule, "level": level, "message": msg, "locations": at}


def parser():
    p = argparse.ArgumentParser("rudnik-review", description="reviews a branch's work")
    p.add_argument("--version", action="version", version=f"%(prog)s {released()}")
    sub = p.add_subparsers(dest="command", metavar="command")
    c = sub.add_parser(
        "setup",
        help="install the formatters and analysers this repository's languages need",
    )
    c.set_defaults(run=setup)
    c.add_argument("--deep", action="store_true", help="infer too, for check --deep")
    sub.add_parser(
        "update", help="install the next release and its tools"
    ).set_defaults(run=update)
    c = sub.add_parser(
        "check",
        help="what this branch adds: an error stops you, a warning or an info does not",
    )
    c.set_defaults(run=check)
    c.add_argument("--base", help="the branch it merges into, found when not given")
    c.add_argument("--files", nargs="+", help="check only these files")
    c.add_argument(
        "--llm",
        action="store_true",
        help="also have another vendor's model review the diff",
    )
    c.add_argument(
        "--local",
        metavar="URL[#MODEL]",
        default=os.environ.get("RUDNIK_REVIEW_LOCAL"),
        help="also ask a model you host each rule a hunk triggers, and to review each changed file freely (OpenAI's chat API)",
    )
    c.add_argument(
        "--local-verifier",
        metavar="URL[#MODEL]",
        help="the model you host that traces each free claim, a thinking one (default: $RUDNIK_REVIEW_LOCAL_VERIFIER, else --local's)",
    )
    c.add_argument(
        "--author",
        help="the model that wrote the change, so another vendor's reviews it",
    )
    c.add_argument(
        "--format",
        choices=("text", "json", "sarif", "github"),
        default="text",
        help="sarif writes .rudnik/review.sarif; github marks the pull request's lines",
    )
    c.add_argument(
        "--hook",
        action="store_true",
        help="started by an agent's stop hook, not by hand",
    )
    c.add_argument(
        "--staged", action="store_true", help="what you staged: what a commit holds"
    )
    c.add_argument("--all", action="store_true", help="ruff's notes too")
    c.add_argument("--deep", action="store_true", help="infer too: minutes a build")
    c = sub.add_parser("fmt", help="format the files you changed")
    c.set_defaults(run=fmt, base=None)
    c.add_argument("--files", nargs="+", help="format only these files")
    c.add_argument(
        "--all", action="store_true", help="format every file, once a repository"
    )
    sub.add_parser(
        "mcp",
        help="check and explain as an agent's tools: started by the editor's integration, not by hand",
    ).set_defaults(run=mcp)
    c = sub.add_parser(
        "init",
        help="wire what it finds here: Cursor, Claude Code, Codex, JetBrains and git's commit",
    )
    c.set_defaults(run=init)
    c.add_argument(
        "what",
        nargs="?",
        choices=WIRED,
        help="wire this one alone; github: the pull request's check",
    )
    c = sub.add_parser(
        "hook", help="an agent's hook: started by the editor's integration, not by hand"
    )
    # 1715: a hook started by the review's own CLI call does nothing, or each review would start another
    c.set_defaults(
        run=lambda a: 0 if os.environ.get("RUDNIK_REVIEW_ASKING") else HOOKS[a.what](a)
    )
    c.add_argument("what", choices=HOOKS, help="the hook the integration names")
    return p


HOOKS = {
    "cursor-stop": stop,
    "cursor-reply": cursor_reply,
    "claude-post": claude,
    "claude-stop": claude,
    "codex-stop": claude,
}


def main(argv=None):
    a = parser().parse_args(argv)
    try:  # 1865 (owner, 17 Nov 2026: "such poor user experience"): no command sets up and checks, one command to learn
        return a.run(a) if a.command else setup_and_check(a)
    # a crash too is a check that could not run: never Python's exit 1, which reads as a blocking finding
    except Exception as e:
        failed(e)
        return (
            0 if getattr(a, "hook", False) else 2
        )  # the hook never makes a stop wait: the gate judges after


if __name__ == "__main__":
    sys.exit(main())
