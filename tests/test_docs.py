"""Keep agent-facing documentation executable.

SKILL.md and AGENTS.md are read by LLM agents, which copy the snippets verbatim.
A wrong option name or a renamed parameter therefore does not produce a confusing
sentence — it produces a failing command. These tests check the documentation
against the real Typer app and the real function signatures, so drift breaks the
build instead of breaking an agent run.

What is checked:
  * every ```python``` block parses, and every call to a documented FridaPilot
    function binds against its actual signature (unknown kwargs, too many
    positionals);
  * every ``fp ...`` line in a ```bash``` block resolves to a registered command,
    uses only real options, satisfies required options and stays within the
    declared positional arguments;
  * ``<!-- return-keys: func = a, b, c -->`` markers match the keys the function
    actually returns, exercised on the synthetic PE.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import re
import shlex
from pathlib import Path

import pytest

from .synthetic_pe import MARKER_TEXT, TARGET_RVA, TEXT_RVA, TEXT_VSIZE, write_synthetic_pe


REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = [
    REPO_ROOT / "AGENTS.md",
    REPO_ROOT / "skills" / "fridapilot-pe-analysis" / "SKILL.md",
]

FENCE = re.compile(r"^```(\w+)\s*$(.*?)^```\s*$", re.MULTILINE | re.DOTALL)
INLINE_CODE = re.compile(r"`([^`\n]+)`")
RETURN_KEYS = re.compile(r"<!--\s*return-keys:\s*([\w.]+)\s*=\s*([^>]+?)\s*-->")



def _docs() -> list[Path]:
    present = [p for p in DOCS if p.is_file()]
    assert present, "no agent-facing documentation found"
    return present


def _blocks(text: str, language: str) -> list[str]:
    return [body for lang, body in FENCE.findall(text) if lang == language]


def _doc_ids(paths: list[Path]) -> list[str]:
    return [str(p.relative_to(REPO_ROOT)) for p in paths]


DOC_FILES = _docs()


# ── python snippets ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("doc", DOC_FILES, ids=_doc_ids(DOC_FILES))
def test_python_blocks_parse(doc: Path):
    for i, block in enumerate(_blocks(doc.read_text(encoding="utf-8"), "python")):
        try:
            ast.parse(block)
        except SyntaxError as exc:
            pytest.fail(f"{doc.name} python block #{i + 1} does not parse: {exc}")


def _documented_callables(tree: ast.Module) -> dict[str, object]:
    """Map local names to real objects, following the block's own imports."""
    resolved: dict[str, object] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or not node.module:
            continue
        if not node.module.startswith("fridapilot"):
            continue
        module = importlib.import_module(node.module)
        for alias in node.names:
            obj = getattr(module, alias.name, None)
            if obj is not None:
                resolved[alias.asname or alias.name] = obj
    return resolved


class _Any:
    """Placeholder for a positional argument whose value is irrelevant here."""


@pytest.mark.parametrize("doc", DOC_FILES, ids=_doc_ids(DOC_FILES))
def test_python_calls_match_real_signatures(doc: Path):
    text = doc.read_text(encoding="utf-8")
    blocks = _blocks(text, "python")
    known: dict[str, object] = {}
    instances: dict[str, type] = {}

    for block in blocks:                       # imports may live in an earlier block
        tree = ast.parse(block)
        known.update(_documented_callables(tree))

    checked = 0
    for block in blocks:
        tree = ast.parse(block)
        for node in ast.walk(tree):
            # var = SomeClass(...)  ->  remember the type for method checks
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name)):
                obj = known.get(node.value.func.id)
                if inspect.isclass(obj):
                    instances[node.targets[0].id] = obj

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = None
            label = ""
            if isinstance(node.func, ast.Name) and node.func.id in known:
                target = known[node.func.id]
                label = node.func.id
            elif (isinstance(node.func, ast.Attribute)
                  and isinstance(node.func.value, ast.Name)
                  and node.func.value.id in instances):
                cls = instances[node.func.value.id]
                target = getattr(cls, node.func.attr, None)
                label = f"{cls.__name__}.{node.func.attr}"
                if target is None:
                    pytest.fail(f"{doc.name}: {label} does not exist")
            if target is None or not callable(target):
                continue

            sig = inspect.signature(target)
            positional = [_Any()] * len(node.args)
            if isinstance(node.func, ast.Attribute):
                positional.insert(0, _Any())          # bound self
            kwargs = {kw.arg: _Any() for kw in node.keywords if kw.arg}
            try:
                sig.bind_partial(*positional, **kwargs)
            except TypeError as exc:
                pytest.fail(f"{doc.name}: {label}{sig} rejects the documented "
                            f"call ({exc})")
            checked += 1

    if known and not checked:
        pytest.fail(f"{doc.name}: imports FridaPilot symbols but shows no calls to them")



# ── CLI snippets ────────────────────────────────────────────────────────────

def _click_root():
    import typer.main

    from fridapilot.cli.main import app

    return typer.main.get_command(app)


def _cli_lines(text: str) -> list[tuple[str, str]]:
    """Runnable `fp ...` examples as (source, line), source in {"bash", "inline"}.

    Inline spans are included because documentation often writes commands as
    ``CLI: `fp binary ...` `` — still copied verbatim by an agent. A span that is
    only a command path (`fp dbg`, `fp binary analyze-pe`) is a prose reference,
    not an invocation, and is skipped during validation.
    """
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(source: str, raw: str) -> None:
        line = raw.split("#", 1)[0].split("|", 1)[0].strip()
        if line.split()[:1] in (["fp"], ["frida-pilot"]) and line not in seen:
            seen.add(line)
            found.append((source, line))

    for block in _blocks(text, "bash"):
        for raw in block.splitlines():
            if raw.strip() and not raw.strip().startswith("#"):
                add("bash", raw.strip())

    for span in INLINE_CODE.findall(text):
        add("inline", span.strip())

    return found




CLI_LINES = [(doc, source, line)
             for doc in DOC_FILES
             for source, line in _cli_lines(doc.read_text(encoding="utf-8"))]


def test_cli_examples_exist():
    assert CLI_LINES, "documentation shows no `fp` commands - nothing to validate"


@pytest.mark.parametrize("doc,source,line", CLI_LINES,
                         ids=[f"{d.name}: {ln[:60]}" for d, _s, ln in CLI_LINES])
def test_cli_example_is_accepted_by_the_app(doc: Path, source: str, line: str):
    import click

    tokens = shlex.split(line, posix=True)[1:]
    command = _click_root()
    root = command
    path = []

    # descend through command groups
    while tokens and isinstance(command, click.Group) and not tokens[0].startswith("-"):
        name = tokens.pop(0)
        sub = command.commands.get(name)
        assert sub is not None, f"{doc.name}: unknown command `{' '.join(path + [name])}`"
        command = sub
        path.append(name)
    if not path:
        # `fp --help` / `fp --version`: no subcommand, only root options
        assert command is root, line
    if source == "inline" and not tokens:
        pytest.skip(f"`{line}` is a command reference, not an invocation")



    options = {"--help": None, "-h": None}   # click adds these lazily
    arguments = []
    for param in command.params:
        if param.param_type_name == "option":
            for opt in list(param.opts) + list(param.secondary_opts):
                options[opt] = param
        else:
            arguments.append(param)

    seen = set()
    positional = 0
    while tokens:
        token = tokens.pop(0)
        if token.startswith("-") and token != "-":
            name, _, inline = token.partition("=")
            assert name in options, \
                f"{doc.name}: `fp {' '.join(path)}` has no option {name}"
            param = options[name]
            if param is None:
                continue                      # --help / -h
            seen.add(param.name)
            if not param.is_flag and not inline:
                assert tokens, f"{doc.name}: {name} is missing its value"
                tokens.pop(0)
        else:
            positional += 1


    missing = [p.opts[0] for p in command.params
               if p.param_type_name == "option" and p.required and p.name not in seen]
    assert not missing, f"{doc.name}: `fp {' '.join(path)}` needs {missing}"

    required_args = sum(1 for a in arguments if a.required)
    variadic = any(a.nargs == -1 for a in arguments)
    assert positional >= required_args, \
        f"{doc.name}: `fp {' '.join(path)}` needs {required_args} positional arg(s)"
    if not variadic:
        assert positional <= len(arguments), \
            f"{doc.name}: `fp {' '.join(path)}` takes {len(arguments)} positional " \
            f"arg(s), example passes {positional}"


# ── documented return keys ──────────────────────────────────────────────────

@pytest.fixture(scope="module")
def pe_path(tmp_path_factory) -> str:
    path, _placed, _end = write_synthetic_pe(
        tmp_path_factory.mktemp("docs_pe") / "synthetic.dll")
    return path


def _actual_keys(name: str, path: str) -> set[str]:
    from fridapilot.tools import binary_analysis, pe_metadata, pe_rva, rip_index


    end = TEXT_RVA + TEXT_VSIZE
    calls = {
        "find_string_rvas": lambda: pe_rva.find_string_rvas(path, ["\x01"])[0],
        "xrefs_to_rva": lambda: pe_rva.xrefs_to_rva(path, TARGET_RVA, TEXT_RVA, end,
                                                    kinds=("rip",))[0],
        "field_refs": lambda: None,
        "function_bounds": lambda: pe_rva.function_bounds(path, TEXT_RVA),
        "disassemble_rva": lambda: pe_rva.disassemble_rva(path, TEXT_RVA, 1),
        "map_refs_to_functions": lambda: pe_rva.map_refs_to_functions(
            path, {"g": TARGET_RVA}, TEXT_RVA, end),
        "section_range": lambda: pe_rva.section_range(path, ".text"),
        "build_rip_index": lambda: rip_index.build_rip_index(
            path, db_path=str(Path(path).with_suffix(".ripindex.db"))),


        "find_text": lambda: binary_analysis.find_text(
            path, MARKER_TEXT, encodings=("ascii",))[0].model_dump(),
        "find_strings": lambda: binary_analysis.find_strings(
            path, min_len=8, encoding="ascii")[0].model_dump(),
        "search_bytes": lambda: binary_analysis.search_bytes(path, "4d5a")[0].model_dump(),
        "pe_metadata": lambda: pe_metadata.pe_metadata(path),
    }
    if name not in calls:
        pytest.fail(f"return-keys marker for unsupported function {name}")
    result = calls[name]()
    if result is None:
        pytest.skip(f"{name} produces no rows on the fixture")
    return set(result.keys())



MARKERS = [(doc, name, keys)
           for doc in DOC_FILES
           for name, keys in RETURN_KEYS.findall(doc.read_text(encoding="utf-8"))]


def test_return_key_markers_exist():
    assert MARKERS, "no <!-- return-keys: ... --> markers found in the docs"


@pytest.mark.parametrize("doc,name,keys", MARKERS,
                         ids=[f"{d.name}: {n}" for d, n, _k in MARKERS])
def test_documented_return_keys_are_real(doc: Path, name: str, keys: str, pe_path: str):
    documented = {k.strip() for k in keys.split(",") if k.strip()}
    assert documented == _actual_keys(name, pe_path), \
        f"{doc.name}: {name} documents {sorted(documented)}"
