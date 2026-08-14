"""Guards on the test harness itself (dexllm#40).

`tests/llm_backend_integration.py` held the only end-to-end coverage of the MCP
server and the FastAPI backend and was never collected — its name is outside
pytest's `test_*.py` pattern. Nothing noticed for months, and it rotted to a
hard-coded `15 tools` against a catalog of 36. A test that cannot run is worse
than no test: it reads as coverage.
"""

import ast
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent

# Modules that deliberately hold no pytest test functions (helpers, harnesses).
# They are checked to STAY that way: adding a `def test_*` to one silently buys
# a test that never runs.
NOT_COLLECTED = {"conftest.py", "dvclass_parity.py"}


def _test_functions(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    return [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    ]


def test_every_module_holding_tests_is_collectible():
    """A `def test_*` outside a `test_*.py` file is invisible to pytest."""
    stranded = {}
    for path in sorted(TESTS.glob("*.py")):
        if path.name.startswith("test_"):
            continue
        found = _test_functions(path)
        if found:
            stranded[path.name] = found
    assert not stranded, (
        f"these modules define test functions pytest will never collect: {stranded} — "
        f"rename them to test_*.py (dexllm#40)"
    )


def test_the_known_helper_modules_are_still_the_only_uncollected_ones():
    """The allow-list must not silently grow a module nobody runs."""
    uncollected = {p.name for p in TESTS.glob("*.py") if not p.name.startswith("test_")}
    assert uncollected == NOT_COLLECTED, (
        f"uncollected modules changed: {uncollected ^ NOT_COLLECTED} — either name it "
        f"test_*.py or add it to NOT_COLLECTED with a reason"
    )


@pytest.mark.parametrize("name", ["test_llm_backends.py"])
def test_the_llm_backend_suite_is_present_under_its_collectible_name(name):
    """The specific file dexllm#40 was filed for."""
    assert (TESTS / name).is_file(), f"{name} is gone or renamed back"
