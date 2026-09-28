"""Deterministic parts of RepoContextAgent."""

import pytest

from depscan.agents.repo_context import RepoContextAgent, analyze_file, console_scripts, first_sentences, path_context
from depscan.config import LLMConfig
from depscan.llm.client import LLMClient
from fake_llm import FakeOpenAI
from test_orchestrator import FIX, make_orch


@pytest.fixture(scope="module")
def flask_result(tmp_path_factory):
    return make_orch(tmp_path_factory.mktemp("ctx")).scan(str(FIX / "flask_vuln_repo"))


def test_web_service_detection(flask_result):
    ctx = RepoContextAgent().deterministic(flask_result)
    assert ctx.app_type == "web_service"
    assert "flask" in ctx.frameworks
    assert "app/__init__.py:4 app factory create_app()" in ctx.entry_points
    assert "app/routes.py:9 route '/import' -> import_config()" in ctx.entry_points
    assert "manage.py:5 __main__ block" in ctx.entry_points


def test_untrusted_input_sources(flask_result):
    ctx = RepoContextAgent().deterministic(flask_result)
    found = {(u.file, u.line, u.symbol) for u in ctx.untrusted_input_sources}
    assert ("app/routes.py", 11, "request.data") in found
    assert ("app/routes.py", 22, "request.files") in found
    assert ("manage.py", 6, "sys.argv") in found
    assert any(s.startswith("open(sys.argv[1])") for _, _, s in found)
    listed = [(u.file, u.line, u.symbol) for u in ctx.untrusted_input_sources]
    assert len(listed) == len(set(listed))            # open(sys.argv[1]) + sys.argv on one line: listed once each


def test_usage_contexts_are_path_based(flask_result):
    ctx = RepoContextAgent().deterministic(flask_result)
    sites = {s.file: s.id for s in flask_result.usages["pyyaml"].sites}
    assert ctx.usage_contexts[sites["app/routes.py"]] == "prod"
    assert ctx.usage_contexts[sites["tests/test_yaml_compat.py"]] == "test"


@pytest.mark.parametrize("path,ctx", [("app/x.py", "prod"), ("tests/test_a.py", "test"), ("conftest.py", "test"),
                                      ("examples/demo.py", "example"), ("docs/conf.py", "example"),
                                      ("scripts/seed.py", "script"), ("src/pkg/mod.py", "prod")])
def test_path_context(path, ctx):
    assert path_context(path) == ctx


def test_cli_detection_and_console_scripts(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "tool"\n[project.scripts]\ntool = "tool.cli:main"\n')
    (tmp_path / "setup.py").write_text("setup(entry_points={'console_scripts': ['legacy=tool.old:main']})\n")
    assert console_scripts(tmp_path) == ["console_script tool = tool.cli:main", "console_script legacy=tool.old:main"]
    facts = analyze_file("import click\n\n@click.command()\n@click.option('--name')\ndef main(name):\n    pass\n", "tool/cli.py")
    assert [u.symbol for u in facts["inputs"]] == ["click.option"]


def test_imports_in_tests_do_not_decide_app_type(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "lib"\ndependencies = ["click==8.0.0"]\n')
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("import click\nimport flask\n")
    result = make_orch(tmp_path / "o").scan(str(tmp_path))
    ctx = RepoContextAgent().deterministic(result)
    assert ctx.app_type == "library" and "click" in ctx.frameworks


def test_argparse_and_input(tmp_path):
    facts = analyze_file("import argparse\np = argparse.ArgumentParser()\np.add_argument('x')\nargs = p.parse_args()\n"
                         "name = input('?')\nopen(args.path)\nopen('fixed.txt')\n", "cli.py")
    assert [u.symbol for u in facts["inputs"]] == ["argparse.add_argument", "argparse.parse_args", "input()",
                                                    "open(args.path) on a user-supplied path"]


def test_summary_from_one_short_llm_call(flask_result, tmp_path):
    fake = FakeOpenAI(["A Flask web service. It accepts YAML over HTTP. It calls an upstream. Extra sentence."])
    ctx = RepoContextAgent(LLMClient(LLMConfig(), client=fake)).run(flask_result)
    assert ctx.summary == "A Flask web service. It accepts YAML over HTTP. It calls an upstream."
    assert len(fake.calls) == 1 and "response_format" not in fake.calls[0]
    assert "config-service" in fake.calls[0]["messages"][1]["content"]   # README head included


def test_first_sentences():
    assert first_sentences("One. Two!  Three? Four.") == "One. Two! Three?"
