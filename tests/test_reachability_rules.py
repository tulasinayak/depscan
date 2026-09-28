"""T4: reachability rules. Entry points of each kind, function references, and the conservative rule: whatever
the analysis cannot follow is "unknown", never "fail" (unreachable)."""

import textwrap
from pathlib import Path

import pytest

from depscan.agents.repo_context import RepoContextAgent
from depscan.agents.repo_mapper import RepoMapperAgent
from depscan.codeindex import CodeIndex
from depscan.models import RepoMapperInput, ScanResult
from datetime import datetime, timezone

VULN = "def load_config(text):\n    return yaml.safe_load(text)\n"      # line 2 of the target's function


def index_of(tmp_path: Path, files: dict[str, str]) -> tuple[CodeIndex, Path]:
    repo = tmp_path / "repo"
    for rel, text in {"requirements.txt": "pyyaml==5.3.1\n", **files}.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8", newline="\n")
    rmap = RepoMapperAgent(tmp_path / "ws").run(RepoMapperInput(url=str(repo)))
    ctx = RepoContextAgent(None).run(ScanResult(created_at=datetime.now(timezone.utc), repo=rmap,
                                                vulnerabilities=[], usages={}))
    return CodeIndex(repo, rmap.source_files, ctx.app_type), repo


def reach(tmp_path, files, target="app/util.py"):
    idx, repo = index_of(tmp_path, files)
    lines = (repo / target).read_text(encoding="utf-8").splitlines()
    line = next(i for i, ln in enumerate(lines, 1) if "yaml.safe_load" in ln)
    return idx.reach(target, line, "yaml.safe_load")


UTIL = {"app/__init__.py": "", "app/util.py": "import yaml\n\n\n" + VULN}

# ---------------------------------------------------------------- entry points of each kind

ENTRY = {
    "flask_route": {"app/web.py": """
        from flask import Flask, request
        from app.util import load_config
        app = Flask(__name__)

        @app.route("/cfg", methods=["POST"])
        def cfg():
            return load_config(request.data)
    """},
    "fastapi_route": {"app/api.py": """
        from fastapi import FastAPI
        from app.util import load_config
        api = FastAPI()

        @api.post("/cfg")
        async def cfg(body: str):
            return load_config(body)
    """},
    "django_urls_views": {"manage.py": "import os\nif __name__ == '__main__':\n    os.environ['X'] = '1'\n",
                          "app/urls.py": "from django.urls import path\nfrom app import views\n"
                                         "urlpatterns = [path('cfg/', views.cfg)]\n",
                          "app/views.py": "from app.util import load_config\n\n\ndef cfg(request):\n"
                                          "    return load_config(request.body)\n",
                          "app/settings.py": "ROOT_URLCONF = 'app.urls'\n"},
    "click_command": {"app/cli.py": """
        import click
        from app.util import load_config

        @click.command()
        @click.argument("path")
        def main(path):
            load_config(open(path).read())

        if __name__ == "__main__":
            main()
    """},
    "typer_command": {"app/cli.py": """
        import typer
        from app.util import load_config
        app = typer.Typer()

        @app.command()
        def run(path: str):
            load_config(open(path).read())
    """},
    "argparse_main": {"app/tool.py": """
        import argparse
        from app.util import load_config

        def main():
            p = argparse.ArgumentParser()
            p.add_argument("path")
            load_config(open(p.parse_args().path).read())

        if __name__ == "__main__":
            main()
    """},
    "console_scripts": {"pyproject.toml": "[project]\nname = 'x'\nversion = '1'\n[project.scripts]\n"
                                          "tool = 'app.tool:main'\n",
                        "app/tool.py": "from app.util import load_config\n\n\ndef main():\n"
                                       "    load_config('a: 1')\n"},
    "dunder_main": {"app/__main__.py": "from app.util import load_config\n\nload_config('a: 1')\n"},
    "celery_task": {"app/tasks.py": """
        from celery import Celery
        from app.util import load_config
        celery = Celery("x")

        @celery.task
        def refresh(text):
            return load_config(text)
    """},
}


@pytest.mark.parametrize("kind", sorted(ENTRY))
def test_entry_points_make_code_reachable(tmp_path, kind):
    r = reach(tmp_path, {**UTIL, **ENTRY[kind]})
    assert r.result == "pass", (kind, r.explanation)


# ---------------------------------------------------------------- function references

ENTRY_MAIN = "from app.registry import dispatch\n\nif __name__ == '__main__':\n    dispatch('load', 'a: 1')\n"
REFS = {
    "callback_argument": """
        from app.util import load_config
        HOOKS = []

        def register(fn):
            HOOKS.append(fn)

        register(load_config)

        def dispatch(name, text):
            return [h(text) for h in HOOKS]
    """,
    "registering_decorator": """
        import yaml
        HANDLERS = {}

        def handler(name):
            def wrap(fn):
                HANDLERS[name] = fn
                return fn
            return wrap

        @handler("load")
        def load_config(text):
            return yaml.safe_load(text)

        def dispatch(name, text):
            return HANDLERS[name](text)
    """,
    "dict_registry": """
        from app.util import load_config
        HANDLERS = {"load": load_config}

        def dispatch(name, text):
            return HANDLERS[name](text)
    """,
    "method_via_instance": """
        import yaml

        class Service:
            def load_config(self, text):
                return yaml.safe_load(text)

        def dispatch(name, text):
            return Service().load_config(text)
    """,
}


@pytest.mark.parametrize("kind", sorted(REFS))
def test_function_references_are_followed(tmp_path, kind):
    files = {**UTIL, "app/registry.py": REFS[kind], "app/__main__.py": ENTRY_MAIN}
    target = "app/registry.py" if "yaml.safe_load" in REFS[kind] else "app/util.py"
    r = reach(tmp_path, files, target)
    assert r.result == "pass", (kind, r.explanation)


def test_dunder_all_export_of_a_library_is_not_unreachable(tmp_path):
    r = reach(tmp_path, {"app/__init__.py": "from app.util import load_config\n__all__ = ['load_config']\n",
                         "app/util.py": "import yaml\n\n\n" + VULN})
    assert r.result != "fail", r.explanation


def test_really_dead_code_is_unreachable(tmp_path):
    """Control: the same function, referenced nowhere, in an app with a real entry point."""
    files = {**UTIL, "app/__main__.py": "print('hello')\n"}
    assert reach(tmp_path, files).result == "fail"


# ---------------------------------------------------------------- what the analysis cannot follow: never "fail"

OPAQUE = {
    "getattr_variable": "import sys\nfrom app import util\n\nif __name__ == '__main__':\n"
                        "    getattr(util, sys.argv[1])('a: 1')\n",
    "importlib_variable": "import importlib, sys\n\nif __name__ == '__main__':\n"
                          "    importlib.import_module(sys.argv[1]).load_config('a: 1')\n",
    "exec_eval": "import sys\nfrom app import util\n\nif __name__ == '__main__':\n    eval(sys.argv[1])\n",
    "signal_handler": "import signal\nfrom app import util\n\nif __name__ == '__main__':\n"
                      "    signal.signal(signal.SIGTERM, lambda *a: util.__dict__[input()]('a: 1'))\n",
    "name_in_string": "from app import util\nACTIONS = ['load_config']\n\nif __name__ == '__main__':\n"
                      "    for a in ACTIONS:\n        getattr(util, a)('a: 1')\n",
}


@pytest.mark.parametrize("kind", sorted(OPAQUE))
def test_constructs_the_analysis_cannot_follow_are_never_unreachable(tmp_path, kind):
    r = reach(tmp_path, {**UTIL, "app/__main__.py": OPAQUE[kind]})
    assert r.result != "fail", (kind, r.explanation)


def test_plugin_entry_points_are_never_unreachable(tmp_path):
    files = {**UTIL, "pyproject.toml": "[project]\nname='x'\nversion='1'\n"
                                       "[project.entry-points.'x.plugins']\ncfg = 'app.util:load_config'\n"}
    assert reach(tmp_path, files).result != "fail"


def test_signal_handler_function_is_never_unreachable(tmp_path):
    files = {**UTIL, "app/__main__.py": "import signal\nfrom app.util import load_config\n\n\ndef on_term(*a):\n"
                                       "    load_config('a: 1')\n\n\nsignal.signal(signal.SIGTERM, on_term)\n"}
    assert reach(tmp_path, files).result != "fail"
