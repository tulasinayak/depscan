from pathlib import Path

import pytest

from depscan.agents.repo_mapper import RepoMapperAgent, clone_dir_name, repo_name_from_url
from depscan.models import RepoMapperInput
from depscan.parsers import normalize_name
from depscan.parsers.python_manifests import (
    PipfileLockParser, PoetryLockParser, PyprojectParser, RequirementsTxtParser, UvLockParser, exact_version,
    name_from_url, requirements_scope,
)

FIX = Path(__file__).parent / "fixtures" / "manifests"


def scan(name: str):
    result = RepoMapperAgent(workspace=Path("unused")).run(RepoMapperInput(url=str(FIX / name)))
    return result, {d.name: d for d in result.dependencies}


@pytest.mark.parametrize("raw,norm", [("PyYAML", "pyyaml"), ("Foo_Bar.baz", "foo-bar-baz"), ("beautifulsoup4", "beautifulsoup4")])
def test_normalize_name(raw, norm):
    assert normalize_name(raw) == norm


@pytest.mark.parametrize("spec,version", [("==3.13", "3.13"), ("===1.0", "1.0"), (">=2.0", None),
                                          ("==2.*", None), (">=1,<2", None), (None, None)])
def test_exact_version(spec, version):
    assert exact_version(spec) == version


# ---------------------------------------------------------------- requirements.txt basics

def test_requirements_txt():
    out = RequirementsTxtParser().parse(FIX / "req_repo" / "requirements.txt", "requirements.txt")
    by = {e.name: e for e in out.entries}
    assert by["flask"].resolved_version == "2.0.1"
    assert by["pyyaml"].resolved_version == "3.13"
    assert by["requests"].resolved_version is None and by["requests"].version_spec == "<3,>=2.19"
    assert by["requests"].unresolved_reason == "version spec '<3,>=2.19' is not an exact pin"
    assert by["beautifulsoup4"].unresolved_reason == "no version specified"
    assert by["urllib3"].resolved_version == "1.24.1"            # continuation line + --hash stripped
    assert by["pytest"].source_file == "requirements-dev.txt"    # followed -r include


def test_requirements_repo_end_to_end():
    result, deps = scan("req_repo")
    assert result.repo_name == "req_repo"
    assert result.source_files == ["app.py"]
    assert sorted(result.manifest_files) == ["requirements-dev.txt", "requirements.txt"]  # .venv skipped
    assert all(d.direct for d in deps.values())
    assert deps["flask"].resolved_version == "2.0.1"             # not 9.9.9 from .venv
    assert deps["requests"].resolved_version is None


# ---------------------------------------------------------------- fix 2: includes, constraints, URLs, extras, markers

@pytest.fixture(scope="module")
def features():
    return scan("req_features_repo")[1]


def test_nested_include_relative_to_including_file(features):
    # requirements.txt -> base/common.txt -> ../shared/extra.txt
    assert features["click"].source_file == "base/common.txt" and features["click"].resolved_version == "8.0.0"
    assert features["idna"].source_file == "shared/extra.txt" and features["idna"].resolved_version == "2.8"


def test_constraint_file_pins_but_never_adds(features):
    assert features["requests"].version_spec == ">=2.0"
    assert features["requests"].resolved_version == "2.19.1" and features["requests"].unresolved_reason is None
    assert "urllib3" not in features                             # only in constraints.txt


def test_extras_and_markers(features):
    assert features["requests"].extras == ["security", "socks"]
    assert features["colorama"].marker == 'sys_platform == "win32"'
    assert features["colorama"].resolved_version == "0.4.4"


@pytest.mark.parametrize("name,reason_start", [
    ("local-pkg", "editable install from ./local_pkg"),
    ("editable-lib", "editable install from git+https://github.com/org/editable-lib.git#egg=editable-lib"),
    ("mylib", "installed from URL git+https://github.com/org/mylib.git@v1.0"),
    ("some-dist", "installed from URL https://files.example.com/pkgs/some_dist-1.2.0.tar.gz"),
])
def test_url_and_editable_deps_are_kept_as_unresolvable(features, name, reason_start):
    dep = features[name]
    assert dep.resolved_version is None and dep.unresolved_reason.startswith(reason_start)


def test_unconstrained_package(features):
    assert features["unconstrained-pkg"].resolved_version is None
    assert features["unconstrained-pkg"].unresolved_reason == "no version specified"


@pytest.mark.parametrize("url,name", [
    ("git+https://github.com/org/x.git#egg=real-name", "real-name"),
    ("./libs/my_pkg", "my_pkg"),
    ("https://host/p/some_dist-1.2.0-py3-none-any.whl", "some_dist"),
])
def test_name_from_url(url, name):
    assert name_from_url(url) == name


# ---------------------------------------------------------------- fix 3: scope

@pytest.mark.parametrize("path,scope", [
    ("requirements.txt", "main"), ("requirements-dev.txt", "dev"), ("requirements-test-integration.txt", "dev"),
    ("requirements_testing.txt", "dev"), ("dev-requirements.txt", "dev"), ("requirements/test.txt", "dev"),
    ("requirements/prod.txt", "main"), ("requirements-prod.txt", "main"), ("base/common.txt", "main"),
])
def test_requirements_scope(path, scope):
    assert requirements_scope(path) == scope


def test_requirements_scopes_in_repo(features):
    assert features["requests"].scope == "main"
    assert features["pytest"].scope == "dev"
    assert features["responses"].scope == "dev"


def test_pep621_with_uv_lock():
    out = PyprojectParser().parse(FIX / "pep621_uv_repo" / "pyproject.toml", "pyproject.toml")
    assert {e.name for e in out.entries} == {"jinja2", "click", "sphinx", "pytest", "ruff"}
    lock = UvLockParser().parse(FIX / "pep621_uv_repo" / "uv.lock", "uv.lock")
    by = {e.name: e for e in lock.entries}
    assert "demo" not in by                                      # the project itself is not a dependency
    assert by["jinja2"].direct and not by["markupsafe"].direct

    _, deps = scan("pep621_uv_repo")
    assert deps["jinja2"].resolved_version == "3.1.2"            # range in pyproject, version from uv.lock
    assert deps["jinja2"].version_spec == ">=3.0" and deps["jinja2"].direct
    assert deps["markupsafe"].resolved_version == "2.1.3" and not deps["markupsafe"].direct
    assert deps["markupsafe"].source_file == "uv.lock"
    assert deps["sphinx"].resolved_version is None               # declared, not locked -> unresolved
    assert deps["jinja2"].scope == "main"                        # [project.dependencies]
    assert deps["sphinx"].scope == "dev"                         # [project.optional-dependencies]
    assert deps["pytest"].scope == "dev" and deps["ruff"].scope == "dev"   # PEP 735 groups
    assert deps["markupsafe"].scope == "unknown"                 # transitive, lockfile-only


def test_poetry():
    out = PyprojectParser().parse(FIX / "poetry_repo" / "pyproject.toml", "pyproject.toml")
    by = {e.name: e for e in out.entries}
    assert "python" not in by
    assert by["pillow"].resolved_version == "9.0.0"              # bare Poetry version = exact pin
    assert by["requests"].resolved_version is None               # caret range
    assert by["black"].resolved_version == "22.3.0"
    assert by["mylib"].unresolved_reason.startswith("installed from git")
    assert len(PoetryLockParser().parse(FIX / "poetry_repo" / "poetry.lock", "poetry.lock").entries) == 4

    _, deps = scan("poetry_repo")
    assert deps["requests"].resolved_version == "2.25.1" and deps["requests"].direct
    assert deps["idna"].resolved_version == "2.10" and not deps["idna"].direct
    assert deps["requests"].scope == "main" and deps["black"].scope == "dev"
    assert deps["idna"].scope == "unknown"                       # lock without category/groups


def test_pipenv():
    out = PipfileLockParser().parse(FIX / "pipenv_repo" / "Pipfile.lock", "Pipfile.lock")
    by = {e.name: e for e in out.entries}
    assert by["mylib"].resolved_version is None and by["mylib"].unresolved_reason.startswith("locked from git")
    _, deps = scan("pipenv_repo")
    assert deps["django"].resolved_version == "3.2.0" and deps["django"].direct
    assert deps["sqlparse"].resolved_version == "0.4.1" and not deps["sqlparse"].direct
    assert deps["django"].scope == "main" and deps["pytest"].scope == "dev" and deps["sqlparse"].scope == "main"


def test_pip_compile_via_annotations_fill_required_by(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "flask==2.0.1\n    # via -r requirements.in\n"
        "jinja2==3.0.1\n    # via\n    #   -r requirements.in\n    #   flask\n"
        "markupsafe==2.0.1  # via jinja2, werkzeug\n")
    deps = {d.name: d for d in RepoMapperAgent(tmp_path / "ws").run(RepoMapperInput(url=str(tmp_path))).dependencies}
    assert deps["flask"].required_by == []
    assert deps["jinja2"].required_by == ["flask"]
    assert deps["markupsafe"].required_by == ["jinja2", "werkzeug"]


# ---------------------------------------------------------------- naming

def test_repo_and_clone_names():
    assert repo_name_from_url("https://github.com/org/my-repo.git") == "my-repo"
    assert repo_name_from_url("https://github.com/org/my-repo/") == "my-repo"
    assert repo_name_from_url("git@github.com:org/thing.git") == "thing"
    assert clone_dir_name("https://github.com/alice/tools") == "alice__tools"
    assert clone_dir_name("https://github.com/bob/tools.git") == "bob__tools"
    assert clone_dir_name("git@github.com:alice/tools.git") == "alice__tools"


def test_empty_repo_warns(tmp_path):
    result = RepoMapperAgent(workspace=tmp_path).run(RepoMapperInput(url=str(tmp_path)))
    assert result.dependencies == [] and any("No Python manifest" in w for w in result.warnings)


def test_lockfile_git_and_path_sources_are_not_pypi_versions(tmp_path):
    from depscan.parsers.python_manifests import PoetryLockParser, UvLockParser
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "private-lib"\nversion = "1.2.0"\ngroups = ["main"]\n'
        '[package.source]\ntype = "git"\nurl = "https://example.org/private-lib.git"\n\n'
        '[[package]]\nname = "requests"\nversion = "2.31.0"\ngroups = ["main"]\n', encoding="utf-8")
    entries = {e.name: e for e in PoetryLockParser().parse(tmp_path / "poetry.lock", "poetry.lock").entries}
    assert entries["private-lib"].resolved_version is None and "not a PyPI release" in entries["private-lib"].unresolved_reason
    assert entries["requests"].resolved_version == "2.31.0"
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "tool"\nversion = "0.3.0"\nsource = { git = "https://example.org/tool.git" }\n',
        encoding="utf-8")
    uv = UvLockParser().parse(tmp_path / "uv.lock", "uv.lock").entries
    assert uv[0].resolved_version is None and "git" in uv[0].unresolved_reason


def test_multi_project_repo_keeps_one_dependency_per_service(tmp_path):
    for svc, pins in (("services/api", "flask==3.1.3\npyyaml==5.3.1\n"), ("services/worker", "pyyaml==6.0.3\n")):
        (tmp_path / svc).mkdir(parents=True)
        (tmp_path / svc / "requirements.txt").write_text(pins, encoding="utf-8")
    (tmp_path / "services/api/app.py").write_text("import yaml\nyaml.full_load(b'')\n", encoding="utf-8")
    (tmp_path / "services/worker/w.py").write_text("import yaml\nyaml.safe_load('')\n", encoding="utf-8")
    repo = RepoMapperAgent(workspace=tmp_path / "ws").run(RepoMapperInput(url=str(tmp_path)))
    got = {(d.project, d.name, d.resolved_version) for d in repo.dependencies}
    assert got == {("services/api", "flask", "3.1.3"), ("services/api", "pyyaml", "5.3.1"),
                   ("services/worker", "pyyaml", "6.0.3")}
    api_yaml = next(d for d in repo.dependencies if d.key == "services/api:pyyaml")

    from depscan.agents.usage_locator import UsageLocatorAgent
    from depscan.models import DependencyVulns, UsageLocatorInput, Vulnerability
    v = Vulnerability(id="V", match="affected", match_reason="t")
    out = UsageLocatorAgent().run(UsageLocatorInput(repo_map=repo, vulnerable=[
        DependencyVulns(dependency=api_yaml, vulnerabilities=[v])]))
    assert {s.file for s in out.usages["services/api:pyyaml"].sites} == {"services/api/app.py"}


def test_single_project_in_subfolders_is_not_split(tmp_path):
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements/base.txt").write_text("flask==3.1.3\n", encoding="utf-8")
    (tmp_path / "requirements/dev.txt").write_text("-r base.txt\npytest==9.0.3\n", encoding="utf-8")
    repo = RepoMapperAgent(workspace=tmp_path / "ws").run(RepoMapperInput(url=str(tmp_path)))
    assert {d.key for d in repo.dependencies} == {"flask", "pytest"}


def test_pip_compile_via_marks_transitive_packages(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "flask==3.1.3\n    # via -r requirements.in\n"
        "urllib3==1.26.16\n    # via requests\n"
        "markupsafe==3.0.2\n    # via\n    #   flask\n    #   jinja2\n"
        "requests==2.33.1  # via -r requirements.in\n"
        "idna==3.15\n    # via\n    #   -r requirements.in\n    #   requests\n", encoding="utf-8")
    repo = RepoMapperAgent(workspace=tmp_path / "ws").run(RepoMapperInput(url=str(tmp_path)))
    direct = {d.name: d.direct for d in repo.dependencies}
    assert direct == {"flask": True, "urllib3": False, "markupsafe": False, "requests": True, "idna": True}
    assert next(d for d in repo.dependencies if d.name == "urllib3").required_by == ["requests"]
