"""Stepwise method: each gate, the conservative rules (unclear -> unknown, never fail) and the verdict rules.

Fixtures are copies of the dead-code / safe-args / unsafe-args / transitive test repos (without their answers) plus
small repos written per test. Trigger specs come from override files, the LLM is a fake: nothing leaves the machine.
"""

import json
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest

from depscan.agents.repo_context import RepoContextAgent
from depscan.agents.repo_mapper import RepoMapperAgent
from depscan.agents.stepwise import StepwiseAgent
from depscan.agents.usage_locator import UsageLocatorAgent
from depscan.codeindex import CodeIndex
from depscan.config import LLMConfig
from depscan.llm.client import LLMClient
from depscan.models import DependencyVulns, ScanResult, UsageLocatorInput, Vulnerability
from depscan.triggers import TriggerStore
from fake_llm import FakeOpenAI

FIX = Path(__file__).parent / "fixtures" / "stepwise"

SPECS = {
    "CVE-2020-14343": """
        package: pyyaml
        plain_summary: Loading an attacker's YAML with the full loader can run code.
        trigger_symbols: [yaml.load, yaml.load_all, yaml.full_load, yaml.full_load_all, yaml.unsafe_load]
        arg_forms:
          - {call: yaml.load, kwarg: Loader, position: 1, dangerous: [FullLoader, UnsafeLoader, Loader],
             safe: [SafeLoader, CSafeLoader, BaseLoader], when_absent: dangerous}
        needs_untrusted_input: true
        untrusted_input: the YAML document
        input_arg: "0"
    """,
    "CVE-2024-35195": """
        package: requests
        plain_summary: After one request without certificate checks, a Session keeps skipping them for that host.
        trigger_symbols: [requests.Session]
        arg_forms:
          - {call: requests.Session, kwarg: verify, dangerous: ["False"], safe: ["True"], when_absent: safe}
        dangerous_condition: a request on the session is made with verify=False
        needs_untrusted_input: false
    """,
    "CVE-2020-25658": """
        package: rsa
        plain_summary: Timing differences in decryption leak the plaintext.
        trigger_symbols: [rsa.decrypt]
        needs_untrusted_input: true
        input_arg: "0"
    """,
    "CVE-2026-45409": """
        package: idna
        plain_summary: Very long names make encoding very slow.
        trigger_symbols: [idna.encode]
        needs_untrusted_input: true
        input_arg: "0"
    """,
    "CVE-2024-5569": """
        package: zipp
        plain_summary: A crafted zip file makes zipp loop forever.
        trigger_symbols: [zipp.Path]
        needs_untrusted_input: true
        input_arg: "0"
    """,
    "CVE-2025-27516": """
        package: jinja2
        plain_summary: A template can escape the sandbox.
        trigger_symbols: [jinja2.sandbox.SandboxedEnvironment]
        needs_untrusted_input: true
        input_arg: "0"
    """,
}
PACKAGE_OF = {"CVE-2020-14343": "pyyaml", "CVE-2024-35195": "requests", "CVE-2020-25658": "rsa",
              "CVE-2026-45409": "idna", "CVE-2024-5569": "zipp", "CVE-2025-27516": "jinja2"}


def vuln(vid: str, kind: str = "standard") -> Vulnerability:
    return Vulnerability(id=vid, kind=kind, summary=f"summary of {vid}", match="affected",
                         match_reason="installed version is in affected range >=0, <99", fixed_version="99.0")


def build(repo: Path, vulns: dict[str, list[Vulnerability]]) -> ScanResult:
    rmap = RepoMapperAgent(repo.parent / "_unused").map(str(repo), repo, repo.name, repo.name, [])
    dvs = [DependencyVulns(dependency=d, vulnerabilities=[v for v in vulns[d.name] if v.kind != "fuzz_crash"],
                           fuzz_crashes=[v for v in vulns[d.name] if v.kind == "fuzz_crash"])
           for d in rmap.dependencies if d.name in vulns]
    located = UsageLocatorAgent().run(UsageLocatorInput(repo_map=rmap, vulnerable=dvs))
    result = ScanResult(created_at=datetime.now(timezone.utc), repo=rmap, vulnerabilities=dvs,
                        usages=located.usages, parse_failures=located.parse_failures)
    result.repo_context = RepoContextAgent(None).run(result)
    return result


def store(tmp_path, specs: dict[str, str]) -> TriggerStore:
    d = tmp_path / "overrides" / "triggers"
    d.mkdir(parents=True, exist_ok=True)
    for vid, text in specs.items():
        (d / f"{vid}.yaml").write_text(textwrap.dedent(text), encoding="utf-8")
    return TriggerStore(tmp_path / "cache", tmp_path / "overrides", offline=True)


def fake_llm(answer="unknown", reason="cannot tell", line=None, log=None):
    """Narrow questions get `answer`; returns (client, fake) so tests can count calls."""
    fake = FakeOpenAI(lambda messages: json.dumps({"answer": answer, "line": line, "reason": reason}))
    return LLMClient(LLMConfig(), client=fake, log_path=log), fake


def check(result, tmp_path, vid, specs=None, llm=None, package=None, max_questions=4):
    specs = SPECS if specs is None else specs
    st = store(tmp_path, {k: v for k, v in specs.items()})
    index = CodeIndex(Path(result.repo.local_path), result.repo.source_files, result.repo_context.app_type)
    package = package or PACKAGE_OF.get(vid)
    dv, v = next((dv, v) for dv in result.vulnerabilities for v in dv.all_vulns()
                 if v.id == vid and (package is None or dv.dependency.name == package))
    return StepwiseAgent(st, index, llm, max_questions=max_questions).run(result, dv, v)


def gates(rec):
    return {g.gate: g for g in rec.gates}


def write_repo(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    return root


# ---------------------------------------------------------------- the test repos

@pytest.fixture(scope="module")
def dead_code():
    return build(FIX / "dead_code", {p: [vuln(v)] for v, p in PACKAGE_OF.items() if p != "requests"})


def test_dead_code_is_ruled_out_in_code(dead_code, tmp_path):
    cases = {"CVE-2020-14343": "never called", "CVE-2026-45409": "never imported",
             "CVE-2020-25658": "if False", "CVE-2024-5569": "always returns"}
    for vid, phrase in cases.items():
        rec = check(dead_code, tmp_path, vid)
        g = gates(rec)
        assert rec.method == "stepwise" and rec.verdict == "likely_not_affected", (vid, rec.reason)
        assert g["present"].result == "pass" and g["reachable"].result == "fail", vid
        assert phrase in g["reachable"].explanation and phrase in rec.reason, (vid, rec.reason)
        assert g["dangerous_form"].skipped and g["attacker_input"].skipped
        assert rec.llm_calls == 0 and not rec.llm_called and rec.spec_source == "human"


def test_feature_flag_is_unknown_never_fail(dead_code, tmp_path):
    rec = check(dead_code, tmp_path, "CVE-2025-27516")
    g = gates(rec)
    assert rec.verdict == "uncertain" and not any(x.result == "fail" for x in rec.gates)
    assert g["reachable"].result == "unknown" and "ENABLE_CUSTOM_TEMPLATES" in g["reachable"].explanation
    assert rec.reason.startswith("Needs review") and "can run" in rec.reason


def test_safe_arguments_are_ruled_out_in_code(tmp_path):
    result = build(FIX / "safe_args", {"pyyaml": [vuln("CVE-2020-14343")], "requests": [vuln("CVE-2024-35195")]})
    rec = check(result, tmp_path, "CVE-2020-14343")
    assert rec.verdict == "likely_not_affected" and gates(rec)["reachable"].result == "pass"
    assert gates(rec)["dangerous_form"].result == "fail" and "SafeLoader" in gates(rec)["dangerous_form"].explanation
    rec = check(result, tmp_path, "CVE-2024-35195")
    assert rec.verdict == "likely_not_affected" and "verify=True" in gates(rec)["dangerous_form"].explanation
    assert rec.llm_calls == 0


def test_unsafe_arguments_are_affected(tmp_path):
    result = build(FIX / "unsafe_args", {"pyyaml": [vuln("CVE-2020-14343")], "requests": [vuln("CVE-2024-35195")]})
    rec = check(result, tmp_path, "CVE-2020-14343")
    g = gates(rec)
    assert rec.verdict == "likely_affected" and all(x.result == "pass" for x in rec.gates)
    assert "Loader=yaml.FullLoader" in g["dangerous_form"].explanation and g["present"].explanation.startswith("yaml.load")
    assert "request.data" in g["attacker_input"].explanation and g["attacker_input"].decided_by == "code"
    rec = check(result, tmp_path, "CVE-2024-35195")
    g = gates(rec)
    assert rec.verdict == "likely_affected" and "verify=False" in g["dangerous_form"].explanation
    assert g["attacker_input"].skipped and g["attacker_input"].result == "pass"      # not needed for this one
    assert "warm_up" in g["reachable"].explanation and rec.llm_calls == 0


def test_transitive_parent_triggers(tmp_path):
    result = build(FIX / "transitive", {"urllib3": [vuln("CVE-A"), vuln("CVE-B"), vuln("CVE-C")],
                                        "certifi": [vuln("CVE-D")]})
    specs = {
        "CVE-A": """
            package: urllib3
            plain_summary: A malicious server can exhaust memory with chained compression.
            trigger_symbols: [urllib3.response.HTTPResponse.read]
            parent_triggers: [{parent: requests, reachable: true, symbols: [requests.get, requests.Session.request]}]
            needs_untrusted_input: true
            untrusted_input: the server the request goes to
        """,
        "CVE-B": """
            package: urllib3
            plain_summary: Redirects handled by urllib3 keep a header.
            trigger_symbols: [urllib3.PoolManager.urlopen]
            parent_triggers: [{parent: requests, reachable: false, condition: requests follows redirects itself}]
        """,
        "CVE-C": """
            package: urllib3
            plain_summary: Something in urllib3.
            trigger_symbols: [urllib3.util.parse_url]
        """,
        "CVE-D": """
            package: certifi
            plain_summary: Removed root certificates are still trusted.
            trigger_symbols: [certifi.where]
            parent_triggers: [{parent: requests, reachable: true, symbols: [requests.get]}]
            needs_untrusted_input: false
        """,
    }
    rec = check(result, tmp_path, "CVE-A", specs, package="urllib3")
    g = gates(rec)
    assert rec.verdict == "likely_affected", rec.reason
    assert "through requests" in g["present"].explanation and "request.form" in g["attacker_input"].explanation
    rec = check(result, tmp_path, "CVE-B", specs, package="urllib3")
    assert rec.verdict == "likely_not_affected" and "requests follows redirects itself" in rec.reason
    rec = check(result, tmp_path, "CVE-C", specs, package="urllib3")         # the spec says nothing about requests
    assert rec.verdict == "uncertain" and gates(rec)["present"].result == "unknown"
    rec = check(result, tmp_path, "CVE-D", specs, package="certifi")
    assert rec.verdict == "likely_affected" and gates(rec)["attacker_input"].skipped


# ---------------------------------------------------------------- conservative behaviour on small repos

WEB = {
    "requirements.txt": "flask==3.1.3\npyyaml==5.3.1\n",
    "app/__init__.py": """
        from flask import Flask


        def create_app():
            app = Flask(__name__)
            from app.routes import bp
            app.register_blueprint(bp)
            return app
    """,
}


def yaml_repo(tmp_path, files: dict[str, str]) -> ScanResult:
    root = write_repo(tmp_path / "repo", {**WEB, **files})
    return build(root, {"pyyaml": [vuln("CVE-2020-14343")]})


def test_computed_getattr_keeps_unreferenced_function_unknown(tmp_path):
    result = yaml_repo(tmp_path, {"app/routes.py": """
        import yaml
        from flask import Blueprint, request

        from app import handlers

        bp = Blueprint("x", __name__)


        @bp.post("/run")
        def run():
            return getattr(handlers, request.args["op"])(request.data)
    """, "app/handlers.py": """
        import yaml


        def legacy(body):
            return yaml.full_load(body)
    """})
    rec = check(result, tmp_path, "CVE-2020-14343")
    assert gates(rec)["reachable"].result == "unknown" and "computed name" in gates(rec)["reachable"].explanation
    assert rec.verdict == "uncertain"


def test_function_name_in_a_string_is_unknown(tmp_path):
    result = yaml_repo(tmp_path, {"app/routes.py": """
        import yaml
        from flask import Blueprint

        bp = Blueprint("x", __name__)
        HOOKS = ["legacy"]


        def legacy(body):
            return yaml.full_load(body)
    """})
    rec = check(result, tmp_path, "CVE-2020-14343")
    assert gates(rec)["reachable"].result == "unknown" and "as a string" in gates(rec)["reachable"].explanation


def test_env_condition_is_unknown_with_flag_name(tmp_path):
    result = yaml_repo(tmp_path, {"app/routes.py": """
        import os

        import yaml
        from flask import Blueprint, request

        bp = Blueprint("x", __name__)


        @bp.post("/import")
        def import_settings():
            if os.environ.get("ALLOW_YAML_IMPORT") == "1":
                return yaml.full_load(request.data)
            return {}
    """})
    rec = check(result, tmp_path, "CVE-2020-14343")
    g = gates(rec)
    assert g["reachable"].result == "unknown" and "ALLOW_YAML_IMPORT" in g["reachable"].explanation
    assert rec.verdict == "uncertain"


def test_import_module_with_variable_keeps_unimported_module_unknown(tmp_path):
    result = yaml_repo(tmp_path, {"app/routes.py": """
        import importlib

        from flask import Blueprint, request

        bp = Blueprint("x", __name__)


        @bp.post("/plugin")
        def plugin():
            return importlib.import_module(request.args["name"]).run(request.data)
    """, "app/plugins/yamlish.py": """
        import yaml


        def run(body):
            return yaml.full_load(body)
    """})
    rec = check(result, tmp_path, "CVE-2020-14343")
    assert gates(rec)["present"].result == "unknown" or gates(rec)["reachable"].result == "unknown"
    assert rec.verdict == "uncertain"


def test_only_used_in_tests_fails(tmp_path):
    result = yaml_repo(tmp_path, {"app/routes.py": """
        from flask import Blueprint

        bp = Blueprint("x", __name__)
    """, "app/fixtures.py": """
        import yaml


        def load_fixture(path):
            with open(path) as fh:
                return yaml.full_load(fh)
    """, "tests/test_data.py": """
        from app.fixtures import load_fixture


        def test_fixture():
            assert load_fixture("tests/data.yaml")
    """})
    rec = check(result, tmp_path, "CVE-2020-14343")
    assert rec.verdict == "likely_not_affected" and "only" in rec.reason and "tests" in rec.reason


def test_method_of_framework_class_is_unknown(tmp_path):
    result = yaml_repo(tmp_path, {"app/routes.py": """
        import yaml
        from flask import Blueprint, request
        from flask.views import MethodView

        bp = Blueprint("x", __name__)


        class Import(MethodView):
            def post(self):
                return yaml.full_load(request.data)
    """})
    rec = check(result, tmp_path, "CVE-2020-14343")
    assert rec.verdict != "likely_not_affected" and gates(rec)["reachable"].result != "fail"


def test_bundled_file_input_fails_and_request_input_passes(tmp_path):
    result = yaml_repo(tmp_path, {"app/routes.py": """
        from pathlib import Path

        import yaml
        from flask import Blueprint

        bp = Blueprint("x", __name__)
        DEFAULTS = yaml.full_load(Path(__file__).with_name("defaults.yaml").read_text())
    """})
    rec = check(result, tmp_path, "CVE-2020-14343")
    g = gates(rec)
    assert g["reachable"].result == "pass" and g["attacker_input"].result == "fail"
    assert "fixed in the code" in g["attacker_input"].explanation and rec.verdict == "likely_not_affected"


def test_partial_input_is_asked_once_and_llm_answer_is_recorded(tmp_path):
    files = {"app/routes.py": """
        import yaml
        from flask import Blueprint, request

        bp = Blueprint("x", __name__)


        @bp.get("/doc/<name>")
        def doc(name):
            return yaml.full_load(f"title: {name}")
    """}
    result = yaml_repo(tmp_path, files)
    llm, fake = fake_llm("unknown")
    rec = check(result, tmp_path, "CVE-2020-14343", llm=llm)
    g = gates(rec)
    assert len(fake.calls) == 1 and rec.llm_calls == 1 and rec.llm_called
    assert g["attacker_input"].decided_by == "llm" and g["attacker_input"].result == "unknown"
    assert rec.verdict == "uncertain"
    prompt = fake.calls[0]["messages"][1]["content"]
    assert "yaml.full_load" in prompt and "title: {name}" in prompt and "doc(name)" in prompt

    llm, fake = fake_llm("no", "only a fixed key with a URL segment", line="app/routes.py:9")
    rec = check(result, tmp_path, "CVE-2020-14343", llm=llm)
    assert rec.verdict == "likely_not_affected" and gates(rec)["attacker_input"].decided_by == "llm"
    assert rec.confidence < 0.9                                    # decided by the LLM, not by code


def test_dangerous_condition_questions_respect_the_limit(tmp_path):
    result = yaml_repo(tmp_path, {"app/routes.py": """
        import yaml
        from flask import Blueprint, request

        bp = Blueprint("x", __name__)


        @bp.post("/a")
        def a():
            return yaml.full_load(request.data)


        @bp.post("/b")
        def b():
            return yaml.full_load(request.form["x"])


        @bp.post("/c")
        def c():
            return yaml.full_load(request.args["y"])
    """})
    spec = {"CVE-2020-14343": """
        package: pyyaml
        plain_summary: x
        trigger_symbols: [yaml.full_load]
        dangerous_condition: the document uses a python/object tag
    """}
    llm, fake = fake_llm("unknown")
    rec = check(result, tmp_path, "CVE-2020-14343", spec, llm=llm, max_questions=2)
    assert len(fake.calls) == 2 and rec.verdict == "uncertain"
    llm, fake = fake_llm("yes", "the body is loaded as is")
    rec = check(result, tmp_path, "CVE-2020-14343", spec, llm=llm)
    assert rec.verdict == "likely_affected" and len(fake.calls) == 1        # stops at the first affected use


def test_fuzz_crash_needs_review_without_llm(tmp_path):
    result = yaml_repo(tmp_path, {"app/routes.py": "import yaml\nyaml.full_load('a: 1')\n"})
    result.vulnerabilities[0].fuzz_crashes.append(vuln("OSV-2020-1", kind="fuzz_crash"))
    llm, fake = fake_llm("yes")
    rec = check(result, tmp_path, "OSV-2020-1", llm=llm, package="pyyaml")
    assert rec.verdict == "uncertain" and rec.llm_calls == 0 and not fake.calls


def test_package_never_imported_fails_unless_named_in_deployment_files(tmp_path):
    root = write_repo(tmp_path / "repo", {**WEB, "requirements.txt": "flask==3.1.3\nrsa==4.6\n",
                                          "app/routes.py": "from flask import Blueprint\nbp = Blueprint('x', __name__)\n"})
    result = build(root, {"rsa": [vuln("CVE-2020-25658")]})
    rec = check(result, tmp_path, "CVE-2020-25658")
    assert rec.verdict == "likely_not_affected" and "never imported" in gates(rec)["present"].explanation
    (root / "Procfile").write_text("keys: pyrsa-keygen 2048 && rsa-tool\nweb: gunicorn wsgi:app rsa\n")
    rec = check(result, tmp_path, "CVE-2020-25658")
    assert rec.verdict == "uncertain" and gates(rec)["present"].result == "unknown"


def test_without_any_spec_reachability_still_rules_out_dead_code(dead_code, tmp_path):
    rec = check(dead_code, tmp_path, "CVE-2026-45409", specs={})
    g = gates(rec)
    assert g["trigger_spec"].result == "unknown" and g["present"].result == "unknown"
    assert rec.verdict == "likely_not_affected" and g["reachable"].result == "fail"
    rec = check(dead_code, tmp_path, "CVE-2025-27516", specs={})
    assert rec.verdict == "uncertain"


def test_other_method_of_a_trigger_class_is_unknown_not_fail(tmp_path):
    result = build(FIX / "safe_args", {"requests": [vuln("CVE-X")]})
    spec = {"CVE-X": """
        package: requests
        plain_summary: x
        trigger_symbols: [requests.Session.request]
    """}
    rec = check(result, tmp_path, "CVE-X", spec, package="requests")
    g = gates(rec)
    assert g["present"].result == "unknown" and "related to the vulnerable one" in g["present"].explanation
    assert rec.verdict == "uncertain"


def test_public_names_and_subclasses_match_triggers():
    from depscan.agents.stepwise import public_form, subclass_like, trigger_match
    assert public_form("rsa.pkcs1.decrypt") == "rsa.decrypt"
    assert trigger_match("rsa.decrypt", "rsa.pkcs1.decrypt")                      # re-exported at the top level
    assert trigger_match("jinja2.sandbox.SandboxedEnvironment.from_string", "jinja2.SandboxedEnvironment")
    assert not trigger_match("yaml.safe_load", "yaml.full_load") and not trigger_match("rsa.encrypt", "rsa.pkcs1.decrypt")
    assert subclass_like("jinja2.sandbox.SandboxedEnvironment.from_string", "jinja2.Environment")
    assert not subclass_like("jinja2.Environment.from_string", "jinja2.Environment")


def test_likely_subclass_gives_needs_review_not_fail(tmp_path):
    result = build(FIX / "dead_code", {"jinja2": [vuln("CVE-Y")]})
    spec = {"CVE-Y": """
        package: jinja2
        plain_summary: x
        trigger_symbols: [jinja2.Environment, jinja2.Template]
    """}
    rec = check(result, tmp_path, "CVE-Y", spec, package="jinja2")
    assert gates(rec)["present"].result == "unknown" and rec.verdict == "uncertain"


def test_spec_names_are_normalized_and_submodule_siblings_are_unknown():
    from depscan.agents.stepwise import normalize_symbols, same_submodule
    assert normalize_symbols(["Pillow.Image.open", "Pillow.PIL.Image.save", "PIL.ImageFile"], "pillow", ["PIL"]) == [
        "PIL.Image.open", "PIL.Image.save", "PIL.ImageFile"]
    assert same_submodule("cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates",
                          "cryptography.hazmat.primitives.serialization.pkcs12.PKCS12_load")
    assert not same_submodule("yaml.safe_load", "yaml.full_load")


def test_parent_route_question_says_the_parent_uses_the_package(tmp_path):
    result = build(FIX / "transitive", {"urllib3": [vuln("CVE-A")]})
    spec = {"CVE-A": """
        package: urllib3
        plain_summary: x
        trigger_symbols: [urllib3.response.HTTPResponse.read]
        dangerous_condition: the response is compressed many times
        parent_triggers: [{parent: requests, reachable: true, symbols: [requests.get]}]
    """}
    llm, fake = fake_llm("unknown")
    check(result, tmp_path, "CVE-A", spec, llm=llm, package="urllib3")
    prompt = fake.calls[0]["messages"][1]["content"]
    assert ("The marked call uses requests, which uses urllib3 internally. The vulnerable code runs inside urllib3 "
            "when requests does this: the operation described above.") in prompt
    assert prompt.startswith("Vulnerability in urllib3: x\nTechnical condition: the response is compressed")


def test_four_statuses():
    from depscan.agents.stepwise import gate, status_of
    ok = [gate(n, "pass", "x") for n in ("version_in_range", "trigger_spec", "present")]
    assert status_of(ok + [gate("reachable", "pass", "x"), gate("dangerous_form", "pass", "x", by="llm")]) == "affected"
    assert status_of(ok + [gate("reachable", "fail", "never called")]) == "not_affected"
    assert status_of(ok + [gate("reachable", "pass", "x"), gate("dangerous_form", "fail", "no", by="llm")]) \
        == "probably_not_affected"
    assert status_of(ok + [gate("reachable", "fail", "x"), gate("dangerous_form", "fail", "no", by="llm")]) \
        == "not_affected"                                           # a code fail proves it, whatever the LLM said
    assert status_of(ok + [gate("reachable", "unknown", "flag")]) == "needs_review"


def test_llm_no_gives_probably_not_affected(tmp_path):
    result = yaml_repo(tmp_path, {"app/routes.py": """
        import yaml
        from flask import Blueprint, request

        bp = Blueprint("x", __name__)


        @bp.get("/doc/<name>")
        def doc(name):
            return yaml.full_load(f"title: {name}")
    """})
    llm, _ = fake_llm("no", "only a fixed key", line="app/routes.py:9")
    rec = check(result, tmp_path, "CVE-2020-14343", llm=llm)
    assert rec.status == "probably_not_affected" and rec.verdict == "likely_not_affected"
    assert rec.reason.startswith("Probably not affected (AI judgement")
    rec = check(dead_code_result(), tmp_path, "CVE-2020-14343")
    assert rec.status == "not_affected"


def dead_code_result():
    return build(FIX / "dead_code", {"pyyaml": [vuln("CVE-2020-14343")]})


def test_via_sentence_per_site_type():
    from depscan.agents.stepwise import Cand, StepwiseAgent
    from depscan.models import NativeFeature, ParentTrigger, TriggerSpec, UsageSite
    site = UsageSite(id="U1", package="requests", file="a.py", line=1, kind="call", symbol="requests.get")
    spec = TriggerSpec(vuln_id="X", package="pillow", plain_summary="s",
                       native_feature=NativeFeature(library="libwebp", description="decoding WebP images"))
    assert StepwiseAgent.via(Cand(site, "direct"), spec, "pyyaml") == ""
    assert StepwiseAgent.via(Cand(site, "parent", ParentTrigger(parent="requests", condition="it follows a redirect")),
                             spec, "urllib3") == ("The marked call uses requests, which uses urllib3 internally. The "
                                                  "vulnerable code runs inside urllib3 when requests does this: it "
                                                  "follows a redirect.")
    assert StepwiseAgent.via(Cand(site, "native"), spec, "pillow") == (
        "The marked call uses pillow, which runs its bundled native library libwebp when decoding WebP images.")


def test_no_without_a_shown_line_is_rejected_and_logged(tmp_path):
    result = yaml_repo(tmp_path, {"app/routes.py": """
        import yaml
        from flask import Blueprint, request

        bp = Blueprint("x", __name__)


        @bp.get("/doc/<name>")
        def doc(name):
            return yaml.full_load(f"title: {name}")
    """})
    log = tmp_path / "llm.jsonl"
    for line in (None, "app/routes.py:99", "app/other.py:9"):      # missing, outside the code shown, other file
        llm, _ = fake_llm("no", "the input is safe", line=line, log=log)
        rec = check(result, tmp_path, "CVE-2020-14343", llm=llm)
        g = gates(rec)["attacker_input"]
        assert g.result == "unknown" and "did not point to a shown line" in g.explanation, line
        assert rec.status == "needs_review" and any(n.startswith("rejected_no") for n in rec.notes)
    entries = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines()]
    assert sum(1 for e in entries if e.get("rejected_no")) == 3
    llm, _ = fake_llm("no", "constant key", line="routes.py:9", log=log)   # short path of a shown file is fine
    assert check(result, tmp_path, "CVE-2020-14343", llm=llm).status == "probably_not_affected"


# ---------------------------------------------------------------- after held-out set 1 (made-up package names)

FAKE_WEB = {**WEB, "requirements.txt": "flask==3.1.3\nquuxarc==2.0.0\nzorbakit==1.0.0\n"}


def fake_repo(tmp_path, routes: str, package: str = "quuxarc") -> ScanResult:
    root = write_repo(tmp_path / "repo", {**FAKE_WEB, "app/routes.py": routes})
    return build(root, {package: [vuln("CVE-F")]})


ARCHIVE_ROUTE = """
    import quuxarc
    from flask import Blueprint, request

    bp = Blueprint("x", __name__)


    @bp.post("/archive")
    def archive():
        arc = quuxarc.QuuxFile(request.files["f"].stream, mode="r")
        names = arc.namelist()
        arc.extractall()
        return {"names": names}
"""


def test_class_call_counts_as_init_or_new(tmp_path):
    from depscan.agents.stepwise import trigger_match
    assert trigger_match("quuxarc.QuuxFile", "quuxarc.QuuxFile.__init__")
    assert trigger_match("quuxarc.QuuxFile", "quuxarc.archive.QuuxFile.__new__")
    assert not trigger_match("quuxarc.QuuxFile.namelist", "quuxarc.QuuxFile.__init__")
    result = fake_repo(tmp_path, ARCHIVE_ROUTE)
    spec = {"CVE-F": """
        package: quuxarc
        plain_summary: A crafted header makes opening an archive very slow.
        trigger_symbols: [quuxarc.QuuxFile.__init__]
        needs_untrusted_input: true
        input_arg: "0"
    """}
    rec = check(result, tmp_path, "CVE-F", spec, package="quuxarc")
    g = gates(rec)
    assert g["present"].result == "pass" and "quuxarc.QuuxFile" in g["present"].explanation
    assert g["attacker_input"].result == "pass" and rec.verdict == "likely_affected"


@pytest.mark.parametrize("spec_text", [
    """
        package: quuxarc
        plain_summary: The bundled codec overflows.
        trigger_symbols: []
        native_feature: {library: libquux, wrapper_symbols: [], description: bundled libquux}
    """,
    """
        package: quuxarc
        plain_summary: x
        trigger_symbols: ["quuxarc.QuuxFile.get_sig, "]
    """,
    """
        package: quuxarc
        plain_summary: x
        trigger_symbols: [quuxarc.Other]
        parent_triggers: []
        native_feature: {library: libquux, wrapper_symbols: ["quuxarc.(decode"], description: x}
    """,
], ids=["empty-lists", "malformed-trigger", "malformed-wrapper"])
def test_empty_or_malformed_trigger_lists_never_fail(tmp_path, spec_text):
    result = fake_repo(tmp_path, ARCHIVE_ROUTE)
    rec = check(result, tmp_path, "CVE-F", {"CVE-F": spec_text}, package="quuxarc")
    assert gates(rec)["present"].result != "fail"
    assert rec.status not in ("not_affected", "probably_not_affected")


def test_value_listed_as_both_safe_and_dangerous_is_unknown(tmp_path):
    result = fake_repo(tmp_path, ARCHIVE_ROUTE)
    spec = {"CVE-F": """
        package: quuxarc
        plain_summary: x
        trigger_symbols: [quuxarc.QuuxFile]
        arg_forms:
          - {call: quuxarc.QuuxFile, kwarg: mode, dangerous: [r], safe: [r], when_absent: unknown}
        needs_untrusted_input: false
    """}
    rec = check(result, tmp_path, "CVE-F", spec, package="quuxarc")
    g = gates(rec)
    assert g["dangerous_form"].result == "unknown" and rec.status == "needs_review"
    agent_form = StepwiseAgent.eval_form
    import ast as _ast
    call = _ast.parse("quuxarc.QuuxFile(x, mode='r')").body[0].value
    from depscan.models import ArgForm
    form = ArgForm(call="quuxarc.QuuxFile", kwarg="mode", dangerous=["r"], safe=["r"], when_absent="unknown")
    index = CodeIndex(Path(result.repo.local_path), result.repo.source_files, result.repo_context.app_type)
    outcome, seen = agent_form(StepwiseAgent(None, index), form, call, index.modules["app/routes.py"])
    assert outcome == "unknown" and "both safe and dangerous" in seen


def test_call_without_arguments_is_not_fixed_input(tmp_path):
    result = fake_repo(tmp_path, ARCHIVE_ROUTE)
    spec = {"CVE-F": """
        package: quuxarc
        plain_summary: Extracting writes outside the target folder.
        trigger_symbols: [quuxarc.QuuxFile.extractall]
        needs_untrusted_input: true
    """}
    rec = check(result, tmp_path, "CVE-F", spec, package="quuxarc")
    g = gates(rec)
    assert g["present"].result == "pass" and g["attacker_input"].result == "unknown"
    assert rec.status == "needs_review"


def test_named_input_argument_missing_is_not_fixed_input(tmp_path):
    result = fake_repo(tmp_path, ARCHIVE_ROUTE)
    spec = {"CVE-F": """
        package: quuxarc
        plain_summary: x
        trigger_symbols: [quuxarc.QuuxFile]
        needs_untrusted_input: true
        input_arg: password
    """}
    rec = check(result, tmp_path, "CVE-F", spec, package="quuxarc")
    assert gates(rec)["attacker_input"].result != "fail"


def test_import_name_with_other_casing_is_found(tmp_path):
    from depscan.import_names import match_case
    assert match_case(["zorbakit"], "name_heuristic", {"zorbaKit", "flask"}) == (["zorbaKit"], "name_heuristic_case")
    assert match_case(["jwt"], "builtin_table", {"JWT"}) == (["jwt"], "builtin_table")
    result = fake_repo(tmp_path, """
        from flask import Blueprint, request
        from zorbaKit.fonts import Face

        bp = Blueprint("x", __name__)


        @bp.post("/font")
        def font():
            return {"name": Face(request.data).family}
    """, package="zorbakit")
    usage = next(u for u in result.usages.values() if u.package == "zorbakit")
    assert usage.import_names == ["zorbaKit"] and usage.import_name_source == "name_heuristic_case"
    assert any(s.kind == "call" and s.symbol == "zorbaKit.fonts.Face" for s in usage.sites)
    spec = {"CVE-F": """
        package: zorbakit
        plain_summary: x
        trigger_symbols: [zorbakit.fonts.Face]
        needs_untrusted_input: true
        input_arg: "0"
    """}
    rec = check(result, tmp_path, "CVE-F", spec, package="zorbakit")
    assert gates(rec)["present"].result == "pass" and rec.verdict == "likely_affected"
