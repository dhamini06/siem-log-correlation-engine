"""Tests for the BlueCloud training platform (pages, server, scenario wiring).

These are static/structural tests: no Elasticsearch required. Live data
verification lives in scripts/validate_scenarios.py.
"""

import os
import re
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAINING = os.path.join(REPO_ROOT, "training")
SCENARIOS_DIR = os.path.join(TRAINING, "scenarios")
INSTRUCTOR_GUIDE = os.path.join(REPO_ROOT, "docs", "INSTRUCTOR_GUIDE.md")

SCENARIO_FILES = [
    "scenario-1-brute-force.html",
    "scenario-2-successful-brute-force.html",
    "scenario-3-post-login-execution.html",
    "scenario-4-linux-privilege-escalation.html",
    "scenario-5-multi-event-soc-investigation.html",
]

# Values that must never appear on a student page: they are the answers.
ANSWER_LEAKS = [
    "203.0.113.45", "203.0.113.66", "198.51.100.25", "198.51.100.77",
    "svc_backup", "/bin/bash -i", "net user administrator",
    "Answer Key", "expected finding:",
]


def read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


# -- Files exist ------------------------------------------------------------

def test_landing_page_exists():
    assert os.path.isfile(os.path.join(TRAINING, "index.html"))


def test_instructions_page_exists():
    assert os.path.isfile(os.path.join(TRAINING, "instructions.html"))


def test_assets_exist():
    assert os.path.isfile(os.path.join(TRAINING, "assets", "css", "bluecloud.css"))
    assert os.path.isfile(os.path.join(TRAINING, "assets", "js", "lab.js"))


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_scenario_page_exists(name):
    assert os.path.isfile(os.path.join(SCENARIOS_DIR, name))


def test_exactly_five_scenarios():
    pages = [f for f in os.listdir(SCENARIOS_DIR) if f.endswith(".html")]
    assert len(pages) == 5, pages


# -- Branding and theme -----------------------------------------------------

@pytest.mark.parametrize(
    "page",
    ["index.html", "instructions.html"] + [os.path.join("scenarios", n) for n in SCENARIO_FILES],
)
def test_page_has_bluecloud_branding(page):
    assert "BlueCloud Softech Solutions" in read(os.path.join(TRAINING, page))


def test_official_logo_is_wired_into_every_page():
    """The real BlueCloud logo is displayed, not the BC monogram placeholder."""
    for page in ["index.html", "instructions.html"] + [
        os.path.join("scenarios", n) for n in SCENARIO_FILES
    ]:
        html = read(os.path.join(TRAINING, page))
        assert 'class="brand-mark"' in html, page
        assert 'bluecloud-logo.png' in html, page
        assert 'alt="BlueCloud Softech Solutions"' in html, page
        # the BC placeholder must be gone
        assert ">BC</div>" not in html, f"{page} still shows the BC placeholder"
        assert "LOGO SLOT" not in html, f"{page} still carries the drop-in comment"


def test_logo_path_resolves_from_every_page():
    """Relative src must be correct for both root and nested scenario pages."""
    for page in ["index.html", "instructions.html"]:
        html = read(os.path.join(TRAINING, page))
        assert 'src="assets/img/bluecloud-logo.png"' in html, page
    for name in SCENARIO_FILES:
        html = read(os.path.join(SCENARIOS_DIR, name))
        assert 'src="../assets/img/bluecloud-logo.png"' in html, name


def test_logo_asset_exists_and_is_a_real_image():
    logo = os.path.join(TRAINING, "assets", "img", "bluecloud-logo.png")
    assert os.path.isfile(logo), "official logo asset is missing"
    with open(logo, "rb") as handle:
        head = handle.read(16)
    # JPEG or PNG, whatever the supplied format turns out to be.
    assert head.startswith(b"\xff\xd8\xff") or head.startswith(b"\x89PNG"), "not a JPEG or PNG"


def test_img_brand_mark_css_rule_exists():
    """The prepared rule keeps the header height while allowing free width."""
    css = read(os.path.join(TRAINING, "assets", "css", "bluecloud.css"))
    assert "img.brand-mark" in css
    assert "object-fit" in css


def test_header_layout_unchanged():
    """Only the mark changed: 68px header bar and the wordmark are intact."""
    css = read(os.path.join(TRAINING, "assets", "css", "bluecloud.css"))
    assert "min-height: 68px" in css
    assert "--bc-blue-600" in css and "--bc-orange-500" in css
    for page in ["index.html"] + [os.path.join("scenarios", SCENARIO_FILES[0])]:
        html = read(os.path.join(TRAINING, page))
        assert 'class="brand-name">BlueCloud Softech Solutions<' in html, page
        assert 'class="site-nav"' in html, page


def test_theme_defines_blue_primary_and_orange_accent():
    css = read(os.path.join(TRAINING, "assets", "css", "bluecloud.css"))
    assert "--bc-blue-" in css
    assert "--bc-orange-" in css
    assert re.search(r"--bc-blue-600:\s*#1257c0", css)
    assert re.search(r"--bc-orange-500:\s*#ff7a00", css)
    assert "--ink-900" in css  # dark security neutrals


def test_no_external_dependencies_in_pages():
    """Free and local: no CDN, no web fonts, no third-party scripts."""
    for page in ["index.html", "instructions.html"] + [
        os.path.join("scenarios", n) for n in SCENARIO_FILES
    ]:
        html = read(os.path.join(TRAINING, page))
        assert "cdn." not in html.lower()
        assert "http://" not in html.replace("http://localhost", "").replace(
            "https://www.", ""
        ).replace("https://", "") or "localhost" in html


def test_css_is_dependency_free():
    css = read(os.path.join(TRAINING, "assets", "css", "bluecloud.css"))
    assert "@import" not in css
    assert "url(http" not in css


# -- Student flow -----------------------------------------------------------

def test_landing_has_required_sections():
    html = read(os.path.join(TRAINING, "index.html"))
    assert "Start Investigation" in html
    assert "Open SIEM Dashboard" in html
    assert "Lab Objective" in html
    assert "What you will learn" in html
    assert "Practice Scenarios" in html
    assert "Basic Instructions" in html


def test_landing_links_to_every_scenario():
    html = read(os.path.join(TRAINING, "index.html"))
    for name in SCENARIO_FILES:
        assert name in html, f"landing page does not link {name}"


def test_landing_explains_do_not_guess():
    html = read(os.path.join(TRAINING, "index.html"))
    assert "not to guess" in html.lower()


def test_instructions_cover_all_seven_steps():
    html = read(os.path.join(TRAINING, "instructions.html"))
    for step in ("Step 1", "Step 2", "Steps 3 to 7"):
        assert step in html


def test_instructions_list_the_nine_identifications():
    html = read(os.path.join(TRAINING, "instructions.html"))
    for question in ("What happened?", "When did it happen?", "Which host was affected?",
                     "Which user was involved?", "Which source IP was involved?",
                     "Which events occurred?", "Why did the SIEM generate the alert?",
                     "What evidence supports your conclusion?",
                     "What is the final security finding?"):
        assert question in html, question


def test_instructions_document_the_schema_and_rules():
    html = read(os.path.join(TRAINING, "instructions.html"))
    for field in ("@timestamp", "event_type", "host", "user", "src_ip", "raw_event", "severity"):
        assert field in html, field
    for rule in ("brute_force", "successful_brute_force", "suspicious_process_post_login"):
        assert rule in html, rule


# -- Scenarios --------------------------------------------------------------

@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_scenario_has_required_parts(name):
    html = read(os.path.join(SCENARIOS_DIR, name))
    assert "Incident Brief" in html
    assert "Security objective" in html
    assert "Incident story" in html
    assert "What you know at the start" in html
    assert "Investigation task" in html
    assert "Answer every question" in html
    assert "Skills Practised" in html
    assert "Progressive Hints" in html


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_scenario_has_a_start_action(name):
    html = read(os.path.join(SCENARIOS_DIR, name))
    assert "data-kibana-dash" in html or "data-kibana-link" in html


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_scenario_has_questions_and_notes(name):
    html = read(os.path.join(SCENARIOS_DIR, name))
    assert 'data-question="q1"' in html
    assert html.count('data-question="') >= 5
    assert "Mark scenario complete" in html


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_saved_note_has_the_id_lab_js_looks_up(name):
    """Regression: lab.js uses getElementById('saved-note'), so the element needs
    an id as well as the class the CSS targets. Without it the save confirmation
    silently never appears."""
    html = read(os.path.join(SCENARIOS_DIR, name))
    assert 'id="saved-note"' in html, f"{name}: missing id=\"saved-note\""
    js = read(os.path.join(TRAINING, "assets", "js", "lab.js"))
    match = re.search(r'getElementById\("([^"]+)"\)', js)
    for element_id in re.findall(r'getElementById\("([^"]+)"\)', js):
        if element_id.endswith("note"):
            assert f'id="{element_id}"' in html, f"{name}: id={element_id} not present"


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_scenario_nav_returns_to_home_and_index(name):
    """Functional navigation: a scenario page must offer a way back."""
    html = read(os.path.join(SCENARIOS_DIR, name))
    assert 'href="../index.html"' in html, name
    assert 'href="../instructions.html"' in html, name
    assert "index.html#scenarios" in html, name


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_scenario_tells_student_to_use_kibana(name):
    html = read(os.path.join(SCENARIOS_DIR, name))
    assert "SOC Triage Board" in html


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_scenario_has_difficulty(name):
    html = read(os.path.join(SCENARIOS_DIR, name))
    assert re.search(r"diff diff-(easy|medium|hard)", html)


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_scenario_does_not_leak_answers(name):
    html = read(os.path.join(SCENARIOS_DIR, name))
    for leak in ANSWER_LEAKS:
        assert leak not in html, f"{name} leaks the answer: {leak}"


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_scenario_next_link_chains_correctly(name):
    """Each scenario links to the next one, and the last links back to the guide."""
    html = read(os.path.join(SCENARIOS_DIR, name))
    index = SCENARIO_FILES.index(name)
    if index + 1 < len(SCENARIO_FILES):
        assert SCENARIO_FILES[index + 1] in html
    else:
        assert "../instructions.html" in html


def test_scenario_ids_are_unique_for_progress_tracking():
    ids = set()
    for name in SCENARIO_FILES:
        html = read(os.path.join(SCENARIOS_DIR, name))
        match = re.search(r'data-scenario="([^"]+)"', html)
        assert match, f"{name} has no data-scenario attribute"
        ids.add(match.group(1))
    assert len(ids) == 5


# -- Instructor material ----------------------------------------------------

def test_instructor_guide_exists_with_answer_key():
    assert os.path.isfile(INSTRUCTOR_GUIDE)
    text = read(INSTRUCTOR_GUIDE)
    assert "Answer Key" in text or "INSTRUCTOR USE ONLY" in text


def test_instructor_guide_covers_all_five_scenarios():
    text = read(INSTRUCTOR_GUIDE)
    for title in ("Brute Force Investigation", "Successful Login After Brute Force",
                  "Suspicious Post-Login Process Execution",
                  "Linux Privilege Escalation and Reverse Shell",
                  "Multi-Event SOC Investigation"):
        assert title in text, title


def test_instructor_guide_has_the_evidence_values():
    text = read(INSTRUCTOR_GUIDE)
    for value in ("203.0.113.45", "203.0.113.66", "198.51.100.25", "198.51.100.77",
                  "svc_backup", "07:25:55", "07:28:04", "07:27:40"):
        assert value in text, value


def test_instructor_guide_is_not_served_by_the_training_platform():
    """The answer key lives outside the served directory."""
    assert not os.path.isfile(os.path.join(TRAINING, "INSTRUCTOR_GUIDE.md"))
    assert not os.path.isdir(os.path.join(TRAINING, "docs"))


# -- Server -----------------------------------------------------------------

def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


@pytest.mark.skipif(sys.platform == "win32", reason="server test runs on POSIX-like CI only")
def test_server_serves_the_landing_page():
    port = 8080
    if not _port_free(port):
        pytest.skip("port already in use")
    process = subprocess.Popen(
        [sys.executable, os.path.join(REPO_ROOT, "scripts", "serve_training.py"),
         "--port", str(port)],
        cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    try:
        body = None
        for _ in range(40):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as response:
                    body = response.read().decode("utf-8")
                break
            except Exception:
                time.sleep(0.25)
        assert body is not None, "training platform did not start"
        assert "BlueCloud Softech Solutions" in body
    finally:
        process.terminate()
        process.wait(timeout=10)


def test_server_script_has_no_third_party_imports():
    source = read(os.path.join(REPO_ROOT, "scripts", "serve_training.py"))
    for module in ("flask", "django", "fastapi", "uvicorn", "aiohttp", "tornado"):
        assert module not in source


def test_reset_lab_data_only_targets_lab_indices():
    """The reset must be narrow: two lab indices + the dedup cache, nothing else."""
    import ast

    path = os.path.join(REPO_ROOT, "scripts", "reset_lab_data.py")
    source = read(path)

    # The target list is exactly the two regenerable lab indices.
    assert 'LAB_INDICES = ("normalized-events-*", "security-alerts-*")' in source

    # It must not shell out to docker or otherwise reach outside the ES API.
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "subprocess" not in imported, "reset must not shell out"
    assert "os.system" not in source and "docker" not in source.lower()

    # Every index deletion goes through the narrow LAB_INDICES loop.
    deletes = [n for n in ast.walk(tree)
               if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
               and n.func.attr == "delete"]
    assert deletes, "reset should delete the lab indices"
    for call in deletes:
        index_arg = next((kw.value for kw in call.keywords if kw.arg == "index"), None)
        # index=<loop variable over LAB_INDICES>
        assert isinstance(index_arg, ast.Name), "index must come from the LAB_INDICES loop"

    # Never touches Kibana internals or the raw-data indices.
    for forbidden in (".kibana", "es-data", "kibana-config", "raw-events"):
        assert forbidden not in source, f"reset must not reference {forbidden}"


def test_reset_lab_data_compiles():
    path = os.path.join(REPO_ROOT, "scripts", "reset_lab_data.py")
    result = subprocess.run([sys.executable, "-m", "py_compile", path],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_reset_lab_data_reports_missing_confirmation():
    """Without --yes the script must refuse to delete anything."""
    result = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "scripts", "reset_lab_data.py")],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    # Either it refuses (exit 1) or Elasticsearch is down (exit 1). Both are correct;
    # what must never happen is exit 0 with no confirmation.
    assert result.returncode != 0, result.stdout


class _StrictIndices:
    """Elasticsearch 8 indices double that refuses wildcard deletes.

    Elasticsearch 8 defaults to ``action.destructive_requires_name=true`` and
    rejects ``DELETE /*-pattern`` with
    ``illegal_argument_exception: Wildcard expressions ... are not allowed``.
    A double that behaves this way is what catches a reset that deletes by pattern.
    """

    def __init__(self, existing):
        self.existing = list(existing)
        self.deleted = []
        self.indices = self

    def get(self, index=None, **kwargs):
        import fnmatch
        matched = [n for n in self.existing if fnmatch.fnmatch(n, index)]
        if not matched:
            raise LookupError("index_not_found_exception")
        return {n: {} for n in matched}

    def delete(self, index=None, ignore_unavailable=False, **kwargs):
        if any(ch in (index or "") for ch in "*?"):
            raise RuntimeError(
                "illegal_argument_exception: Wildcard expressions or all indices "
                "are not allowed"
            )
        self.deleted.append(index)
        if index in self.existing:
            self.existing.remove(index)
        return {"acknowledged": True}


def test_reset_lab_data_deletes_concrete_names_not_wildcards():
    """Regression: the reset must resolve patterns before deleting.

    Deleting ``normalized-events-*`` directly fails on Elasticsearch 8, which made
    the script report success while the data was still there.
    """
    sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
    import reset_lab_data

    class _ES:
        def __init__(self):
            self.indices = _StrictIndices([
                "normalized-events-2026-09-26",
                "normalized-events-2026-09-28",
                "security-alerts-2026-09-26",
            ])
            self.es = self
            self.remaining = 99

        def count(self, pattern):
            return self.remaining

    fake = _ES()
    cache = os.path.join(REPO_ROOT, "data", "pytest-reset-cache.json")
    summary = reset_lab_data.reset(es_client=fake, dedup_cache_path=cache)

    assert summary["errors"] == [], summary["errors"]
    assert summary["indices_deleted"] == [
        "normalized-events-2026-09-26",
        "normalized-events-2026-09-28",
        "security-alerts-2026-09-26",
    ]
    # No wildcard ever reached Elasticsearch.
    assert not any("*" in name for name in fake.indices.deleted)


def test_reset_lab_data_reports_counts_afterwards():
    """The summary must expose after-counts so callers can verify the reset."""
    sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
    import reset_lab_data

    class _ES:
        def __init__(self):
            self.indices = _StrictIndices(["normalized-events-2026-09-28",
                                           "security-alerts-2026-09-28"])
            self.es = self

        def count(self, pattern):
            return 0

    summary = reset_lab_data.reset(
        es_client=_ES(),
        dedup_cache_path=os.path.join(REPO_ROOT, "data", "pytest-reset-cache2.json"),
    )
    for key in ("events_before", "alerts_before", "events_after", "alerts_after"):
        assert key in summary, key
    assert summary["indices_deleted"], "nothing was deleted"


# -- Validator --------------------------------------------------------------

def test_validator_script_parses():
    """validate_scenarios.py must be importable-clean (syntax check)."""
    path = os.path.join(REPO_ROOT, "scripts", "validate_scenarios.py")
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", path],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_validator_structural_mode_passes():
    """The page-level half of the validator must pass without Elasticsearch."""
    path = os.path.join(REPO_ROOT, "scripts", "validate_scenarios.py")
    result = subprocess.run(
        [sys.executable, path, "--skip-es"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "checks passed" in result.stdout
