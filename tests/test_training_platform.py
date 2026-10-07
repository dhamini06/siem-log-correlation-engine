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


def test_scenarios_page_exists():
    assert os.path.isfile(os.path.join(TRAINING, "scenarios.html"))


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
    ["index.html", "instructions.html", "scenarios.html"]
    + [os.path.join("scenarios", n) for n in SCENARIO_FILES],
)
def test_page_has_bluecloud_branding(page):
    assert "BlueCloud Softech Solutions" in read(os.path.join(TRAINING, page))


def test_official_logo_is_wired_into_every_page():
    """The real BlueCloud logo is displayed, not the BC monogram placeholder."""
    for page in ["index.html", "instructions.html", "scenarios.html"] + [
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
    """The header keeps an explicit bar height and the wordmark is intact.

    Phase 2 retargeted the bar from 68px to 60px as part of the type scale, so
    the assertion follows the new value rather than being dropped: a regression
    back to an implicit height would still fail here.
    """
    css = read(os.path.join(TRAINING, "assets", "css", "bluecloud.css"))
    assert "min-height: 60px" in css
    assert "--brand-blue:" in css and "--brand-orange:" in css
    for page in ["index.html"] + [os.path.join("scenarios", SCENARIO_FILES[0])]:
        html = read(os.path.join(TRAINING, page))
        assert 'class="brand-name">BlueCloud Softech Solutions<' in html, page
        assert 'class="site-nav"' in html, page


def test_theme_defines_blue_primary_and_orange_accent():
    """Blue primary, orange accent, dark security neutrals.

    Phase 2 renamed the scale to --brand-* / --surface-*; the palette values
    themselves did not move, so the hexes are still pinned here.
    """
    css = read(os.path.join(TRAINING, "assets", "css", "bluecloud.css"))
    assert "--brand-blue-" in css
    assert "--brand-orange-" in css
    assert re.search(r"--brand-blue:\s*#1257c0", css)
    assert re.search(r"--brand-orange:\s*#ff7a00", css)
    assert "--surface-inverse:" in css  # dark security neutrals


def test_colour_literals_live_only_in_the_token_block():
    """Phase 2: no raw colour outside :root.

    Every hex, rgb() and rgba() value belongs in the token declaration block, so
    a colour change is a one-line change and the palette cannot drift into
    near-duplicates spread across the file. Named colours used as literal CSS
    keywords (e.g. `border: 1px solid transparent`) are not colours and are
    not covered by this check.
    """
    css = read(os.path.join(TRAINING, "assets", "css", "bluecloud.css"))
    body = css[css.index("}") + 1:]  # everything after the :root block
    literals = re.findall(r"#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)", body)
    assert not literals, "colour literals outside the token block: %r" % literals[:8]
    root = css[:css.index("}") + 1]
    assert re.search(r"#[0-9a-fA-F]{6}\b", root), "the token block should hold the palette"


def test_spacing_and_type_use_only_the_declared_scales():
    """Phase 2: six spacing steps, seven type steps, nothing ad hoc."""
    css = read(os.path.join(TRAINING, "assets", "css", "bluecloud.css"))
    root = css[css.index(":root"):css.index("}") + 1]
    for step in ("--s-1", "--s-2", "--s-3", "--s-4", "--s-5", "--s-6"):
        assert re.search(re.escape(step) + r":\s*\d+px", root), step
    for size in ("--fs-xs", "--fs-sm", "--fs-base", "--fs-md",
                 "--fs-lg", "--fs-xl", "--fs-2xl"):
        assert re.search(re.escape(size) + r":\s*\d+px", root), size
    # no other rem-based spacing or font-size may leak in
    body = css[css.index("}") + 1:]
    stray_fs = re.findall(r"font-size:\s*([\d.]+rem)", body)
    assert not stray_fs, "font sizes must come from the --fs-* scale: %r" % stray_fs[:8]
    stray_mp = re.findall(r"margin[^:]*:\s*[\d.]+rem", body)
    assert not stray_mp, "margins must come from the --s-* scale: %r" % stray_mp[:8]


def test_light_surface_text_never_uses_the_raw_orange():
    """Phase 2: orange text on a light background needs the ink token.

    #d96300 measures 3.3-3.7:1 on white and on the light section tints, so any
    orange label on a light surface uses --brand-orange-ink (6.8:1) instead.
    Measured in a browser; the guard stops the raw orange creeping back in.
    """
    css = read(os.path.join(TRAINING, "assets", "css", "bluecloud.css"))
    assert re.search(r"--brand-orange-ink:\s*#8a3d00", css)
    body = css[css.index("}") + 1:]
    # `border-color:` and `background-color:` also contain the substring
    # "color:", so the negative lookbehind is required to match a real
    # foreground declaration.
    pattern = r"(?<![\w-])color:\s*var\(--brand-orange-deep\)"
    offenders = [i + 1 for i, line in enumerate(body.split("\n"))
                 if re.search(pattern, line)]
    assert not offenders, (
        "orange-deep used as text on line(s) %r; use --brand-orange-ink" % offenders)


def test_dark_section_link_rule_does_not_capture_buttons():
    """`.section-dark a` outranks `.btn-primary`, which painted light blue text
    onto a filled orange button at 1.43:1. The exclusion is load-bearing."""
    css = read(os.path.join(TRAINING, "assets", "css", "bluecloud.css"))
    assert re.search(r"\.section-dark a:not\(\.btn\)", css), (
        "the :not(.btn) guard is missing; dark-section links would override "
        "button foreground colours")
    assert not re.search(r"(?m)^\.section-dark a\s*\{", css)


def test_muted_text_clears_wcag_aa_on_light_surfaces():
    """--text-muted is used for labels and hints, so it must clear 4.5:1."""
    css = read(os.path.join(TRAINING, "assets", "css", "bluecloud.css"))
    m = re.search(r"--text-muted:\s*(#[0-9a-fA-F]{6})", css)
    assert m, "no --text-muted token"

    def lum(hexv):
        ch = [int(hexv[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        f = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in ch]
        return 0.2126 * f[0] + 0.7152 * f[1] + 0.0722 * f[2]

    for bg in ("#ffffff", "#f6f8fc", "#f1f5fb"):
        l1, l2 = sorted([lum(m.group(1)), lum(bg)], reverse=True)
        assert (l1 + 0.05) / (l2 + 0.05) >= 4.5, (
            "--text-muted is %.2f:1 on %s, needs 4.5:1"
            % ((l1 + 0.05) / (l2 + 0.05), bg))


def test_only_two_radii_and_one_shadow_level():
    """Phase 2: restrained shape and elevation.

    Pill radii are allowed, but only for status/difficulty chips and the
    progress track. Ordinary containers must use one of the two radii, and the
    single shadow level is reserved for the sticky header.
    """
    css = read(os.path.join(TRAINING, "assets", "css", "bluecloud.css"))
    body = css[css.index("}") + 1:]
    radii = {r.strip() for r in re.findall(r"border-radius:\s*([^;]+);", body)}
    allowed = {
        "var(--radius-sm)",   # inputs, inline code, small panels
        "var(--radius)",      # cards, tables, buttons, callouts
        "var(--pill)",        # status / difficulty chips, progress track
        "50%",                # circular step and tick counters
        "0",                  # deliberately unboxed figures
        # the joined hint group: only its outer two corners are rounded
        "var(--radius) var(--radius) 0 0",
        "0 0 var(--radius) var(--radius)",
    }
    stray = radii - allowed
    assert not stray, "unexpected border-radius values: %r" % sorted(stray)
    # the card itself must not carry a shadow any more
    card = re.search(r"\.card\s*\{([^}]*)\}", body)
    assert card and "box-shadow" not in card.group(1), ".card should not be shadowed"


def test_no_external_dependencies_in_pages():
    """Free and local: no CDN, no web fonts, no third-party scripts."""
    for page in ["index.html", "instructions.html", "scenarios.html"] + [
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

def test_home_is_a_compact_student_dashboard():
    """The home page is a dashboard, not a course page.

    It keeps the lab framing, the progress panel and the SOC entry point, and
    nothing else. The long-form material lives on instructions.html and the
    scenario cards on scenarios.html.
    """
    html = read(os.path.join(TRAINING, "index.html"))
    assert "SIEM Log Correlation Engine" in html          # the lab still names itself
    assert "Open SOC Dashboard" in html
    assert 'id="my-progress"' in html
    assert 'id="soc-operations"' in html
    # the course sections that used to live here have moved
    for moved in ("What you will learn", "Practice Scenarios",
                  "Basic Instructions", "Lab Objective",
                  "How an alert connects to the evidence"):
        assert moved not in html, f"{moved} should have moved off the home page"
    # and it stays compact
    assert html.count("<section") <= 4, "the home page should not be a long page again"


def test_scenarios_page_holds_the_five_cards():
    html = read(os.path.join(TRAINING, "scenarios.html"))
    assert "Practice Scenarios" in html
    for name in SCENARIO_FILES:
        assert name in html, f"scenarios page does not link {name}"
    assert html.count('class="card') >= 5


def test_every_scenario_is_reachable_from_the_home_page():
    """One hop from the dashboard: the cards moved, the links must still work."""
    home = read(os.path.join(TRAINING, "index.html"))
    assert "scenarios.html" in home


def test_course_material_survived_the_move():
    """Nothing load-bearing was deleted in the Phase 1A de-duplication.

    The portal used to repeat the same material on six or more pages, so the old
    version of this test asserted that specific *section headings* still existed.
    That is the wrong shape of assertion: it would force the duplication back.
    What matters is the technical content, so assert on that instead - the
    concepts must exist somewhere in the portal, whatever they are called.
    """
    blob = "".join(
        read(os.path.join(TRAINING, page)).lower()
        for page in ("index.html", "instructions.html", "scenarios.html")
    )
    for phrase in ("practice scenarios", "lab objective", "what this lab is",
                   "your only evidence source", "correlation",
                   "raw_event", "brute_force", "suspicious_process_post_login"):
        assert phrase in blob, f"lost during the move: {phrase}"


def test_instructional_material_appears_exactly_once():
    """Phase 1A: 'explain once, apply many times'.

    The generic method was previously restated on the reference page and on all
    five scenario pages. These are the load-bearing duplicates; if one reappears
    the de-duplication has been undone.
    """
    reference = read(os.path.join(TRAINING, "instructions.html"))
    scenario_pages = [read(os.path.join(SCENARIOS_DIR, n)) for n in SCENARIO_FILES]

    # the duplicated four-step "Investigation workflow" block
    assert "Investigation workflow" not in read(os.path.join(TRAINING, "scenarios.html"))
    for page in scenario_pages:
        assert "Investigation workflow" not in page

    # the duplicated "what you will learn" card grids
    for page in scenario_pages + [read(os.path.join(TRAINING, "scenarios.html"))]:
        assert "Skills Practised" not in page, "skills grid reintroduced into a scenario"
        assert "What this exercise builds" not in page

    # the footer reminder that restated the evidence rule on every scenario page
    for page in scenario_pages:
        assert "Do not guess &mdash; find the record" not in page
        assert "Every answer must cite evidence" not in page

    # the method itself still has exactly one home
    assert "The investigation loop" in reference


def test_each_scenario_keeps_one_short_mission():
    """A scenario states its own mission, at most four steps, and points at each
    tool once. The generic workflow block that used to sit above the mission is
    gone, so the mission is now the only step list on the page."""
    for name in SCENARIO_FILES:
        html = read(os.path.join(SCENARIOS_DIR, name))
        main = html[html.index('<main id="main">'):html.index("</main>")]
        lists = re.findall(r'<ol class="steps">(.*?)</ol>', main, re.S)
        assert len(lists) == 1, "%s: expected one mission list, found %d" % (name, len(lists))
        steps = re.findall(r"<li>", lists[0])
        assert 1 <= len(steps) <= 4, "%s: mission has %d steps, at most 4 allowed" % (
            name, len(steps))
        assert main.count("data-kibana-dash") <= 1, "%s: too many dashboard links" % name
        assert main.count("data-kibana-link") <= 1, "%s: too many Discover links" % name


def test_instructions_explains_do_not_guess():
    html = read(os.path.join(TRAINING, "instructions.html"))
    assert "do not guess" in html.lower()


def test_instructions_cover_the_investigation_loop():
    """The loop used to be labelled 'Step 1' / 'Step 2' / 'Steps 3 to 7'.

    The reference is now six named sections rather than a numbered walk, so assert
    the substance of each step instead of the old kicker labels.
    """
    html = read(os.path.join(TRAINING, "instructions.html"))
    for step in ("Pick the alert your brief describes", "Read the alert",
                 "Follow the evidence", "Read the raw lines", "Widen for context",
                 "Write the finding"):
        assert step in html, f"investigation loop lost the step: {step}"


def test_instructions_are_six_compact_sections():
    """Phase 1A: the reference is a reference, not a wall of cards.

    The old page was 2,657 words over 12 sections with 28 cards and 14 callouts.
    """
    html = read(os.path.join(TRAINING, "instructions.html"))
    main = html[html.index('<main id="main">'):html.index("</main>")]
    assert len(re.findall(r"<section", main)) == 6, "the reference should be six sections"
    text = re.sub(r"<[^>]+>", " ", main)
    words = len(re.findall(r"[A-Za-z][A-Za-z'\-]+", text))
    assert words <= 1500, f"reference page is {words} words, should be far shorter"
    assert html.count('class="card') <= 4, "the reference should not be a card grid"


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
    # Phase 6 replaced "Answer every question" with the investigation framing.
    assert "Work the investigation" in html, (
        "%s: the question section lost its heading" % name)
    assert "Answer every question" not in html, (
        "%s: the worksheet heading is back" % name)
    assert "Progressive Hints" in html
    # Phase 1A removed the "Skills Practised" grid from every scenario.
    # test_instructional_material_appears_exactly_once guards against it
    # coming back, so it must not be required here.


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_scenario_has_a_start_action(name):
    html = read(os.path.join(SCENARIOS_DIR, name))
    assert "data-kibana-dash" in html or "data-kibana-link" in html


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_scenario_has_questions_and_notes(name):
    """Each page carries its own questions, not Scenario 01's.

    The assertion used to look for 's1e1' on every page, which only passed because
    the worksheet ids were identical across scenarios. Reading the page's own
    scenario number is what actually proves the page is populated.
    """
    html = read(os.path.join(SCENARIOS_DIR, name))
    number = re.search(r"scenario-(\d)", name).group(1)
    assert 'data-question="s%se1"' % number in html, name
    ids = set(re.findall(r'data-question-row="(s\d(?:e\d+|f))"', html))
    assert len(ids) >= 7, "%s: %d questions" % (name, len(ids))
    assert "s%sf" % number in ids, "%s: no final analyst finding" % name
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
    assert 'href="../scenarios.html"' in html, name


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
    """The guide must carry the stable evidence values.

    Absolute timestamps are deliberately absent: the generator re-bases them every
    session, which is why the key grades durations and counts instead. The guide's
    reference timeline is regenerated from the live dataset, so its clock times
    move between datasets by design and are not asserted here.
    """
    text = read(INSTRUCTOR_GUIDE)
    for value in ("203.0.113.45", "203.0.113.66", "198.51.100.25", "198.51.100.77",
                  "svc_backup", "132", "129", "brute_force", "successful_brute_force",
                  "suspicious_process_post_login"):
        assert value in text, value


def test_instructor_guide_documents_the_current_question_ids():
    """The guide declares itself the answer key's source, so it cannot lag behind.

    Phase 6 renamed every question. A guide still describing the old worksheet
    numbering would be worse than useless to an instructor marking work.
    """
    text = read(INSTRUCTOR_GUIDE)
    import json
    with open(os.path.join(REPO_ROOT, "data", "answer-key.json"), encoding="utf-8") as handle:
        key = json.load(handle)
    missing = []
    for scenario, spec in key["scenarios"].items():
        for qid in spec["questions"]:
            if qid not in text:
                missing.append(qid)
    assert not missing, "question ids absent from the instructor guide: %s" % missing
    for scenario in key["scenarios"]:
        assert ("## " in text), "guide structure intact"
    # No worksheet numbering left behind.
    import re as _re
    assert not _re.search(r"\|\s*Q\s*\|", text), "a worksheet Q-number table survived"
    assert "Check answers" not in text, "the guide still describes the submit-all button"


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
