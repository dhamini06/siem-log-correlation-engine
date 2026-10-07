"""Structural contracts for the Phase 3 scenario investigation workspace.

The scenario page was rebuilt as a two-column workspace: the case brief and the
question queue on the left, the evidence rail on the right, and the final
finding marked off inside the queue rather than moved out of it.

These tests protect the decisions that are easy to undo by accident:

* the two-column geometry, and the small-screen reading order, are expressed as
  named grid areas so the DOM order and the mobile order cannot drift apart
* the evidence rail is context and access only. The lab dataset is small, so
  anything the SIEM could be asked for is the answer to one of the questions.
  Severity and the rule name are safe because the case header already prints
  them; addresses, accounts, ports, counts and timestamps are not, and none of
  them may appear in the rail or the case header
* the question list is untouched: same ids, same order, same hooks, same number
  of answer fields and reveal buttons. The only addition is a break element,
  which must stay invisible to lab-check.js
* the workspace added no cards. Phase 3 is a structural change, and the review
  that asked for it also asked for the box count to come down

Written against the shape of the decision rather than the exact markup, so an
equivalent rewrite still passes.
"""

import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAINING = os.path.join(ROOT, "training")
SCENARIOS = os.path.join(TRAINING, "scenarios")
CSS = os.path.join(TRAINING, "assets", "css", "bluecloud.css")

# Only Scenario 01 shipped an investigation-progress readout; 02-05 never had
# one. Phase 3 was not allowed to add or remove them, so the counts are pinned
# to the pre-Phase-3 pages rather than derived at run time.
EXPECTED_PROGRESS = {"scenario-1-brute-force.html": 1}

SCENARIO_FILES = ["scenario-1-brute-force.html",
                  "scenario-2-successful-brute-force.html",
                  "scenario-3-post-login-execution.html",
                  "scenario-4-linux-privilege-escalation.html",
                  "scenario-5-multi-event-soc-investigation.html"]

# Values a student is expected to discover. None of them may be printed by the
# workspace chrome the student sees before they start investigating.
STUDENT_MUST_FIND = [
    "203.0.113.45", "203.0.113.66", "198.51.100.25", "198.51.100.77",
    "10.0.0.10", "10.0.0.30", "svc_backup", "alice",
    "07:25:55", "07:28:07", "132 seconds", "min_failures: 5",
    "web-01", "app-01", "app-02", "fw-01",
]


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def page(name):
    return read(os.path.join(SCENARIOS, name))


def main_of(html):
    return html[html.index('<main id="main">'):html.index("</main>")]


# --------------------------------------------------------------- the geometry

def test_workspace_uses_named_grid_areas():
    """Named areas, not flex `order`.

    With `order` the DOM order and the visual order can silently disagree, and
    a student tabbing through the page meets the questions before the evidence.
    Named areas make the mobile order a property of the stylesheet, where it
    can be asserted.
    """
    css = read(CSS)
    assert 'grid-template-areas: "brief" "rail" "questions"' in css, (
        "the small-screen order must be brief, then evidence, then questions")
    assert 'grid-template-areas: "brief rail" "questions rail"' in css
    for area in ("brief", "questions", "rail"):
        assert "grid-area: %s;" % area in css, area
    assert "order:" not in css.split("@media (min-width: 1100px)")[0].split(
        ".layout-split")[-1][:400], "the workspace should not rely on flex order"


def test_workspace_columns_are_roughly_65_35():
    css = read(CSS)
    m = re.search(r"grid-template-columns:\s*minmax\(0,\s*([\d.]+)fr\)\s*"
                  r"minmax\(0,\s*1fr\)", css)
    assert m, "no two-column ratio in the workspace"
    ratio = float(m.group(1)) / (float(m.group(1)) + 1.0)
    assert 0.55 <= ratio <= 0.75, (
        "the investigation column is %.0f%% of the width; it should dominate" % (ratio * 100))


def test_the_rail_is_sticky_but_the_questions_are_not():
    """The rail holds the hints, so it follows the student down the queue."""
    css = read(CSS)
    rail = re.search(r"\.case-rail\s*\{[^}]*\}", css)
    assert rail, "no .case-rail rule"
    sticky = re.search(r"@media \(min-width: 1100px\)\s*\{[^@]*?\.case-rail\s*\{"
                       r"[^}]*position:\s*sticky", css, re.S)
    assert sticky, "the evidence rail is not sticky on a wide screen"


# ------------------------------------------------------------- the page shape

@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_every_scenario_is_a_workspace(name):
    html = page(name)
    body = main_of(html)
    assert body.count('class="layout-split"') == 1, name
    order = [a or b for a, b in re.findall(
        r'class="ws-section (workspace-\w+)"|class="(case-rail)"', html)]
    assert order == ["workspace-brief", "workspace-questions", "case-rail"], (
        "%s: workspace areas are %r" % (name, order))
    assert body.count('class="ws-section') == 2, name
    assert body.count('class="rail-block"') == 2, name


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_every_scenario_has_a_case_header(name):
    html = page(name)
    head = re.search(r'<section class="page-head case-head">(.*?)</section>', html, re.S)
    assert head, "%s: no case header" % name
    block = head.group(1)
    assert re.search(r'Scenario \d+', block), "%s: no scenario number" % name
    assert re.search(r"<h1>[^<]+</h1>", block), "%s: no title" % name
    assert "Severity" in block or "severity" in block, "%s: no severity" % name
    assert "Rule" in block or "rule" in block, "%s: no correlation rule" % name
    assert 'class="case-objective"' in block, "%s: no objective" % name
    # it is a header, not a hero: no marketing paragraph block
    assert 'class="eyebrow"' not in block, "%s: the case header became a hero" % name


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_no_answers_in_the_workspace_chrome(name):
    """The rail may give context and access, never the answer.

    Scanned *excluding the hints*. Hint bodies are pre-existing public content
    that this phase is explicitly forbidden to rewrite, and several of them
    legitimately name a host so the student knows which system to look at.
    What must be clean is the chrome this phase authored: the rail headings,
    the rail note and the tool links.
    """
    html = page(name)
    rail = re.search(r'<aside class="case-rail">(.*)</aside>', html, re.S)
    assert rail, "%s: no evidence rail" % name
    chrome = re.sub(r'<details class="hint">.*?</details>', "", rail.group(1), flags=re.S)
    head = re.search(r'<section class="page-head case-head">(.*?)</section>',
                     html, re.S).group(1)
    for secret in STUDENT_MUST_FIND:
        assert secret not in chrome, (
            "%s: the evidence rail chrome exposes %r" % (name, secret))
        assert secret not in head, ("%s: the case header exposes %r" % (name, secret))


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_the_case_header_states_the_case_once(name):
    """The scenario number appears twice, and no more.

    Once in the breadcrumb, which is navigation, and once as the case identity
    in .case-id. The rebuild promoted the old page-head meta row into
    .case-meta and gave it a .case-id of its own; keeping the original
    "Scenario NN" chip as well printed it three times inside one header.
    """
    head = re.search(r'<section class="page-head case-head">(.*?)</section>',
                     page(name), re.S).group(1)
    num = re.search(r'class="case-id">Scenario (\d+)<', head)
    assert num, "%s: no case-id" % name
    label = "Scenario " + num.group(1)
    assert head.count(label) == 2, (
        "%s: %r appears %d times in the case header, expected 2 "
        "(breadcrumb + case identity)" % (name, label, head.count(label)))
    # and it is not also sitting there as a chip
    meta = re.search(r'<div class="case-meta">(.*?)</div>\s*<h1>', head, re.S)
    assert meta, "%s: no case-meta" % name
    assert meta.group(1).count(label) == 1, (
        "%s: the case-meta row repeats the scenario number" % name)


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_the_rail_gives_access_to_the_tools(name):
    html = page(name)
    rail = re.search(r'<aside class="case-rail">(.*)</aside>', html, re.S).group(1)
    assert rail.count("data-kibana-dash") == 1, name
    assert rail.count("data-kibana-link") == 1, name
    # one pair in the whole body, not one per block
    body = main_of(html)
    assert body.count("data-kibana-dash") == 1, (
        "%s: %d dashboard links in the body" % (name, body.count("data-kibana-dash")))
    assert body.count("data-kibana-link") == 1, (
        "%s: %d discover links in the body" % (name, body.count("data-kibana-link")))


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_hints_travel_to_the_rail_with_their_control(name):
    html = page(name)
    rail = re.search(r'<aside class="case-rail">(.*)</aside>', html, re.S).group(1)
    total = len(re.findall(r'<details class="hint">', html))
    assert total >= 5, "%s: %d hints" % (name, total)
    assert rail.count('<details class="hint">') == total, (
        "%s: %d of %d hints are in the rail"
        % (name, rail.count('<details class="hint">'), total))
    assert 'id="toggle-hints"' in rail, "%s: the hint toggle is not with the hints" % name
    assert html.count('id="toggle-hints"') == 1, name
    actions = re.search(r'<div class="check-actions[^"]*">(.*?)</div>', html, re.S).group(1)
    assert "toggle-hints" not in actions, (
        "%s: the hint toggle is mixed in with the answer-check buttons" % name)


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_the_workspace_added_no_cards(name):
    body = main_of(page(name))
    assert 'class="card' not in body, "%s: the workspace introduced a card" % name


# ------------------------------------------------------- questions untouched

@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_the_questions_are_untouched(name):
    """The queue is well formed and every question is independently usable.

    Phase 6 retired the worksheet: the rows are named s<N>e<M> with s<N>f last,
    and they no longer share one control type. So the old "every row is a
    textarea" equality is replaced by three equalities that actually matter -
    one row, one control and one Check button per question - plus the ordering
    rule that puts the finding last.
    """
    html = page(name)
    rows = re.findall(r'data-question-row="(s\d(?:e\d+|f))"', html)
    evidence = [q for q in rows if re.fullmatch(r"s\de\d+", q)]
    findings = [q for q in rows if re.fullmatch(r"s\df", q)]

    assert evidence == ["s%se%d" % (name.split("-")[1], i) for i in range(1, len(evidence) + 1)], (
        "%s: evidence ids are not a contiguous run: %r" % (name, evidence))
    assert len(evidence) in (7, 8), "%s: %d evidence questions" % (name, len(evidence))
    assert len(findings) == 1, "%s: %d findings" % (name, len(findings))
    assert rows[-1] == findings[0], "%s: the finding must come last: %r" % (name, rows)

    controls = re.findall(r'data-question="(s\d(?:e\d+|f))"', html)
    checks = re.findall(r'data-check="(s\d(?:e\d+|f))"', html)
    reveals = re.findall(r'data-reveal="(s\d(?:e\d+|f))"', html)
    hints = re.findall(r'data-hint="(s\d(?:e\d+|f))"', html)
    # An ordering control lists its items in a <ol> carrying data-question, so the
    # count there is rows + ordering questions. Everything else is one per row.
    assert sorted(set(controls)) == sorted(rows), (
        "%s: controls %r vs rows %r" % (name, sorted(set(controls)), sorted(rows)))
    assert sorted(set(checks)) == sorted(rows), "%s: check buttons do not match rows" % name
    assert sorted(set(reveals)) == sorted(rows), "%s: reveals do not match rows" % name
    assert sorted(set(hints)) == sorted(rows), "%s: hints do not match rows" % name

    for token in ('id="mark-done"', 'id="undo-done"', 'id="check-result"',
                  'id="done-banner"', 'id="check-status"', 'id="check-gate-note"',
                  'id="saved-note"'):
        assert html.count(token) == 1, "%s: %s appears %d times" % (
            name, token, html.count(token))
    assert 'id="check-answers"' not in html, (
        "%s: the submit-everything button is back" % name)


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_the_final_finding_is_marked_off_inside_the_queue(name):
    """The finding is a distinct final step, visually and structurally.

    Under the worksheet model the break was a separate <li> carrying no question
    data, sitting before the last question. Phase 6 replaced that with a single
    final row marked q-item-final, which is simpler but has to earn the same
    separation: it must be the last row, must not advance the evidence numbering,
    and must be visibly set apart.
    """
    html = page(name)
    # A row's extent is bounded by the *next* row's start, not by the next
    # "</li>": the finding row contains its own <ul> of rubric items, and a
    # non-greedy match would stop inside it and miss the Check button that comes
    # after the rubric.
    starts = list(re.finditer(
        r'<li class="q-item[^"]*" data-question-row="(s\d(?:e\d+|f))"', html))
    assert starts, "%s: no question rows" % name
    list_end = html.index("</ol>", starts[-1].end())
    last_start = starts[-1]
    row = html[last_start.start():list_end]
    assert re.fullmatch(r"s\df", last_start.group(1)), (
        "%s: the last row must be the final finding, found %r"
        % (name, last_start.group(1)))
    assert "q-item-final" in row[:120], (
        "%s: the finding row is not marked as the final step" % name)

    # Nothing may sit between the last question row and the end of the list.
    between = html[starts[-2].end():last_start.start()] if len(starts) > 1 else ""
    assert "data-question-row" not in between, (
        "%s: an unaccounted row sits after the evidence questions" % name)

    # The finding is usable: a control, a Check button, a reveal and its rubric.
    for hook in ('data-question="', "data-check=", "data-reveal=", "data-hint=",
                 "q-rubric-list", "q-rubric-note"):
        assert hook in row, "%s: the finding is missing %s" % (name, hook)

    css = read(CSS)
    assert ".q-item-final {" in css, "the finding has no styling of its own"
    block = re.search(r"\.q-item-final\s*\{([^}]*)\}", css).group(1)
    assert "border-top" in block, (
        "the finding would not be visually separated from the evidence questions")
    # The evidence numbering is explicit per row, so nothing must advance a counter.
    assert "q-item-final .q-number" in css, (
        "the finding number should be styled apart from the evidence numbers")


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_progress_is_kept_but_secondary(name):
    """Phase 3 keeps the existing progress readout, and only on the page that
    had one. It must not grow into a second widget competing with the questions.

    The rebuild originally dropped it silently: the markup sits *before*
    .check-actions, and the extraction sliced from check-actions onwards, so the
    readout fell outside the slice and vanished without failing anything else.
    The count is pinned so that cannot recur.
    """
    html = page(name)
    expected = EXPECTED_PROGRESS.get(name, 0)
    assert html.count('id="progress-bar"') == expected, (
        "%s: progress readout count %d, expected %d"
        % (name, html.count('id="progress-bar"'), expected))
    if expected:
        for token in ('id="progress-label"', 'id="progress-fill"', 'id="progress-hint"',
                      'aria-valuemin', 'aria-valuemax'):
            assert html.count(token) == 1, "%s: %s" % (name, token)
    css = read(CSS)
    progress = re.search(r"\.progress-card\s*\{([^}]*)\}", css)
    assert progress, "no .progress-card rule"
    # no border, no background, no shadow: a strip, not a card
    for prop in ("border:", "background:", "box-shadow:"):
        assert prop not in progress.group(1), (
            "the progress readout should not be boxed (%s)" % prop)


@pytest.mark.parametrize("name", SCENARIO_FILES)
def test_the_workspace_has_no_stray_text_nodes(name):
    """A bare ">" or an orphaned fragment in the markup is a visible artefact.

    Caught by reading a rendered page, not by any structural check: stripping
    the .section-head wrapper with a hard-coded offset left the tag's closing
    character behind, and it printed as a stray mark between two sections.
    """
    html = page(name)
    # Scan the rendered markup only. Script and style bodies contain lines that
    # are just "}" and would match a naive stray-character sweep.
    visible = re.sub(r"<script.*?</script>", "", html, flags=re.S)
    visible = re.sub(r"<style.*?</style>", "", visible, flags=re.S)
    for stray in re.findall(r"^[ \t]*[>{}][ \t]*$", visible, re.M):
        raise AssertionError("%s: stray text node %r" % (name, stray))
    # every opening tag inside <main> is either a known element or closed
    main = main_of(html)
    for tag in ("div", "section", "aside", "ol", "ul", "li", "p", "details",
                "span", "label", "button", "textarea", "table", "h2", "h3"):
        o = len(re.findall(r"<%s[\s>]" % tag, main))
        c = len(re.findall(r"</%s>" % tag, main))
        assert o == c, "%s: %s open %d / close %d" % (name, tag, o, c)
