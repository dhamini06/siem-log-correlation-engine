"""Regression tests for the two UI defects found by driving a real browser.

Both were invisible to every test that already existed:

* ``fillTable`` received a descriptor object and read ``columns.forEach`` off
  it. The API contract tests asserted the *data* was right, the markup tests
  asserted the *headers* matched the field list, and neither ever ran the
  render. The instructor dashboard threw on every load and showed no tables.

* ``paintIdentity`` was handed the sign-*out* element in the slot documented for
  a sign-*in* link, so signing in hid "Sign out". A signed-in student had no
  visible way to end their session.

There is no JS test runner in this repository and adding one is out of scope, so
these are structural checks in the same spirit as the existing admin_stats SQL
checks. They are deliberately written against the *shape* that broke - a
parameter used as an array, and a toggle driven by the wrong control - rather
than against the particular fix, so an equivalent rewrite still passes.
"""

import glob
import html
import os
import re
import sys
from datetime import datetime, timedelta

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAINING = os.path.join(ROOT, "training")
AUTH_JS = os.path.join(TRAINING, "assets", "js", "auth.js")
ADMIN_JS = os.path.join(TRAINING, "assets", "js", "admin.js")
ADMIN_HTML = os.path.join(TRAINING, "admin.html")

PAGES_WITH_SLOTS = ["index.html", "instructions.html", "scenarios.html",
                   "admin.html"] + [
    "scenarios/" + n for n in sorted(os.listdir(os.path.join(TRAINING, "scenarios")))
    if n.endswith(".html")
]


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def strip_comments(js: str) -> str:
    """Remove // and /* */ comments so a rule cannot be satisfied by prose.

    Necessary, not decoration: the fix for each defect carries a comment that
    names the very expression being asserted, and a naive substring check would
    pass on the comment alone.
    """
    js = re.sub(r"/\*.*?\*/", " ", js, flags=re.S)
    return re.sub(r"//[^\n]*", " ", js)


def function_body(js: str, name: str) -> str:
    """Return one top-level function's body by brace matching.

    Deliberately not a regex over the whole file: the caller must be able to
    assert about a specific function without picking up a same-named word
    elsewhere.
    """
    js = strip_comments(js)
    m = re.search(r"function\s+%s\s*\(" % re.escape(name), js)
    assert m, "function %s not found" % name
    start = js.index("{", m.end() - 1)
    depth = 0
    for i in range(start, len(js)):
        if js[i] == "{":
            depth += 1
        elif js[i] == "}":
            depth -= 1
            if depth == 0:
                return js[start:i + 1]
    raise AssertionError("unbalanced braces in %s" % name)


def function_signature(js: str, name: str):
    m = re.search(r"function\s+%s\s*\(([^)]*)\)" % re.escape(name), strip_comments(js))
    assert m, "function %s not found" % name
    return [p.strip() for p in m.group(1).split(",") if p.strip()]


# =============================================== the fillTable descriptor bug

def test_fill_table_takes_a_descriptor_not_a_bare_array():
    """The third argument is a descriptor; the column list lives inside it."""
    body = function_body(read(ADMIN_JS), "fillTable")
    params = function_signature(read(ADMIN_JS), "fillTable")
    assert len(params) == 3, "fillTable(tableId, rows, config): %r" % params
    # it must unpack the list out of the descriptor
    assert re.search(r"=\s*\(?\s*%s\s*&&\s*%s\.columns\s*\)?\s*\|\|\s*\[\]"
                     % (re.escape(params[2]), re.escape(params[2])), body), \
        "fillTable must read the column array off the descriptor: %s" % body[:300]


def test_fill_table_never_uses_its_third_argument_as_an_array():
    """The exact shape that broke: a method called on the descriptor.

    Before the fix the body was ``columns.forEach(...)`` where ``columns`` was
    the descriptor object, so every table threw
    ``columns.forEach is not a function`` and rendered nothing.
    """
    body = function_body(read(ADMIN_JS), "fillTable")
    params = function_signature(read(ADMIN_JS), "fillTable")
    third = re.escape(params[2])
    # any method call directly on the descriptor, other than property access
    offenders = re.findall(r"\b%s\s*\.\s*(forEach|map|filter|length|join)\b"
                           % third, body)
    assert not offenders, \
        "fillTable treats its descriptor as an array: %r" % offenders


def test_every_fill_table_call_supplies_a_column_array():
    js = strip_comments(read(ADMIN_JS))
    calls = re.findall(r"fillTable\(\s*\"[^\"]+\"[^;]*?\}\);", js, flags=re.S)
    assert calls, "no fillTable call sites found"
    for call in calls:
        assert re.search(r"columns\s*:\s*\[", call), \
            "a fillTable call has no columns array: %s" % call[:160]
        assert "emptyMessage" in call, \
            "a fillTable call has no empty-state message: %s" % call[:160]


def test_each_tables_column_list_matches_its_headers():
    """The rendered cells must line up with the <th> elements.

    The empty-state colspan is derived from the same list that builds the rows,
    so a mismatch here would show up as a visibly ragged table.
    """
    html = read(ADMIN_HTML)
    js = strip_comments(read(ADMIN_JS))
    for table_id in ("student-table", "scenario-table"):
        m = re.search(r'id="%s".*?</table>' % table_id, html, flags=re.S)
        assert m, "%s not found in admin.html" % table_id
        thead = m.group(0).split("</thead>")[0]
        # <th\s, not <th[^>]*>: the latter also matches <thead>.
        headers = re.findall(r"<th\s[^>]*>", thead)
        call = re.search(r'fillTable\(\s*"%s".*?\}\);' % table_id, js, flags=re.S)
        assert call, "no fillTable call for %s" % table_id
        fields = re.findall(r'\{\s*field:\s*"([a-z_]+)"', call.group(0))
        assert fields, "no columns declared for %s" % table_id
        assert len(fields) == len(headers), (
            "%s: %d columns declared but %d headers in the markup"
            % (table_id, len(fields), len(headers)))


# ================================================ the session-control bug

def test_paint_identity_separates_the_sign_in_and_sign_out_controls():
    """One slot for two controls is what inverted the toggle."""
    params = function_signature(read(AUTH_JS), "paintIdentity")
    assert len(params) == 4, \
        "paintIdentity must take (user, nameEl, signInEl, signOutEl): %r" % params
    body = function_body(read(AUTH_JS), "paintIdentity")
    sign_in, sign_out = re.escape(params[2]), re.escape(params[3])
    # each control is toggled against its own element
    assert re.search(r"%s\.hidden\s*=\s*signedIn" % sign_in, body), \
        "the sign-in link is not driven by its own slot: %s" % body[:300]
    assert re.search(r"%s\.hidden\s*=\s*!\s*signedIn" % sign_out, body), \
        "the sign-out control is not driven by its own slot: %s" % body[:300]


def test_a_signed_in_user_shows_sign_out_and_hides_sign_in():
    """The exact regression: signing in must not hide the way out."""
    body = function_body(read(AUTH_JS), "paintIdentity")
    assert re.search(r"signOutEl\s*\.\s*hidden\s*=\s*!\s*signedIn", body)
    # and the identity itself follows the same flag
    assert re.search(r"nameEl\s*\.\s*hidden\s*=\s*!\s*signedIn", body)


def test_mount_identity_finds_and_passes_both_controls():
    js = strip_comments(read(AUTH_JS))
    body = function_body(read(ADMIN_JS), "unused") if False else function_body(read(AUTH_JS),
                                                                                "mountIdentity")
    assert 'querySelector("[data-auth-signin]")' in body, \
        "mountIdentity does not look up the sign-in slot"
    assert 'querySelector("[data-auth-signout]")' in body
    call = re.search(r"paintIdentity\(([^;]*)\);", body)
    assert call, "mountIdentity never calls paintIdentity"
    assert call.group(1).count(",") == 3, \
        "paintIdentity is not given both controls: %r" % call.group(1)


@pytest.mark.parametrize("page", PAGES_WITH_SLOTS)
def test_every_page_with_a_signout_slot_also_has_an_identity_slot(page):
    """The two slots ship together; a page with one and not the other would
    render a header that can sign out but never say who is signed in."""
    html = read(os.path.join(TRAINING, page))
    assert "data-auth-signout" in html, page
    assert "data-auth-identity" in html, page


def test_the_scenario_titles_in_the_script_match_the_scenarios_page():
    """student-progress.js labels the scenarios in its "Recent activity" card.

    The progress payload carries a scenario id and nothing else, so the script
    carries its own id -> title and id -> href map. Nothing stops those from
    drifting away from the real cards, and a stale title on the home page would
    quietly misdescribe a student's own work.
    """
    js = read(os.path.join(TRAINING, "assets", "js", "student-progress.js"))
    pairs = dict(re.findall(r'"(scenario-\d)":\s*\{\s*title:\s*"([^"]+)"', js))
    hrefs = dict(re.findall(r'"(scenario-\d)":\s*\{[^}]*?href:\s*"([^"]+)"', js, re.S))
    assert pairs, "no scenario titles found in student-progress.js"

    page = read(os.path.join(TRAINING, "scenarios.html"))
    # Split on the article boundaries first. A single pattern with .*? across
    # the whole page happily matches one card's data-scenario to the *next*
    # card's heading, which is exactly the mis-pairing this test exists to
    # catch - so it must not be written that way.
    cards = []
    for block in re.findall(r"<article\b.*?</article>", page, re.S):
        sid = re.search(r'data-scenario="(scenario-\d)"', block)
        h3 = re.search(r"<h3>(.*?)</h3>", block, re.S)
        href = re.search(r'<a class="btn[^"]*" href="([^"]+)"', block)
        if sid and h3 and href:
            title = re.sub(r"<[^>]+>", "", h3.group(1))
            # The markup escapes "&" as &amp;; the script holds the plain
            # character. Unescape before comparing or the guard reports a false
            # mismatch on any title containing an ampersand.
            cards.append((sid.group(1), html.unescape(re.sub(r"\s+", " ", title)).strip(),
                          href.group(1)))
    assert len(cards) == 5, "expected five scenario cards, found %d" % len(cards)

    for scenario_id, title, href in cards:
        assert scenario_id in pairs, "%s missing from student-progress.js" % scenario_id
        assert pairs[scenario_id] == title, (
            "%s: script says %r, scenarios.html says %r"
            % (scenario_id, pairs[scenario_id], title))
        assert scenario_id in hrefs, "%s has no href in student-progress.js" % scenario_id
        assert hrefs[scenario_id] == href, (
            "%s: script links %r, the card links %r" % (scenario_id, hrefs[scenario_id], href))


def test_hidden_actually_hides():
    """`[hidden]` must beat the class rules, or hidden elements still render.

    The browser default is a type-level rule, so `.btn { display: inline-flex }`
    silently beat it: the home dashboard's "Continue" button carried the
    `hidden` attribute and was still painted for a student who had started
    nothing. Found by rendering the page, not by reading it. Two `.nav-*[hidden]`
    rules were patching individual cases before this was enforced globally.
    """
    css = read(os.path.join(TRAINING, "assets", "css", "bluecloud.css"))
    # Anchored to the start of a line: the stylesheet also contains
    # class-qualified rules like `.nav-identity[hidden]`, and a loose search
    # finds one of those first and reports a false failure.
    m = re.search(r"(?m)^\[hidden\]\s*\{([^}]*)\}", css)
    assert m, "no global [hidden] rule in bluecloud.css"
    assert "!important" in m.group(1), (
        "[hidden] needs !important to outrank the class-level display rules: %r"
        % m.group(1).strip())
    # and the class that actually caused it must still set a display
    assert re.search(r"\.btn\s*\{[^}]*display:", css, re.S), (
        "expected .btn to set display, which is what [hidden] has to beat")


def test_progress_script_never_writes_to_the_body():
    """`[data-scenario]` on <body> made a bare selector destroy the page.

    Every scenario page carries data-scenario on the body element, so
    student-progress.js's `querySelectorAll("[data-scenario]")` matched it. The
    badge writer then set `body.className` and replaced the body's contents with
    one line of text. The server returned HTTP 200 and 25 KB; the browser
    rendered zero elements, and no test noticed because none of them run a
    browser. The selector must be class-qualified so the only things written to
    are the badges on scenarios.html.
    """
    import glob
    # the precondition: the pages really do put it on <body>
    scen_dir = os.path.join(TRAINING, "scenarios")
    pages = sorted(glob.glob(os.path.join(scen_dir, "*.html")))
    assert pages, "no scenario pages found"
    for path in pages:
        body = re.search(r"<body[^>]*>", read(path))
        assert body and "data-scenario" in body.group(0), (
            "%s is expected to carry data-scenario on <body>" % os.path.basename(path))

    # Comments are stripped first, and that is not optional: the fix for this
    # defect carries a comment that quotes the offending selector verbatim, so
    # a scan of the raw source finds its own documentation and fails.
    js = strip_comments(read(os.path.join(TRAINING, "assets", "js",
                                          "student-progress.js")))
    # Any querySelector/All whose selector *is* a bare [data-...] attribute
    # selector is the hazard. Note the (?:All)? - "querySelectorAll?" would
    # match "querySelectorAl" and silently find nothing.
    selectors = re.findall(r"querySelector(?:All)?\(\s*[\"']([^\"']+)[\"']", js)
    assert selectors, "no querySelector call found - is the file intact?"
    for selector in selectors:
        if selector.startswith("[") and selector.endswith("]"):
            assert "." in selector or " " in selector, (
                "student-progress.js queries the bare attribute selector %r, which "
                "matches <body> on every scenario page" % selector)
    # and the badge writer must name the class it is allowed to touch
    assert ".scenario-state[data-scenario]" in js, (
        "the scenario badge selector lost its class qualifier")

def test_only_the_scenarios_page_carries_badges():
    """The badges belong on scenarios.html. A scenario page has none, which is
    what makes the script a no-op there."""
    scen_page = read(os.path.join(TRAINING, "scenarios.html"))
    assert scen_page.count('class="scenario-state"') == 5, (
        "expected five badges on scenarios.html")
    for path in glob.glob(os.path.join(TRAINING, "scenarios", "*.html")):
        assert 'class="scenario-state"' not in read(path), (
            "%s should not carry a scenario-state badge" % os.path.basename(path))


@pytest.mark.parametrize("page", PAGES_WITH_SLOTS + [
    "scenarios/" + n for n in sorted(os.listdir(os.path.join(TRAINING, "scenarios")))
    if n.endswith(".html")
])
def test_no_script_is_loaded_twice(page):
    """A duplicated <script src> runs the file twice.

    student-progress.js ended up included twice on all five scenario pages, so
    init() ran twice and every page load fired two /api/student/progress
    requests instead of one. Harmless in appearance, wrong in cost, and the
    kind of duplicate that creeps in unnoticed because nothing fails.
    """
    html = read(os.path.join(TRAINING, page))
    scripts = re.findall(r'<script src="([^"]+)"></script>', html)
    assert scripts, "%s loads no external script at all" % page
    for src in set(scripts):
        assert scripts.count(src) == 1, (
            "%s includes %s %d times" % (page, src, scripts.count(src)))


def test_the_sign_in_link_is_hooked_wherever_it_exists():
    """Pages carrying a visible 'Sign in' link must expose it as a slot, or a
    signed-in student is shown a link to a page that bounces them straight
    back."""
    found = 0
    for page in PAGES_WITH_SLOTS:
        html = read(os.path.join(TRAINING, page))
        if 'href="login.html"' in html:
            found += 1
            assert "data-auth-signin" in html, \
                "%s shows a Sign in link but does not hook it" % page
    assert found >= 2, "expected the student pages to carry a sign-in link"


# ================================= the Discover deep-link time window

#: The dataset this lab runs on spans a fixed 14 days. Any window narrower than
#: this hides the incidents; see docs/DATASET.md.
DATASET_FIRST_DAY = "2026-09-16"
DATASET_LAST_DAY = "2026-09-29"

#: The window is absolute, so it is parsed and compared as a date rather than
#: matched as a string. This test used to assert `window == "now-15d"`, which
#: checked the *implementation* rather than the property it is named for: any
#: other value failed, including a correct absolute one, and - the reason this
#: matters - `now-15d` kept passing long after it had stopped covering the
#: dataset. A relative window and a fixed dataset cannot both age well, so the
#: assertion is now containment, and it holds whatever the window is written as.
ISO_WINDOW = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$")

#: How far outside the dataset the window may reach. The approved bounds carry a
#: day of slack at each end so containment does not depend on the exact first
#: and last event; a week is the ceiling, which still rules out a window that
#: technically "covers" the data while burying it in months of empty range.
MAX_WINDOW_SLACK_DAYS = timedelta(days=7)

KIBANA_PAGES = ["index.html", "instructions.html", "scenarios.html"] + [
    "scenarios/" + n for n in sorted(os.listdir(os.path.join(TRAINING, "scenarios")))
    if n.endswith(".html")
]
LAB_JS = os.path.join(TRAINING, "assets", "js", "lab.js")


def test_no_page_carries_its_own_kibana_url_block():
    """The deep-links are defined once, in lab.js, not copied per page.

    Eight copies of a value that has to agree is eight chances to disagree, and
    they did: every page asked Discover for the last 24 hours while the dataset
    spans 14 days, so a student following the link saw 511 of 9,584 events and
    none of the four alerts. Nothing failed, because each page was internally
    consistent.
    """
    for page in KIBANA_PAGES:
        html = read(os.path.join(TRAINING, page))
        assert "function discover(" not in html, \
            "%s defines its own discover() instead of using lab.js" % page
        assert not re.search(r"time:\(from:[^,]+,to:[^)]+\)", html), \
            "%s hard-codes a Discover time range" % page
        assert "localhost:5601" not in html, \
            "%s hard-codes the Kibana base URL" % page


def test_no_page_anywhere_in_training_still_asks_for_the_old_window():
    for path in glob.glob(os.path.join(TRAINING, "**", "*.*"), recursive=True):
        if path.endswith(".pyc"):
            continue
        with open(path, encoding="utf-8", errors="replace") as handle:
            body = handle.read()
        assert "now-24h" not in body, "%s still uses now-24h" % os.path.relpath(path, TRAINING)


def test_lab_js_owns_the_deep_links():
    js = read(LAB_JS)
    body = function_body(js, "initKibanaLinks")
    for selector in ("[data-kibana-dash]", "[data-kibana-link]",
                     "[data-kibana-alerts]", "[data-es-link]"):
        assert selector in body, "initKibanaLinks does not wire %s" % selector
    for data_view in ("siem-normalized-events", "siem-security-alerts"):
        assert data_view in js, "lab.js does not reference %s" % data_view
    assert "siem-soc-triage-board" in js, "lab.js does not reference the board"


def test_lab_js_runs_the_deep_link_wiring():
    """Registering the initializer is the whole contract; the call must be
    inside the DOMContentLoaded handler or the anchors do not exist yet."""
    js = strip_comments(read(LAB_JS))
    assert "function initKibanaLinks(" in js
    handler = re.search(r"addEventListener\(\s*[\"']DOMContentLoaded[\"']\s*,"
                        r"\s*function\s*\(\)\s*\{(.*?)\}\s*\)\s*;", js, re.S)
    assert handler, "lab.js has no DOMContentLoaded handler"
    assert "initKibanaLinks()" in handler.group(1), \
        "initKibanaLinks is not called on DOMContentLoaded"


def _lab_js_window():
    """The two window constants lab.js actually uses, uncommented."""
    js = strip_comments(read(LAB_JS))
    found = {}
    for name in ("INVESTIGATION_FROM", "INVESTIGATION_TO"):
        m = re.search(name + r"\s*=\s*[\"']([^\"']+)[\"']", js)
        assert m, "lab.js does not declare %s" % name
        found[name] = m.group(1)
    return found["INVESTIGATION_FROM"], found["INVESTIGATION_TO"]


def test_the_discover_window_covers_the_dataset():
    """The window must contain the whole approved dataset, at both ends.

    Containment, not equality with a literal. The dataset is intentionally
    immutable - 2026-09-16 .. 2026-09-29, one fixed seed and one fixed base
    timestamp - so a window expressed relative to "now" is the wrong shape:
    `now-15d` covered the dataset when it was built and silently stopped
    covering it, and the board came to show 3 of the 4 canonical alerts. The
    bounds therefore have to straddle the dataset's own extent.
    """
    window_from, window_to = _lab_js_window()

    for name, value in (("INVESTIGATION_FROM", window_from),
                        ("INVESTIGATION_TO", window_to)):
        assert ISO_WINDOW.match(value), (
            "%s is %r; the dataset is fixed, so the window must be an absolute "
            "ISO-8601 UTC instant, not a date-math expression. A relative window "
            "silently stops covering the dataset as the clock advances." % (name, value))

    assert window_from[:10] <= DATASET_FIRST_DAY, (
        "the window opens %s but the dataset starts %s, so the first incident's "
        "evidence is hidden" % (window_from[:10], DATASET_FIRST_DAY))
    assert window_to[:10] >= DATASET_LAST_DAY, (
        "the window closes %s but the dataset runs to %s, so the last incident's "
        "evidence is hidden" % (window_to[:10], DATASET_LAST_DAY))

    # Containment is necessary but not sufficient: a window that reached back
    # years would also "cover" the dataset while showing a student months of
    # nothing. The slack is deliberate but bounded.
    opened = datetime.strptime(window_from[:10], "%Y-%m-%d").date()
    closed = datetime.strptime(window_to[:10], "%Y-%m-%d").date()
    first = datetime.strptime(DATASET_FIRST_DAY, "%Y-%m-%d").date()
    last = datetime.strptime(DATASET_LAST_DAY, "%Y-%m-%d").date()
    assert first - opened <= MAX_WINDOW_SLACK_DAYS, (
        "the window opens %d days before the dataset starts; slack is intended, "
        "an unbounded window is not" % (first - opened).days)
    assert closed - last <= MAX_WINDOW_SLACK_DAYS, (
        "the window closes %d days after the dataset ends; slack is intended, "
        "an unbounded window is not" % (closed - last).days)


def test_the_discover_url_quotes_its_absolute_window():
    """Kibana silently discards an unquoted absolute ISO in its Rison time syntax.

    `_g=(time:(from:2026-09-15T00:00:00.000Z,to:...))` does not parse. The
    picker falls back to "Last 15 minutes", Discover shows zero results, and
    nothing anywhere reports an error - which is precisely how the original
    `now-24h` defect presented. Verified against Kibana 8.13: only the quoted
    form `from:'...'` returns the canonical alerts.

    So the constants stay plain unquoted ISO (the board's saved `timeFrom` is
    compared against them byte for byte) and the quoting happens where the URL
    is serialised. This asserts that split, because getting it wrong is
    invisible until a student clicks the link.
    """
    js = strip_comments(read(LAB_JS))
    window_from, window_to = _lab_js_window()

    # The constants themselves must NOT carry Rison quoting.
    for name, value in (("INVESTIGATION_FROM", window_from),
                        ("INVESTIGATION_TO", window_to)):
        assert not value.startswith("'") and not value.endswith("'"), (
            "%s carries Rison quoting (%r). The constant is compared byte for "
            "byte against the dashboard's saved timeFrom, which stores plain "
            "ISO; quoting belongs in discoverUrl()." % (name, value))

    body = function_body(js, "discoverUrl")
    flat = re.sub(r"\s+", "", body)
    assert "(time:(from:'\"+INVESTIGATION_FROM+\"',to:'\"+INVESTIGATION_TO+\"'))" in flat, (
        "discoverUrl does not serialise the window as (from:'<ISO>',to:'<ISO>'); "
        "Kibana discards an unquoted absolute ISO. Body was %r" % flat)

    # The URL those two constants actually produce, assembled the way
    # discoverUrl does, must carry the quoted form and the current values.
    built = ("_g=(time:(from:'%s',to:'%s'))" % (window_from, window_to))
    assert built == ("_g=(time:(from:'2026-09-15T00:00:00.000Z',"
                     "to:'2026-09-30T23:59:59.999Z'))"), built
    # A control: the unquoted form is the defect this guards against.
    unquoted = "_g=(time:(from:%s,to:%s))" % (window_from, window_to)
    assert built != unquoted and "'" in built and '"' not in built


def _discover_url_for(data_view_id):
    """The exact URL discoverUrl() builds, derived from its source.

    The `return` is a plain `+` concatenation of string literals and four
    identifiers, so it is evaluated here rather than pattern-matched. That
    matters: an earlier version of this helper *assumed* the `dataViewId`
    fragment was present and only looked for `index`, so it happily passed a
    `discoverUrl` that had dropped `dataViewId` altogether.

    Evaluating the expression means the assertions are about the URL a student
    ends up with, not about how the source happens to spell it. No JS runtime is
    required, so the suite keeps its stdlib-only, no-dependency property.
    """
    js = strip_comments(read(LAB_JS))
    window_from, window_to = _lab_js_window()
    body = function_body(js, "discoverUrl")

    values = {
        "KIBANA_URL": "http://localhost:5601",
        "INVESTIGATION_FROM": window_from,
        "INVESTIGATION_TO": window_to,
        "dataViewId": data_view_id,
    }
    expr = re.search(r"return\s+(.*?);", body, re.S)
    assert expr, "discoverUrl has no return statement. Body was %r" % body

    out = []
    for term in expr.group(1).split("+"):
        term = term.strip()
        assert term, "discoverUrl's return has an empty term: %r" % expr.group(1)
        literal = re.match(r"""^(["'])(.*)\1$""", term, re.S)
        if literal:
            out.append(literal.group(2))
            continue
        assert term in values, (
            "discoverUrl concatenates %r, which this helper does not model; "
            "extend it rather than weakening the assertion" % term)
        out.append(values[term])
    return "".join(out)


def test_the_events_discover_link_names_the_events_data_view_explicitly():
    """The events deep-link must carry `index`, not only `dataViewId`.

    Kibana 8.13 honours `index` and merely tolerates `dataViewId`. A `_a` state
    naming only `dataViewId` gets normalised with an `index` of Kibana's own
    choosing, so the link lands on whichever data view Kibana defaults to.
    Measured on a real instance: the events link resolved to `security-alerts-*`
    and displayed 4 documents instead of 9,584, with no error reported anywhere.

    The alerts link resolved correctly by luck, because security-alerts is that
    default. Both are asserted here so neither is left resting on coincidence.
    """
    events = _discover_url_for("siem-normalized-events")
    alerts = _discover_url_for("siem-security-alerts")

    for label, url, dv in (("events", events, "siem-normalized-events"),
                           ("alerts", alerts, "siem-security-alerts")):
        assert "dataViewId:'%s'" % dv in url, (
            "the %s Discover link lost its dataViewId: %s" % (label, url))
        assert "index:'%s'" % dv in url, (
            "the %s Discover link does not name index:'%s'. Kibana 8.13 honours "
            "index and only tolerates dataViewId, so without it this link opens "
            "whichever data view Kibana defaults to - measured: the events link "
            "showed security-alerts-* and 4 documents. Got %s"
            % (label, dv, url))
        # The index must not point at the other data view.
        other = ("siem-security-alerts" if dv == "siem-normalized-events"
                 else "siem-normalized-events")
        assert "index:'%s'" % other not in url, (
            "the %s Discover link points index at %s: %s" % (label, other, url))

    # The fix must not have cost the link its investigation window.
    window_from, window_to = _lab_js_window()
    for label, url in (("events", events), ("alerts", alerts)):
        assert "from:'%s'" % window_from in url, (
            "the %s Discover link lost its window start: %s" % (label, url))
        assert "to:'%s'" % window_to in url, (
            "the %s Discover link lost its window end: %s" % (label, url))
        assert "now-" not in url, (
            "the %s Discover link reintroduced a relative window: %s" % (label, url))


def test_the_dashboard_and_the_deep_links_agree():
    """One window, two artefacts.

    The board's range is generated by scripts/build_dashboard.py and the
    deep-link range lives in lab.js. They are different files in different
    languages, so the agreement cannot come from sharing a constant - it has to
    be asserted.
    """
    js = strip_comments(read(LAB_JS))
    board = read(os.path.join(ROOT, "dashboards", "soc-triage-board.ndjson"))
    from_js = re.search(r"INVESTIGATION_FROM\s*=\s*[\"']([^\"']+)[\"']", js).group(1)
    from_board = re.search(r'"timeFrom":\s*"([^"]+)"', board)
    assert from_board, "the dashboard NDJSON has no timeFrom"
    assert from_js == from_board.group(1), (
        "lab.js opens %s but the board opens %s; a student would get a different "
        "window depending on which link they used" % (from_js, from_board.group(1)))


def test_every_kibana_page_loads_lab_js():
    """Otherwise the shared wiring never runs and the anchors keep href='#'."""
    for page in KIBANA_PAGES:
        html = read(os.path.join(TRAINING, page))
        assert re.search(r'<script src="[^"]*lab\.js"></script>', html), \
            "%s does not load lab.js, so its Kibana links are never wired" % page
