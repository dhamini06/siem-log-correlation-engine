/* ==========================================================================
   BlueCloud Softech Solutions - SIEM Lab
   Shared behaviour: nav state, reveal hints, local answer drafts, and the
   Kibana deep-links every page points at.
   No frameworks, no network calls. Only the answer drafts and the local
   scenario-complete toggle are stored in the browser; real progress is
   server-side (see student-progress.js).
   ========================================================================== */
(function () {
  "use strict";

  var STORE_KEY = "bluecloud-siem-lab-v1";

  /* ------------------------------------------------------ local state */
  function loadState() {
    try {
      return JSON.parse(window.localStorage.getItem(STORE_KEY) || "{}") || {};
    } catch (err) {
      return {};
    }
  }

  function saveState(state) {
    try {
      window.localStorage.setItem(STORE_KEY, JSON.stringify(state));
    } catch (err) {
      /* private mode / disabled storage: the lab still works, just no memory */
    }
  }

  function markDirty() {
    var note = document.getElementById("saved-note");
    if (note) {
      note.classList.add("show");
      /* Accurate, and deliberately narrow: only the answer drafts live here.
         Scenario progress (started / attempted / correct / assisted /
         completed) is written to the server by student-progress.js. */
      note.textContent = "Draft saved in this browser. Progress saves to your account.";
    }
  }

  /* ------------------------------------------------- answer notepads */
  function initAnswerBoxes() {
    var boxes = document.querySelectorAll("textarea[data-question]");
    if (!boxes.length) return;
    var state = loadState();
    var page = document.body.getAttribute("data-scenario") || "shared";

    Array.prototype.forEach.call(boxes, function (box) {
      var key = page + ":" + box.getAttribute("data-question");
      if (state.answers && state.answers[key]) box.value = state.answers[key];
      box.addEventListener("input", function () {
        var current = loadState();
        current.answers = current.answers || {};
        current.answers[key] = box.value;
        saveState(current);
        markDirty();
      });
    });
  }

  /* -------------------------------------------- scenario done tracking */
  function initScenarioState() {
    var scenario = document.body.getAttribute("data-scenario");
    if (!scenario) return;

    var state = loadState();
    var done = Boolean(state.done && state.done[scenario]);
    var doneBtn = document.getElementById("mark-done");
    var undoBtn = document.getElementById("undo-done");

    function paint() {
      if (doneBtn) {
        doneBtn.textContent = done ? "Completed" : "Mark scenario complete";
        doneBtn.classList.toggle("btn-outline", done);
        doneBtn.classList.toggle("btn-primary", !done);
      }
      if (undoBtn) undoBtn.style.display = done ? "inline-flex" : "none";
      var banner = document.getElementById("done-banner");
      if (banner) banner.style.display = done ? "block" : "none";
    }

    if (doneBtn) {
      doneBtn.addEventListener("click", function () {
        var current = loadState();
        current.done = current.done || {};
        current.done[scenario] = !current.done[scenario];
        saveState(current);
        done = Boolean(current.done[scenario]);
        paint();
      });
    }
    if (undoBtn) {
      undoBtn.addEventListener("click", function () {
        var current = loadState();
        current.done = current.done || {};
        current.done[scenario] = false;
        saveState(current);
        done = false;
        paint();
      });
    }
    paint();
  }

  /* ----------------------------------------- landing page progress ring */
  function paintProgressSummary() {
    var el = document.getElementById("progress-summary");
    if (!el) return;
    var state = loadState();
    var done = state.done || {};
    var total = el.getAttribute("data-total") || "5";
    var count = Object.keys(done).filter(function (key) {
      return done[key];
    }).length;
    el.textContent = count + " / " + total + " scenarios completed";
    el.classList.toggle("chip-ok", count > 0);
  }

  function initProgressSummary() {
    paintProgressSummary();
  }

  /* Lets the answer checker refresh the counter the moment a scenario is
     completed, without reloading the page. */
  window.refreshLabProgress = paintProgressSummary;

  /* --------------------------------------------------------- nav state */
  /* Marks the current page in the nav. Falls back to the containing section,
     because a scenario page's own filename is not a nav destination: without
     the fallback every scenario page showed no active item at all, so the nav
     gave no sense of "you are inside Scenarios". */
  function initNav() {
    var path = window.location.pathname;
    var here = path.split("/").pop() || "index.html";
    var dir = path.split("/").slice(-2, -1)[0] || "";
    var links = Array.prototype.slice.call(document.querySelectorAll(".site-nav a"));

    function mark(match) {
      links.forEach(function (link) {
        if (match(link)) link.classList.add("active");
      });
    }
    function targetOf(link) {
      return (link.getAttribute("href") || "").split("/").pop() || "";
    }

    mark(function (link) { return targetOf(link) === here; });
    if (dir) {
      mark(function (link) {
        return targetOf(link).replace(/\.html$/, "") === dir;
      });
    }
  }

  /* ------------------------------------------------- open all / hints */
  function initExpandAll() {
    var btn = document.getElementById("toggle-hints");
    if (!btn) return;
    btn.addEventListener("click", function () {
      var boxes = document.querySelectorAll("details.hint");
      var anyClosed = false;
      Array.prototype.forEach.call(boxes, function (box) {
        if (!box.open) anyClosed = true;
      });
      Array.prototype.forEach.call(boxes, function (box) {
        box.open = anyClosed;
      });
      btn.textContent = anyClosed ? "Hide all hints" : "Show all hints";
    });
  }

  /* ------------------------------------------- live SIEM reachability */
  /* Asks this same-origin server, which relays Elasticsearch's cluster health.
     A direct browser request to http://localhost:9200 cannot work: it is a
     cross-origin request and Elasticsearch sends no Access-Control-Allow-Origin
     header, so the browser blocks the response and the old code reported
     "not reachable" against a perfectly healthy cluster. The relay is a single
     request per page load, with no retries. */
  function initStackStatus() {
    var host = document.querySelectorAll("[data-es-status]");
    if (!host.length || !window.fetch) return;
    fetch("/api/es-status")
      .then(function (r) { return r.json(); })
      .then(function (body) {
        if (!body || body.ok !== true) return Promise.reject(new Error("unreachable"));
        Array.prototype.forEach.call(host, function (el) {
          el.textContent = "Elasticsearch " + body.status;
          el.classList.remove("chip-light");
          el.classList.add("chip-ok");
        });
      })
      .catch(function () {
        Array.prototype.forEach.call(host, function (el) {
          el.textContent = "Elasticsearch not reachable - start it with: docker compose up -d";
          el.classList.remove("chip-light");
          el.classList.add("chip-warn");
        });
      });
  }

  /* ------------------------------------------------- Kibana deep-links
     Single source of truth for the lab endpoints, so each URL lives only
     here. Every page used to carry its own copy of this block with its own
     literal time range: eight copies of a value that has to agree is eight
     chances to disagree, and they did. The dataset spans fourteen days
     (2026-09-16 to 2026-09-29) while the pages still asked Discover for the
     last 24 hours, which showed 511 of 9,584 events and none of the four
     alerts. The window now exists once.

     data-kibana-dash    -> the SOC Triage Board, the student's alert queue
     data-kibana-link    -> Discover, already pointed at normalized-events-*
     data-kibana-alerts  -> Discover, already pointed at security-alerts-*
     data-es-link        -> the Elasticsearch API
     Students are never sent to Kibana's generic home screen. */
  var ELASTICSEARCH_URL = "http://localhost:9200";
  var KIBANA_URL = "http://localhost:5601";
  var DASHBOARD_ID = "siem-soc-triage-board";
  var EVENTS_DATA_VIEW = "siem-normalized-events";
  var ALERTS_DATA_VIEW = "siem-security-alerts";

  /* The investigation window, and why it is absolute rather than relative.

     The dataset is intentionally immutable: 9,584 events over 2026-09-16
     00:01:07Z .. 2026-09-29 23:57:07Z, generated from one fixed seed and one
     fixed base timestamp so every cohort investigates byte-identical
     evidence. Nothing about that dataset moves, so a window expressed
     relative to "now" is the wrong shape: `now-15d` covered the dataset on
     the day it was built and silently stopped covering it as the clock
     advanced, which is exactly how the SOC Triage Board came to show 3 of the
     4 canonical alerts instead of 4. An absolute window cannot age.

     The bounds carry a day of slack on each side so containment does not
     depend on the exact first and last event. They must contain the whole
     dataset, and they must be changed deliberately, together, if the dataset
     is ever deliberately re-anchored.

     Kibana's Rison time syntax requires an absolute ISO timestamp to be
     quoted; an unquoted one is silently discarded and the picker falls back
     to "Last 15 minutes", i.e. zero results. Verified against Kibana 8.13:
     only `from:'...'` works. So the constants below stay plain unquoted ISO
     (they are compared byte-for-byte against the board's saved `timeFrom`)
     and discoverUrl() does the quoting at the point of serialisation. */
  var INVESTIGATION_FROM = "2026-09-15T00:00:00.000Z";
  var INVESTIGATION_TO = "2026-09-30T23:59:59.999Z";

  /* Build a Discover URL for one data view, over the absolute window.

     The `index` beside `dataViewId` is not redundant and must not be dropped.
     Kibana 8.13 normalises a `_a` state that names only `dataViewId` by adding
     an `index` of its own choosing, and `index` is the field it actually
     honours. Measured on a real instance: with `dataViewId` alone, the events
     link resolved to security-alerts-* and showed 4 documents instead of 9,584,
     silently and with no error anywhere. Adding `index` makes the state
     explicit and the link lands on the data view it names. The alerts link
     already resolved correctly by luck - it happens to be the data view
     Kibana defaults to - so this changes nothing observable for it and makes it
     correct for the same reason rather than by accident. */
  function discoverUrl(dataViewId) {
    return KIBANA_URL + "/app/discover#/?_g=(time:(from:'" + INVESTIGATION_FROM +
           "',to:'" + INVESTIGATION_TO + "'))" +
           "&_a=(dataSource:(dataViewId:'" + dataViewId + "',type:dataView)" +
           ",index:'" + dataViewId + "')";
  }

  function initKibanaLinks() {
    var targets = [
      ["[data-kibana-dash]", KIBANA_URL + "/app/dashboards#/view/" + DASHBOARD_ID],
      ["[data-kibana-link]", discoverUrl(EVENTS_DATA_VIEW)],
      ["[data-kibana-alerts]", discoverUrl(ALERTS_DATA_VIEW)],
      ["[data-es-link]", ELASTICSEARCH_URL],
    ];
    targets.forEach(function (pair) {
      document.querySelectorAll(pair[0]).forEach(function (el) {
        el.href = pair[1];
        el.target = "_blank";
        el.rel = "noopener";
      });
    });
  }

  function initYear() {
    var el = document.getElementById("year");
    if (el) el.textContent = String(new Date().getFullYear());
  }

  document.addEventListener("DOMContentLoaded", function () {
    initNav();
    initAnswerBoxes();
    initScenarioState();
    initProgressSummary();
    initExpandAll();
    initStackStatus();
    initKibanaLinks();
    initYear();
  });
})();
