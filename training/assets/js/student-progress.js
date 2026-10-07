/* Student progress, rendered into the compact home dashboard and the scenarios
 * page.
 *
 * Reads /api/student/progress, which only ever returns the signed-in student's
 * own data. No user id is sent: the server derives it from the session cookie,
 * so there is nothing here to spoof. Every value is written with textContent,
 * so a value that somehow reached the client could not become markup.
 *
 * The scenario titles and links below are duplicated from scenarios.html
 * because the progress payload carries a scenario *id* and nothing else. That
 * duplication is guarded by a test that reads the titles back out of the
 * scenarios page, so the two cannot drift apart unnoticed.
 */
(function () {
  "use strict";

  var API = "/api/student/";

  /* id -> { title, href }. href is relative to a page at the training root,
     which is where both the home page and scenarios.html live. */
  var SCENARIOS = {
    "scenario-1": { title: "Brute Force Investigation",
                    href: "scenarios/scenario-1-brute-force.html" },
    "scenario-2": { title: "Successful Login After Brute Force",
                    href: "scenarios/scenario-2-successful-brute-force.html" },
    "scenario-3": { title: "Suspicious Post-Login Process Execution",
                    href: "scenarios/scenario-3-post-login-execution.html" },
    "scenario-4": { title: "Linux Privilege Escalation & Reverse Shell",
                    href: "scenarios/scenario-4-linux-privilege-escalation.html" },
    "scenario-5": { title: "Multi-Event SOC Investigation",
                    href: "scenarios/scenario-5-multi-event-soc-investigation.html" }
  };

  var STATE_TEXT = {
    not_started: "Not started",
    in_progress: "In progress",
    completed: "Completed"
  };

  function setText(id, value) {
    var el = document.getElementById(id);
    if (el) { el.textContent = value === null || value === undefined ? "-" : String(value); }
  }

  function show(el, visible) {
    if (!el) { return; }
    if (visible) { el.removeAttribute("hidden"); } else { el.setAttribute("hidden", ""); }
  }

  /* "Scenario 01 - Brute Force Investigation" */
  function label(scenarioId) {
    var meta = SCENARIOS[scenarioId];
    var m = /^scenario-(\d+)$/.exec(scenarioId || "");
    var n = m ? ("0" + m[1]).slice(-2) : "";
    return (n ? "Scenario " + n + " - " : "") + (meta ? meta.title : scenarioId);
  }

  /* The number the student can act on: what they got right, out of what they
     actually attempted.

     Deliberately NOT "4 / 7 required". The payload records what this student
     answered, not how many questions the scenario requires, so "correct out of
     required" would read as 0 of 7 for a student who has only just started and
     4 of 7 for one who is nearly done - the number would move backwards as they
     worked. Attempted is a fact this student controls and can verify. */
  function standing(scenario) {
    if (scenario.state === "not_started") { return "Not started yet."; }
    var bits = [];
    if (scenario.questions_attempted) {
      bits.push(scenario.correct_answers + " correct of " +
                scenario.questions_attempted + " attempted");
    } else {
      bits.push("Opened, nothing checked yet");
    }
    if (scenario.assisted_answers) {
      bits.push(scenario.assisted_answers + " assisted");
    }
    if (scenario.last_activity_at) { bits.push("last active " + scenario.last_activity_at); }
    return bits.join(" \u00b7 ") + ".";
  }

  /* ---------------------------------------------------------- the home page */
  function renderDashboard(data) {
    var tiles = [
      ["my-started", data.scenarios_started],
      ["my-questions", data.questions_attempted],
      ["my-correct", data.correct_answers],
      ["my-completed", data.scenarios_completed]
    ];
    tiles.forEach(function (t) { setText(t[0], t[1]); });

    /* Recent activity = whichever scenario the server says was touched last. */
    var recent = null;
    (data.scenarios || []).forEach(function (s) {
      if (s.state === "not_started") { return; }
      if (!recent || (s.last_activity_at || "") > (recent.last_activity_at || "")) {
        recent = s;
      }
    });

    setText("recent-title", recent ? label(recent.scenario_id) : "Nothing started yet");
    setText("recent-detail", recent
      ? STATE_TEXT[recent.state] + " \u00b7 " + standing(recent)
      : "Open a scenario and it will appear here, with how far you got.");

    var last = document.getElementById("recent-activity-last");
    if (last) {
      last.textContent = data.last_activity_at
        ? "Last activity " + data.last_activity_at : "";
      show(last, !!data.last_activity_at);
    }

    var cont = document.getElementById("recent-continue");
    if (cont) {
      show(cont, !!recent);
      if (recent) {
        var meta = SCENARIOS[recent.scenario_id];
        cont.setAttribute("href", meta ? meta.href : "scenarios.html");
        cont.textContent = recent.state === "completed" ? "Review answers" : "Continue";
      }
    }
  }

  /* ------------------------------------------------------- the scenarios page */
  function renderScenarioBadges(data) {
    var byId = {};
    (data.scenarios || []).forEach(function (s) { byId[s.scenario_id] = s; });

    /* Scoped to .scenario-state, and it has to stay scoped.
     *
     * All five scenario pages put data-scenario on the BODY element, because
     * the inline script there reports the scenario open from
     * document.body.getAttribute("data-scenario"). A bare
     * querySelectorAll("[data-scenario]") therefore matched <body> on every
     * scenario page, and the textContent/className assignments below replaced
     * the whole document with one line of text: HTTP 200, 25 KB delivered,
     * zero elements rendered. Scoping to the class means the only elements
     * written to are the badges on scenarios.html. */
    document.querySelectorAll(".scenario-state[data-scenario]").forEach(function (el) {
      var s = byId[el.getAttribute("data-scenario")];
      if (!s) { return; }
      el.textContent = STATE_TEXT[s.state] || s.state;
      el.className = "scenario-state is-" + s.state;
      if (s.state !== "not_started") {
        el.textContent += " \u00b7 " + standing(s);
      }
      show(el, true);
    });
  }

  function load() {
    return fetch(API + "progress", {
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" }
    }).then(function (response) {
      if (response.status === 401) { return null; }
      return response.json().catch(function () { return null; });
    }).then(function (data) {
      if (!data) { return; }
      renderDashboard(data);
      renderScenarioBadges(data);
    });
  }

  function init() {
    /* Same scoping requirement as renderScenarioBadges. On a scenario page the
       bare "[data-scenario]" selector resolves to <body>, which made this
       script fetch and render on a page it has nothing to draw on - and was
       the other half of the blank-page regression. */
    var wanted = document.getElementById("my-progress") ||
                 document.querySelector(".scenario-state[data-scenario]");
    if (!wanted) { return; }
    if (!window.LabAuth || !window.LabAuth.me) { return; }
    // Only a student has progress here. An admin gets 403 on the endpoint and
    // the section simply stays at its placeholders.
    window.LabAuth.me().then(function (user) {
      if (user && user.role === "student") { load(); }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
