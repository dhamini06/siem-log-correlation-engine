/* Student answer checking - investigation flow.
 *
 * The worksheet model was: read every question, fill every textarea, press one
 * button, receive a verdict for all of them. That made the page feel like a form
 * rather than an investigation, and it had a second effect worth naming: every
 * check rewrote the recorded verdict for *every* question, so a student who had
 * answered two questions well could not keep those two correct while working on
 * the third.
 *
 * This version checks one objective at a time. Each question carries its own
 * Check answer button; the request names the question, so the server grades that
 * question alone and the response carries no verdict for work the student has
 * not done. Completion needs every evidence question *and* the final finding.
 *
 * Answers are always submitted as the same flat map of question id -> string.
 * A number input, a select, a yes/no choice and an ordered list are all
 * flattened to text here, so the check request format and the grader's
 * containment matching are unchanged. An ordered list is joined with " -> ".
 *
 * The answer key is never present in this file, in the page, or in localStorage.
 * localStorage holds the student's own unsent draft text only, so a refresh
 * does not lose typing; server-side progress is authoritative for verdicts and
 * is what the summary and the completion gate read.
 */
(function () {
  "use strict";

  var API_CHECK = "/api/check";
  var API_REVEAL = "/api/reveal";
  var API_STUDENT = "/api/student";
  var DRAFT_KEY = "bluecloud-siem-lab-v1";
  var ORDER_SEP = " -> ";

  /* ------------------------------------------------------------- utilities */

  function scenarioId() {
    return document.body.getAttribute("data-scenario") || "";
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clear(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function questionRow(id) {
    return document.querySelector('[data-question-row="' + id + '"]');
  }

  function allRows() {
    return Array.prototype.slice.call(
      document.querySelectorAll("[data-question-row]"));
  }

  function isFinding(row) {
    return /f$/.test(row.getAttribute("data-question-row") || "");
  }

  /* ---------------------------------------------------------------- drafts */
  /* Draft only. Never a verdict, never a source of truth for completion. */

  function readDrafts() {
    try {
      return JSON.parse(window.localStorage.getItem(DRAFT_KEY) || "{}") || {};
    } catch (err) {
      return {};
    }
  }

  function writeDrafts(state) {
    try {
      window.localStorage.setItem(DRAFT_KEY, JSON.stringify(state));
    } catch (err) {
      /* storage disabled: grading still works, drafts just do not persist */
    }
  }

  function saveDraft(row, value) {
    var state = readDrafts();
    var key = scenarioId() + ":" + row.getAttribute("data-question-row");
    if (value) { state[key] = value; } else { delete state[key]; }
    writeDrafts(state);
  }

  function loadDraft(row) {
    var state = readDrafts();
    var key = scenarioId() + ":" + row.getAttribute("data-question-row");
    return state[key] || "";
  }

  /* ------------------------------------------------------- reading answers */

  /* The one place that turns whatever control a question has into a string. */
  function readAnswer(row) {
    var control = row.getAttribute("data-control");

    if (control === "ordering") {
      var list = row.querySelector(".ordered-list");
      if (!list) return "";
      var items = Array.prototype.map.call(
        list.querySelectorAll(".ord-label"), function (n) {
          return (n.textContent || "").trim();
        });
      return items.join(ORDER_SEP);
    }

    if (control === "boolean") {
      var chosen = row.querySelector(".btn-choice[aria-pressed='true']");
      var why = row.querySelector(".answer-why");
      var lead = chosen ? (chosen.getAttribute("data-choice") || "") : "";
      var reason = why ? (why.value || "").trim() : "";
      if (!lead && !reason) return "";
      return reason ? lead + " " + reason : lead;
    }

    var field = row.querySelector("[data-question]");
    return field ? (field.value || "").trim() : "";
  }

  function collectAnswers() {
    var out = {};
    allRows().forEach(function (row) {
      var id = row.getAttribute("data-question-row");
      var value = readAnswer(row);
      if (value) out[id] = value;
    });
    return out;
  }

  function paintOrdered(row, value) {
    var list = row.querySelector(".ordered-list");
    if (!list) return;
    if (!value) return;
    var wanted = String(value).split(ORDER_SEP).map(function (s) { return s.trim(); })
      .filter(Boolean);
    var items = Array.prototype.slice.call(list.querySelectorAll("li"));
    items.sort(function (a, b) {
      var ai = wanted.indexOf((a.querySelector(".ord-label").textContent || "").trim());
      var bi = wanted.indexOf((b.querySelector(".ord-label").textContent || "").trim());
      if (ai === bi) return 0;
      if (ai === -1) return 1;
      if (bi === -1) return -1;
      return ai - bi;
    });
    items.forEach(function (item) { list.appendChild(item); });
  }

  /* -------------------------------------------------------------- controls */

  function wireOrdering(row) {
    var list = row.querySelector(".ordered-list");
    if (!list) return;
    list.addEventListener("click", function (event) {
      var button = event.target.closest ? event.target.closest(".ord-move") : null;
      if (!button) return;
      var item = button.parentNode;
      if (button.getAttribute("data-dir") === "up" && item.previousElementSibling) {
        list.insertBefore(item, item.previousElementSibling);
      } else if (button.getAttribute("data-dir") === "down" && item.nextElementSibling) {
        list.insertBefore(item.nextElementSibling, item);
      }
      var hidden = row.querySelector(".ord-value");
      if (hidden) hidden.value = readAnswer(row);
    });
  }

  function wireBoolean(row) {
    var group = row.querySelector(".answer-choice");
    if (!group) return;
    group.addEventListener("click", function (event) {
      var button = event.target.closest ? event.target.closest(".btn-choice") : null;
      if (!button) return;
      var was = button.getAttribute("aria-pressed") === "true";
      Array.prototype.forEach.call(group.querySelectorAll(".btn-choice"), function (b) {
        b.setAttribute("aria-pressed", "false");
      });
      button.setAttribute("aria-pressed", was ? "false" : "true");
      saveDraft(row, readAnswer(row));
    });
  }

  function wireDraft(row) {
    var field = row.querySelector("[data-question]:not(.ord-value)");
    if (!field) return;
    field.addEventListener("input", function () {
      saveDraft(row, readAnswer(row));
      if (row.getAttribute("data-state") === "needs_work") {
        setState(row, "not_started");
      }
    });
  }

  /* ----------------------------------------------------------------- state */

  var STATE_TEXT = {
    not_started: "Not started",
    needs_work: "Needs work",
    correct: "Correct",
    assisted: "Assisted"
  };

  function setState(row, state) {
    row.setAttribute("data-state", state);
    var chip = row.querySelector("[data-state-chip]");
    if (chip) {
      chip.textContent = isFinding(row) && state === "not_started"
        ? "Not submitted"
        : (STATE_TEXT[state] || state);
    }
  }

  /* -------------------------------------------------------------- progress */

  /* "Done" means the question was answered correctly, whether or not the student
   * looked at the model answer first. Assistance is recorded separately and is
   * not a reason to withhold completion - a student who was shown the answer and
   * then wrote a correct one has finished the question. */
  function isDone(state) {
    return state === "correct" || state === "assisted";
  }

  function computeProgress() {
    var evidence = { total: 0, correct: 0, assisted: 0 };
    var finding = { row: null, state: "not_started" };
    allRows().forEach(function (row) {
      var state = row.getAttribute("data-state") || "not_started";
      if (isFinding(row)) {
        finding.row = row;
        finding.state = state;
      } else {
        evidence.total += 1;
        if (state === "correct") evidence.correct += 1;
        else if (state === "assisted") evidence.assisted += 1;
      }
    });
    return { evidence: evidence, finding: finding };
  }

  function paintSummary() {
    var box = document.getElementById("check-result");
    if (!box) return;
    var p = computeProgress();
    var findingDone = p.finding.state === "correct";

    clear(box);
    box.hidden = false;
    box.className = "callout " + (p.evidence.correct === p.evidence.total && findingDone
                                   ? "callout-ok" : "callout-info");

    var done = p.evidence.correct + p.evidence.assisted;
    var allEvidenceDone = done === p.evidence.total;

    box.appendChild(el("span", "callout-title", "Your investigation"));
    box.appendChild(el("p", "mb0",
      "Evidence " + done + "/" + p.evidence.total + " answered correctly" +
      (p.evidence.assisted
        ? " (" + p.evidence.assisted + " with help)" : "") +
      ". Finding: " +
      (findingDone ? "complete"
        : p.finding.state === "needs_work" ? "needs work" : "not submitted") + "."));

    if (allEvidenceDone && !findingDone) {
      box.appendChild(el("p", "mb0",
        "Every evidence question is answered correctly. The scenario is finished " +
        "when you also submit the final analyst finding below."));
    }
    setCompletionGate(allEvidenceDone && findingDone);
  }

  function setCompletionGate(completed) {
    var button = document.getElementById("mark-done");
    if (button) button.disabled = !completed;
    var note = document.getElementById("check-gate-note");
    if (note) {
      note.hidden = Boolean(completed);
    }
    var banner = document.getElementById("done-banner");
    if (banner && completed) banner.style.display = "block";
    if (typeof window.refreshLabProgress === "function") window.refreshLabProgress();
  }

  /* --------------------------------------------------------------- feedback */

  function showFeedback(row, kind, title, lines) {
    var box = row.querySelector("[data-feedback]");
    if (!box) return;
    clear(box);
    box.hidden = false;
    box.className = "q-feedback q-feedback-" + kind;
    box.appendChild(el("p", "q-feedback-title", title));
    lines.forEach(function (line) {
      box.appendChild(el("p", "q-feedback-line", line));
    });
  }

  function hideFeedback(row) {
    var box = row.querySelector("[data-feedback]");
    if (box) { box.hidden = true; clear(box); }
  }

  /* A normal failed check must never contain the answer. It says which part
   * was not matched and offers the hint, nothing more. */
  function paintResult(row, entry) {
    var status = entry.status;
    row.querySelectorAll("[data-hint]").forEach(function (b) { b.hidden = false; });

    if (status === "correct") {
      /* Assistance is sticky. Once the model answer has been shown for this
       * question the record keeps saying so, so answering it correctly
       * afterwards must not quietly erase that the student looked. */
      var wasAssisted = entry.assisted ||
                        row.getAttribute("data-state") === "assisted";
      setState(row, wasAssisted ? "assisted" : "correct");
      showFeedback(row, "ok",
        wasAssisted ? "Correct (answer was shown earlier)" : "Correct",
        ["Checked against the evidence. Move on when you are ready."]);
      return;
    }

    setState(row, "needs_work");
    var unmatched = (entry.parts || []).filter(function (p) { return !p.ok; });
    if (status === "partial") {
      var lines = ["Partly right. Still needed:"];
      unmatched.forEach(function (p) { lines.push("- " + p.label); });
      lines.push("Adjust your answer and check again, or show a hint.");
      showFeedback(row, "partial", "Partly right", lines);
    } else {
      var missed = ["That does not match the evidence yet."];
      if (unmatched.length) {
        missed.push("Look again at:");
        unmatched.forEach(function (p) { missed.push("- " + p.label); });
      }
      missed.push("Use Show a hint if you want a pointer. The answer is not given here.");
      showFeedback(row, "bad", "Not yet", missed);
    }
  }

  function showHint(row, entry) {
    var parts = (entry && entry.parts) || [];
    var hints = [];
    parts.forEach(function (p) {
      if (p.hint && hints.indexOf(p.hint) === -1) hints.push(p.hint);
    });
    if (!hints.length) {
      showFeedback(row, "hint", "Hint",
        ["Re-read the objective, then the alert and the events it points at."]);
      return;
    }
    showFeedback(row, "hint", "Hint",
      hints.concat(["Check your answer again once you have followed it."]));
  }

  /* --------------------------------------------------------------- checking */

  function checkOne(row) {
    var scenario = scenarioId();
    var id = row.getAttribute("data-question-row");
    var button = row.querySelector("[data-check]");
    var status = row.querySelector("[data-check-status]");
    if (!scenario || !id) return;
    if (!readAnswer(row)) {
      if (status) status.textContent = "Enter an answer first";
      showFeedback(row, "bad", "Nothing to check",
        ["Fill in your answer, then choose Check answer."]);
      return;
    }

    if (button) button.disabled = true;
    if (status) status.textContent = "Checking...";

    var payload = { scenario: scenario, questions: [id], answers: {} };
    payload.answers[id] = readAnswer(row);

    postJSON(API_CHECK, payload)
      .then(function (result) {
        var entry = (result.questions || {})[id];
        if (!entry) throw new Error("no verdict returned");
        paintResult(row, entry);
        if (status) status.textContent = "Checked " + new Date().toLocaleTimeString();
        saveDraft(row, "");
        paintSummary();
        refreshServerProgress();
        /* Completion is decided by a whole-scenario check, because only that
         * sees every required question at once. A scoped check deliberately
         * cannot report it. So once the finding - the last required question -
         * is correct, ask for one full check to settle the scenario. Without
         * this the student could satisfy every question and never finish. */
        if (id === findingId()) settleCompletion();
      })
      .catch(function (err) {
        showFeedback(row, "bad", "Checking unavailable",
          ["This page is being served without the lab answer service. Start it with " +
           "'python scripts\\serve_training.py' and reload. Your answer is still saved " +
           "in this browser."]);
        if (status) status.textContent = "Checking unavailable";
      })
      .then(function () {
        if (button) button.disabled = false;
      });
  }

  /* The finding is the last required question, so it is the point at which a
   * whole-scenario verdict becomes meaningful. */
  function findingId() {
    var row = allRows().filter(isFinding)[0];
    return row ? row.getAttribute("data-question-row") : null;
  }

  /* One unscoped check over everything currently on the page. This is the only
   * request that can report completion, and it is made at most once, when the
   * finding has just been answered correctly. */
  function settleCompletion() {
    var scenario = scenarioId();
    if (!scenario) return Promise.resolve();
    return postJSON(API_CHECK, { scenario: scenario, answers: collectAnswers() })
      .then(function (result) {
        setCompletionGate(Boolean(result.completed));
        paintSummary();
      })
      .catch(function () { /* completion settles on the next visit */ });
  }

  /* ---------------------------------------------------------------- reveal */
  /* Unchanged in substance: same endpoint, same gates. Assistance is sticky, so
   * once the model answer has been shown the question stays marked assisted
   * even if the student then answers it correctly. */

  function attachReveal(row) {
    var button = row.querySelector("[data-reveal]");
    if (!button) return;
    button.hidden = false;
    button.addEventListener("click", function () {
      var id = button.getAttribute("data-reveal");
      var existing = row.querySelector(".answer-solution");
      if (existing) {
        existing.parentNode.removeChild(existing);
        button.textContent = "Show the answer";
        return;
      }
      if (button.disabled) return;
      button.disabled = true;
      postJSON(API_REVEAL, { scenario: scenarioId(), question: id })
        .then(function (result) {
          var box = el("div", "answer-solution");
          box.appendChild(el("span", "answer-solution-title", "Model answer"));
          box.appendChild(el("p", "mb0", result.solution || ""));
          if (result.review_prompt) {
            box.appendChild(el("p", "answer-solution-rubric", result.review_prompt));
          }
          row.appendChild(box);
          button.textContent = "Hide the answer";
          setState(row, "assisted");
          paintSummary();
          refreshServerProgress();
        })
        .catch(function (err) {
          showFeedback(row, "bad", "Answer not available",
            [(err && err.message) || "Check your answers first, then try again."]);
        })
        .then(function () { button.disabled = false; });
    });
  }

  /* ------------------------------------------------------ server progress */

  function refreshServerProgress() {
    if (typeof window.refreshLabProgress === "function") window.refreshLabProgress();
  }

  /* Restore verdicts from the server so a reload shows the real state rather
   * than an empty page. Sourced from GET student/progress/<scenario>, which is
   * the only per-question view; it is scoped to the signed-in student by the
   * session, so nothing here can read another student's progress. A question id
   * the server knows but this page no longer carries is skipped, which is what
   * makes the id migration safe. */
  function applyServerProgress(detail) {
    if (!detail || !detail.questions) return false;
    detail.questions.forEach(function (q) {
      var row = questionRow(q.question_id);
      if (!row) return;
      if (q.assisted) { setState(row, "assisted"); return; }
      if (q.last_status === "correct") { setState(row, "correct"); }
      else if (q.last_status) { setState(row, "needs_work"); }
    });
    return Boolean(detail.completed);
  }

  function loadServerProgress() {
    var scenario = scenarioId();
    if (!scenario || !window.LabAuth) { paintSummary(); return; }
    /* Root-relative on purpose. This page is served from /scenarios/, so a
     * relative "student/progress/..." resolves under /scenarios/ and 404s -
     * which silently loses every verdict on reload. */
    fetch(API_STUDENT + "/progress/" + encodeURIComponent(scenario), {
      credentials: "same-origin",
      cache: "no-store"
    })
      .then(function (response) {
        return response.ok ? response.json() : null;
      })
      .then(function (detail) {
        if (detail) setCompletionGate(applyServerProgress(detail));
        paintSummary();
      })
      .catch(function () { paintSummary(); });
  }

  /* ------------------------------------------------------------------ init */

  function postJSON(url, payload) {
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }).then(function (response) {
      return response.json().then(function (body) {
        if (!response.ok) {
          throw new Error((body && body.error) || "request failed");
        }
        return body;
      });
    });
  }

  function init() {
    var legacy = document.getElementById("check-answers");
    if (legacy) legacy.hidden = true;

    allRows().forEach(function (row) {
      wireOrdering(row);
      wireBoolean(row);
      wireDraft(row);
      attachReveal(row);

      var draft = loadDraft(row);
      if (draft) {
        if (row.getAttribute("data-control") === "ordering") {
          paintOrdered(row, draft);
        } else if (row.getAttribute("data-control") === "boolean") {
          var lead = draft.split(" ")[0].toLowerCase();
          var button = row.querySelector('.btn-choice[data-choice="' + lead + '"]');
          if (button) button.setAttribute("aria-pressed", "true");
          var why = row.querySelector(".answer-why");
          if (why) why.value = draft.slice(lead.length).trim();
        } else {
          var field = row.querySelector("[data-question]:not(.ord-value)");
          if (field) field.value = draft;
        }
      }

      var check = row.querySelector("[data-check]");
      if (check) check.addEventListener("click", function () { checkOne(row); });
    });

    var legacyCheck = document.getElementById("check-answers");
    if (legacyCheck) legacyCheck.addEventListener("click", function (e) { e.preventDefault(); });

    loadServerProgress();
    if (typeof window.refreshLabProgress === "function") window.refreshLabProgress();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  /* Exposed for the scenario page and for tests: apply a server progress
   * detail to the queue without going through the network. */
  window.applyInvestigationProgress = applyServerProgress;
})();
