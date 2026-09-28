/* ==========================================================================
   BlueCloud Softech Solutions - SIEM Lab
   Student answer checking.

   Answers are graded by the lab server (POST /api/check). The answer key is
   never present in this file, in the page, or in localStorage: the server
   returns only a verdict per question plus a hint for anything unmatched, and
   the model solution only when the student explicitly asks for it.

   The script degrades safely. If the platform is served by a plain static
   file server instead of scripts/serve_training.py, checking is unavailable
   and the page says so instead of failing silently.
   ========================================================================== */
(function () {
  "use strict";

  var API_CHECK = "/api/check";
  var API_REVEAL = "/api/reveal";
  var REQUEST_TIMEOUT = 15000;

  var STATUS_TEXT = {
    correct: "Correct",
    partial: "Partially correct",
    incorrect: "Needs work",
    self_review: "Your call"
  };

  /* ---------------------------------------------------------------- utils */
  function scenarioId() {
    return document.body.getAttribute("data-scenario");
  }

  function store() {
    try {
      return JSON.parse(window.localStorage.getItem("bluecloud-siem-lab-v1") || "{}") || {};
    } catch (err) {
      return {};
    }
  }

  function save(state) {
    try {
      window.localStorage.setItem("bluecloud-siem-lab-v1", JSON.stringify(state));
    } catch (err) {
      /* storage disabled: grading still works, it just will not persist */
    }
  }

  function collectAnswers() {
    var answers = {};
    var boxes = document.querySelectorAll("textarea[data-question]");
    Array.prototype.forEach.call(boxes, function (box) {
      answers[box.getAttribute("data-question")] = box.value;
    });
    return answers;
  }

  function postJSON(url, payload) {
    var controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    var timer = window.setTimeout(function () {
      if (controller) controller.abort();
    }, REQUEST_TIMEOUT);

    return window.fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller ? controller.signal : undefined
    }).then(function (response) {
      window.clearTimeout(timer);
      return response.json().then(function (body) {
        if (!response.ok) {
          throw new Error((body && body.error) || "HTTP " + response.status);
        }
        return body;
      });
    }, function (err) {
      window.clearTimeout(timer);
      throw err;
    });
  }

  function clear(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  /* ------------------------------------------------------------- rendering */
  function questionRow(id) {
    return document.querySelector('.qlist li[data-question-row="' + id + '"]');
  }

  function paintQuestion(id, result) {
    var row = questionRow(id);
    if (!row) return;

    var status = result.status;
    row.classList.remove("is-correct", "is-partial", "is-incorrect", "is-selfreview");
    if (status === "correct") row.classList.add("is-correct");
    else if (status === "partial") row.classList.add("is-partial");
    else if (status === "self_review") row.classList.add("is-selfreview");
    else row.classList.add("is-incorrect");

    var badge = row.querySelector(".answer-status");
    if (badge) {
      badge.textContent = STATUS_TEXT[status] || status;
      badge.hidden = false;
    }

    var feedback = row.querySelector(".answer-feedback");
    if (!feedback) return;
    clear(feedback);

    (result.parts || []).forEach(function (part) {
      var line = el("li", part.ok ? "fb-ok" : "fb-no");
      line.appendChild(el("span", "fb-mark", part.ok ? "✓" : "✗"));
      line.appendChild(el("span", "fb-label", part.label));
      if (!part.ok && part.hint) {
        line.appendChild(el("span", "fb-hint", part.hint));
      }
      feedback.appendChild(line);
    });

    if (status === "self_review" && result.review_prompt) {
      var self = el("li", "fb-self");
      self.appendChild(el("span", "fb-mark", "✎"));
      self.appendChild(el("span", "fb-label", result.review_prompt));
      feedback.appendChild(self);

      var check = row.querySelector(".self-review-check");
      if (check) {
        check.hidden = false;
        if (result.reviewed) check.checked = true;
      }
    }
  }

  function paintSummary(result) {
    var box = document.getElementById("check-result");
    if (!box) return;
    clear(box);
    box.hidden = false;
    box.className = "callout";

    var s = result.summary;
    var title, tone;
    if (result.verdict === "complete") {
      title = "Scenario completed";
      tone = "callout-ok";
    } else if (result.verdict === "unanswered") {
      title = "Nothing to check yet";
      tone = "callout-warn";
    } else if (s.correct || s.partial) {
      title = "Keep going";
      tone = "callout-warn";
    } else {
      title = "Not there yet";
      tone = "callout-crit";
    }

    box.classList.add(tone);
    box.appendChild(el("span", "callout-title", title));

    var line = el("p", "check-score");
    line.textContent =
      s.correct + " of " + s.required_total + " required questions correct" +
      (s.partial ? ", " + s.partial + " partially correct" : "") +
      (s.incorrect ? ", " + s.incorrect + " still to fix" : "") + ".";
    box.appendChild(line);

    if (result.verdict === "complete") {
      var ok = el("p", "mb0");
      ok.appendChild(document.createTextNode(
        "Every checkable answer is right. Review your written answers below, then mark the scenario complete."
      ));
      box.appendChild(ok);
    } else if (result.verdict === "unanswered") {
      box.appendChild(el("p", "mb0",
        "Fill in at least one answer box, then use Check answers again."));
    } else {
      box.appendChild(el("p", "mb0",
        "Each ✗ line below says which part of the question was not matched. Follow the hint, correct the answer, and check again."));
    }
  }

  function persistProgress(result) {
    var scenario = scenarioId();
    if (!scenario) return;
    var state = store();

    state.results = state.results || {};
    state.results[scenario] = {
      verdict: result.verdict,
      completed: Boolean(result.completed),
      correct: result.summary.correct,
      required_total: result.summary.required_total,
      assisted: Boolean(state.results[scenario] && state.results[scenario].assisted)
    };
    if (result.completed) {
      state.done = state.done || {};
      state.done[scenario] = true;
    }
    save(state);

    if (typeof window.refreshLabProgress === "function") window.refreshLabProgress();
  }

  /* ------------------------------------------------------- completion gate
     "Mark scenario complete" used to be one click away with no verification,
     so a page could claim a completion that was never earned. It now stays
     disabled until a check reports every required answer correct, and is
     re-disabled if the student edits an answer afterwards. */
  function setCompletionGate(completed) {
    var doneBtn = document.getElementById("mark-done");
    if (doneBtn) doneBtn.disabled = !completed;
    var note = document.getElementById("check-gate-note");
    if (note) note.hidden = Boolean(completed);
  }

  function invalidateOnEdit() {
    var boxes = document.querySelectorAll("textarea[data-question]");
    Array.prototype.forEach.call(boxes, function (box) {
      box.addEventListener("input", function () {
        setCompletionGate(false);
        clearCompletion();
        var status = document.getElementById("check-status");
        if (status) status.textContent = "Answers changed - check again";
      });
    });
  }

  /* Editing after the scenario was marked complete withdraws the completion,
     otherwise the page would keep claiming a result that no longer matches the
     answers on screen. */
  function clearCompletion() {
    var scenario = scenarioId();
    if (!scenario) return;
    var state = store();
    if (!state.done || !state.done[scenario]) return;

    state.done[scenario] = false;
    save(state);

    var banner = document.getElementById("done-banner");
    if (banner) banner.style.display = "none";
    var undo = document.getElementById("undo-done");
    if (undo) undo.style.display = "none";
    var doneBtn = document.getElementById("mark-done");
    if (doneBtn) doneBtn.textContent = "Mark scenario complete";
    if (typeof window.refreshLabProgress === "function") window.refreshLabProgress();
  }

  /* ------------------------------------------------------------- checking */
  function checkAnswers() {
    var scenario = scenarioId();
    var button = document.getElementById("check-answers");
    if (!scenario || !button) return;

    var status = document.getElementById("check-status");
    if (status) status.textContent = "Checking...";
    button.disabled = true;

    postJSON(API_CHECK, { scenario: scenario, answers: collectAnswers() })
      .then(function (result) {
        Object.keys(result.questions || {}).forEach(function (id) {
          paintQuestion(id, result.questions[id]);
        });
        paintSummary(result);
        persistProgress(result);
        setCompletionGate(Boolean(result.completed));
        if (status) {
          status.textContent = "Checked " + new Date().toLocaleTimeString();
        }
      })
      .catch(function () {
        var box = document.getElementById("check-result");
        if (box) {
          clear(box);
          box.hidden = false;
          box.className = "callout callout-warn";
          box.appendChild(el("span", "callout-title", "Answer checking is unavailable"));
          box.appendChild(el("p", "mb0",
            "This page is being served without the lab answer service. Start it with " +
            "'python scripts\\serve_training.py' (or 'python3 scripts/serve_training.py' on Linux) " +
            "instead of opening the file directly, then reload. Your answers are still saved in this browser."));
        }
        if (status) status.textContent = "Checking unavailable";
      })
      .then(function () {
        button.disabled = false;
      });
  }

  /* ------------------------------------------------------------- revealing */
  function attachReveal() {
    var buttons = document.querySelectorAll("[data-reveal]");
    Array.prototype.forEach.call(buttons, function (button) {
      button.hidden = false;
      button.addEventListener("click", function () {
        var id = button.getAttribute("data-reveal");
        var row = questionRow(id);
        if (!row) return;

        var existing = row.querySelector(".answer-solution");
        if (existing) {                      // toggle
          existing.hidden = !existing.hidden;
          button.textContent = existing.hidden ? "Show solution" : "Hide solution";
          return;
        }

        button.disabled = true;
        postJSON(API_REVEAL, { scenario: scenarioId(), question: id })
          .then(function (data) {
            var box = row.querySelector(".answer-solution") || el("div", "answer-solution");
            clear(box);
            box.appendChild(el("span", "callout-title", "Model solution" + (data.assisted ? " (assisted)" : "")));
            box.appendChild(el("p", "mb0", data.solution || ""));
            box.hidden = false;
            if (!row.querySelector(".answer-solution")) row.appendChild(box);
            button.textContent = "Hide solution";
            /* Re-enable: the button is a real <button>, so leaving it disabled
               suppressed its click event and the "Hide solution" label became a
               dead control. The solution is cached in the row, so the toggle
               above now handles show/hide without another request. */
            button.disabled = false;

            var state = store();
            state.results = state.results || {};
            state.results[scenarioId()] = state.results[scenarioId()] || {};
            state.results[scenarioId()].assisted = true;
            save(state);
          })
          .catch(function () {
            button.disabled = false;
            button.textContent = "Solution unavailable";
          });
      });
    });
  }

  /* ------------------------------------------------- restore last verdict */
  function restoreLastResult() {
    var scenario = scenarioId();
    if (!scenario) return;
    var state = store();
    var results = state.results || {};
    if (!results[scenario]) return;

    var saved = results[scenario];
    var status = document.getElementById("check-status");
    if (status) {
      status.textContent = saved.completed
        ? "Last checked: all required answers correct"
        : "Last checked: " + (saved.correct || 0) + " of " +
          (saved.required_total || 0) + " required correct";
    }
    /* The gate is re-evaluated on the next Check answers run, so it starts
       closed after a reload even if the last check passed. */
    setCompletionGate(false);
  }

  function init() {
    var button = document.getElementById("check-answers");
    if (button) button.addEventListener("click", checkAnswers);

    invalidateOnEdit();

    /* self-review checkboxes, stored per scenario/question */
    var boxes = document.querySelectorAll(".self-review-check");
    var state = store();
    Array.prototype.forEach.call(boxes, function (box) {
      var id = box.getAttribute("data-self-review");
      var seen = state.reviewed || {};
      var key = scenarioId() + ":" + id;
      box.checked = Boolean(seen[key]);
      box.addEventListener("change", function () {
        var current = store();
        current.reviewed = current.reviewed || {};
        current.reviewed[key] = box.checked;
        save(current);
      });
    });

    attachReveal();
    restoreLastResult();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
