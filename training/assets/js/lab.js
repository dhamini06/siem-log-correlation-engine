/* ==========================================================================
   BlueCloud Softech Solutions - SIEM Lab
   Shared behaviour: nav state, reveal hints, local progress + answer notes.
   No frameworks, no network calls. Progress is stored only in the browser.
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
      note.textContent = "Saved in this browser only.";
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
  function initProgressSummary() {
    var el = document.getElementById("progress-summary");
    if (!el) return;
    var state = loadState();
    var done = state.done || {};
    var total = el.getAttribute("data-total") || "5";
    var count = Object.keys(done).filter(function (key) {
      return done[key];
    }).length;
    el.textContent = count + " / " + total + " scenarios completed";
  }

  /* --------------------------------------------------------- nav state */
  function initNav() {
    var here = window.location.pathname.split("/").pop() || "index.html";
    Array.prototype.forEach.call(document.querySelectorAll(".site-nav a"), function (link) {
      var target = (link.getAttribute("href") || "").split("/").pop();
      if (target === here) link.classList.add("active");
    });
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
  function initStackStatus() {
    var host = document.querySelectorAll("[data-es-status]");
    if (!host.length || !window.fetch) return;
    var url = host[0].getAttribute("data-es-status") || "http://localhost:9200";
    fetch(url + "/_cluster/health")
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (body) {
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
    initYear();
  });
})();
