/* Instructor dashboard.
 *
 * Every number on this page comes from /api/admin/*, which the server refuses
 * to serve to anyone whose session is not an admin. The page is therefore only
 * ever a renderer: if the fetch fails, the table stays empty rather than
 * showing something invented here.
 *
 * Two habits are deliberate and load-bearing:
 *   - every value from the server is written with textContent, never
 *     innerHTML, so a username can never become markup;
 *   - the role is read back from /api/auth/me for display only. It is never
 *     sent to the server and never trusted for access, which the server has
 *     already decided by the time this runs.
 */
(function () {
  "use strict";

  var API = "/api/admin/";

  function get(path) {
    return fetch(API + path, {
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" }
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (data) {
        return { status: response.status, data: data };
      });
    });
  }

  function text(tag, value, className) {
    var el = document.createElement(tag);
    el.textContent = value === null || value === undefined ? "-" : String(value);
    if (className) { el.className = className; }
    return el;
  }

  function setStat(id, value) {
    var el = document.getElementById(id);
    if (el) { el.textContent = value === null || value === undefined ? "-" : String(value); }
  }

  function fillTable(tableId, rows, config) {
    var table = document.getElementById(tableId);
    if (!table) { return; }
    var body = table.querySelector("tbody");
    if (!body) { return; }
    // The third argument is a descriptor, not the column list. Reading the list
    // off config.columns is the whole point: the previous version read
    // columns.forEach straight off the descriptor, which is not a function, so
    // every table threw on load and rendered empty. The empty-state colSpan is
    // derived from the same list that builds the rows, so the two cannot drift.
    var columns = (config && config.columns) || [];
    body.textContent = "";
    if (!rows || !rows.length) {
      var empty = document.createElement("tr");
      var cell = text("td", config.emptyMessage, "table-empty");
      cell.colSpan = columns.length;
      empty.appendChild(cell);
      body.appendChild(empty);
      return;
    }
    rows.forEach(function (row) {
      var tr = document.createElement("tr");
      columns.forEach(function (column) {
        tr.appendChild(text("td", row[column.field], column.className));
      });
      body.appendChild(tr);
    });
  }

  function init() {
    var who = document.getElementById("admin-identity");
    var status = document.getElementById("admin-status");

    if (!window.LabAuth || !window.LabAuth.me) { return; }

    window.LabAuth.me().then(function (user) {
      // Display only. The server has already authorised this request; if it
      // had not, none of the fetches below would have returned anything.
      if (user && who) {
        who.textContent = user.username + " (" + user.role + ")";
      }
      if (user && user.role !== "admin") {
        if (status) {
          status.textContent = "This account is not an instructor account.";
        }
        return;
      }
      load();
    });

    function load() {
      get("summary").then(function (result) {
        if (result.status === 401 || result.status === 403) {
          if (status) { status.textContent = "Not authorised for the instructor dashboard."; }
          return;
        }
        var data = result.data || {};
        setStat("stat-students", data.total_students);
        setStat("stat-active", data.active_students);
        setStat("stat-started", data.students_who_started);
        setStat("stat-checks", data.attempts);
        setStat("stat-scenarios-started", data.scenarios_started);
        setStat("stat-scenarios-completed", data.scenarios_completed);
        setStat("stat-questions", data.questions_attempted);
        setStat("stat-correct", data.correct_answers);
        setStat("stat-assisted", data.assisted_answers);
        setStat("stat-admins", data.total_admins);
        setStat("stat-live", data.students_with_live_session);
        if (status) { status.textContent = "Updated " + new Date().toLocaleTimeString(); }
      });

      get("scenarios").then(function (result) {
        if (result.status !== 200) { return; }
        fillTable("scenario-table", result.data.scenarios, {
          emptyMessage: "No scenario activity recorded yet.",
          // "checks" is deliberately not shown: with one progress row per
          // student and scenario it is the same number as "students" under a
          // different name.
          columns: [
            { field: "title" },
            { field: "students" },
            { field: "attempts" },
            { field: "questions_attempted" },
            { field: "completions" },
            { field: "correct" },
            { field: "assisted" }
          ]
        });
      });

      get("students").then(function (result) {
        if (result.status !== 200) { return; }
        fillTable("student-table", result.data.students, {
          emptyMessage: "No student accounts yet.",
          columns: [
            { field: "username" },
            { field: "created_at" },
            { field: "scenarios_started" },
            { field: "scenarios_completed" },
            { field: "attempts" },
            { field: "questions_attempted" },
            { field: "correct" },
            { field: "assisted" },
            { field: "last_activity" },
            { field: "is_active", className: "col-active" }
          ]
        });
      });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
