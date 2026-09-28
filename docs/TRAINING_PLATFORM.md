# Training Platform Guide — BlueCloud Softech Solutions

**Lab #07 — SIEM Log Correlation Engine**
How the student-facing training platform sits on top of the working SIEM, and how to run it.

---

## 1. Objective

The SIEM is the instrument; the training platform is the syllabus. It gives students a branded
entry point, a five-step investigation method, and five scenario briefs — all pointing at the
same live Elasticsearch and Kibana instance. Students never leave the lab to find evidence.

## 2. Architecture

```
                     browser
                        |
   +--------------------+--------------------+
   |                                         |
training/  (static, stdlib server)     Kibana 8.13  :5601
   |                                         |
   |  index.html                             |  SOC Triage Board
   |  instructions.html                      |  security-alerts-*
   |  scenarios/scenario-1..5.html            |  normalized-events-*
   |  assets/css/bluecloud.css               |
   |  assets/js/lab.js                       |
   +--------------------+--------------------+
                        |
              link out (no proxy, no embed)
                        |
                   Elasticsearch 8.13  :9200
                        |
              security-alerts-*  (4 alerts)
              normalized-events-* (50 events)
```

- The training platform is **read-only presentation**: it never proxies, embeds or modifies the
  SIEM. It links out to Kibana with plain URLs.
- No backend, no database, no authentication, no external calls. Student notes live in
  `localStorage` in the student's own browser.
- The answer key is **outside** the served directory (`docs/`), so it cannot be fetched from the
  training server.

## 3. Technology stack

| Layer | Choice | Why |
|---|---|---|
| Pages | Plain HTML5 | No build step, no framework, printable, works in any browser |
| Styling | One hand-written CSS file | Blue/orange theme via CSS custom properties; no CDN |
| Behaviour | One vanilla JS file | Nav state, hint reveal, local progress and notes |
| Server | `http.server` (Python stdlib) | Zero dependencies; identical on Windows and Ubuntu |
| Validation | `scripts/validate_scenarios.py` | Asserts every scenario against live data |

Nothing is fetched from the internet at runtime, so the lab works fully offline.

## 4. Start and stop the lab

```powershell
# One-time environment + Docker stack + index templates
.\scripts\setup.ps1

# Every session after that
.\scripts\start_lab.ps1
```

`start_lab.ps1` performs, in order:

1. `docker compose up -d`
2. wait for Elasticsearch green and Kibana available
3. `python -m src.main init-templates`
4. **clear any previous session's lab data** (see "Why a reset" below), unless `-KeepLabData`
5. `python -m src.main generate-samples --scenario all`
6. `python -m src.main ingest --log-dir .\logs\generated`
7. `python -m src.main correlate --run-once`
8. `python -m src.main import-dashboard`
9. `python scripts/validate_scenarios.py`
10. `python scripts/serve_training.py` (training platform on <http://localhost:8080>)

### Why a reset is part of starting a session

The lab must always present the same dataset: **50 normalized events and 4 alerts**, which is
what the five scenarios and the answer key are written against.

Re-running the pipeline *without* a reset does not reproduce that state. The Windows sample
records carry millisecond timestamps taken from the clock at generation time, so their
deterministic document IDs change on every run and roughly six duplicate events accumulate per
session (measured: 50 → 56 → 62 → 68 …). Alerts stay at 4 only because deduplication suppresses
them, so the drift is easy to miss — but the event count no longer matches the answer key and
`validate_scenarios.py` will fail.

`scripts/reset_lab_data.py` clears only the two regenerable lab indices and the dedup cache. It
never touches the Elasticsearch or Kibana volumes, index templates, data views, dashboards, or
the correlation configuration.

```powershell
python scripts\reset_lab_data.py          # shows what it would delete, refuses
python scripts\reset_lab_data.py --yes    # performs the reset
```

To stop:

```powershell
# Training platform: Ctrl+C in its window
# SIEM stack (data is preserved in Docker volumes)
docker compose stop
```

## 5. URLs

| Purpose | URL |
|---|---|
| Training platform | <http://localhost:8080> |
| SOC Triage Board | <http://localhost:5601/app/dashboards#/view/siem-soc-triage-board> |
| Kibana Discover | <http://localhost:5601/app/discover> |
| Kibana Dashboards | <http://localhost:5601/app/dashboards> |
| Elasticsearch | <http://localhost:9200> |

## 6. How students use the lab

| Step | Where | What they do |
|---|---|---|
| 1 | `instructions.html` | Learn the schema, the three rules, and the nine required identifications |
| 2 | SOC Triage Board | Survey the alert population: count, severity split |
| 3 | SOC Triage Board | Read alert `reasoning` and open `evidence_event_ids` |
| 4 | `scenarios/scenario-N-*.html` | Read the brief: objective, story, initial knowledge, task |
| 5 | Kibana Discover | Query the `normalized-events-*` data view; read `raw_event` |
| 6 | Scenario page | Answer each question in the notepad; reveal hints progressively |
| 7 | Scenario page | Write the security finding; mark the scenario complete |

The platform enforces no answers — it only records what the student types and tracks progress in
their browser. That is deliberate: the assessment is the reasoning, and the instructor holds the key.

## 7. The five scenarios

| # | Scenario | Rule under test | Difficulty | Alert |
|---|---|---|---|---|
| 1 | Brute Force Investigation | `brute_force` | Easy | high |
| 2 | Successful Login After Brute Force | `successful_brute_force` | Medium | critical |
| 3 | Suspicious Post-Login Process Execution | `suspicious_process_post_login` | Medium | high |
| 4 | Linux Privilege Escalation & Reverse Shell | `privilege_escalation` + rule 3 | Hard | high |
| 5 | Multi-Event SOC Investigation | all three | Hard | capstone |

Each scenario is validated against live data. The two deliberate teaching traps are:

- **`svc_backup`** (Scenario 1 / 5) — 4 failures then a success, *below* the 5-failure threshold.
- **`app-02` PowerShell** (Scenario 5) — a suspicious binary 30 minutes after login, *outside* the
  2-minute window.

Both correctly produce no alert, and Scenario 5 requires students to explain why.

## 8. Instructor workflow

1. Run `.\scripts\start_lab.ps1` and confirm the board shows 4 alerts.
2. Run `python scripts\validate_scenarios.py` — all checks must pass.
3. Open `docs/INSTRUCTOR_GUIDE.md`: scenario objectives, expected findings, evidence, expected
   investigation path, hints ladder, common student mistakes and the rubric.
4. Brief the class, then hand out the landing page URL.
5. Debrief using the guide's per-scenario notes and the username-normalisation aside in Scenario 3.

**Do not re-run `correlate` mid-session.** Deduplication will suppress the existing alerts and the
board will look empty. If you must, delete `data\dedup-cache.json` first.

## 8a. Answer checking

The platform grades student answers **server-side**, so the key never reaches the browser.

| Piece | Location | Reachable by a student? |
|---|---|---|
| `docs/answer-key.json` | machine-readable form of the instructor answer key | **No** — outside the `training/` root |
| `scripts/answer_grader.py` | the grading logic | **No** — imported only by the server |
| `POST /api/check` | verdict plus hints for a submission | yes, this is the endpoint |
| `POST /api/reveal` | model solution for one question, on request | yes, only when asked |
| `training/assets/js/lab-check.js` | the student-facing workflow | yes — contains no answers |

`scripts/serve_training.py` grew a `do_POST` handler for those two endpoints. It still uses only
the Python standard library, and static serving is unchanged. Nothing was added to
`requirements.txt` and there is no database.

### What a submission returns

```json
{
  "verdict": "in_progress",
  "completed": false,
  "summary": {"correct": 5, "partial": 1, "incorrect": 1, "self_review": 2,
              "answered": 9, "required_total": 7, "required_correct": 5},
  "questions": {
    "q1": {"status": "correct", "required": true,
           "parts": [{"label": "source IP", "ok": true},
                     {"label": "target host", "ok": true}]}
  }
}
```

An unmatched part returns a `hint` and **never** the accepted value. The `solution` string is
omitted unless the student presses *Show solution*, which flags the scenario as assisted.

### How grading works

Answers are free text, so a part is satisfied by **containment after normalisation**, not exact
equality. Normalisation folds case, unifies the dashes and quotes people actually type, collapses
whitespace, and treats `_`, `-`, `.` and spaces as interchangeable inside identifiers — so
`brute_force`, `brute force` and `Brute-Force` all match. Short numeric tokens respect word
boundaries, so a required `5` is not satisfied by `15`.

Two guards stop it being too loose:

- **Refusals are not attempts.** `"no idea"`, `"idk"`, `"?"`, `"n/a"` and similar count as
  unanswered. Without this, `"no idea"` would pass a yes/no question, because `"no"` is the
  expected negative answer.
- **Hints never contain answers.** `tests/test_answer_validation.py` asserts that no label or hint
  states a value the scenario page does not already display, and that no hint echoes the solution.

Adjust what is graded by editing `docs/answer-key.json` — no code change needed. Each question
carries `required: true` for machine-checked parts and `required: false` for self-reviewed ones.

### What is deliberately not graded

Excluded because the sample generator re-bases them on every session, so grading them would mark
correct students wrong:

- absolute UTC timestamps
- PIDs (the `winlogon.exe` parent PID differs on each run)
- the interpretation and "final finding" questions, which are self-reviewed with a checkbox

Completion therefore requires every machine-checked question to be correct. The self-reviewed
questions carry their own checkbox and a review prompt.

### Serving statically instead

A purely static deployment (nginx serving `training/`) has no answer checking; the pages detect
this and point the student at `scripts/serve_training.py`. To keep checking behind nginx, route
`/api/` to this script and serve everything else as static files.

The instructor key itself is in `docs/INSTRUCTOR_GUIDE.md` and must never be copied into
`training/`. `tests/test_answer_validation.py` fails the build if it is.


## 9. Verifying before class

```powershell
python scripts\validate_scenarios.py     # 124 checks: data, alerts, pages, Kibana
python -m pytest tests -q                # full suite
docker compose ps                        # both containers healthy
```

## 10. Ubuntu deployment notes

The training platform is static, so it drops onto any web server. The SIEM itself is unchanged
and portable (Lab #07 requirement: no application code changes).

```bash
# 1. SIEM stack — unchanged from the lab
docker compose up -d

# 2. Option A: serve the platform with the bundled stdlib server under a service
python3 scripts/serve_training.py --host 0.0.0.0 --port 8080

# 2b. Option B: nginx (recommended for a classroom)
sudo cp -r training /var/www/bluecloud-lab
sudo tee /etc/nginx/sites-available/bluecloud-lab >/dev/null <<'EOF'
server {
    listen 80;
    server_name _;
    root /var/www/bluecloud-lab;
    index index.html;
    location / { try_files $uri $uri/ =404; }
}
EOF
sudo ln -s /etc/nginx/sites-available/bluecloud-lab /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# 3. Same pipeline, unchanged
python3 -m src.main init-templates
python3 -m src.main generate-samples --scenario all
python3 -m src.main ingest --log-dir ./logs/generated
python3 -m src.main correlate --run-once
python3 -m src.main import-dashboard
```

Notes for a shared classroom server:

- Keep the same `mem_limit` values: Elasticsearch needs **2 GB** with a pinned 512 MB heap, Kibana
  768 MB. Under-provisioning Elasticsearch gets it OOM-killed (exit 137) and the dashboard goes
  blank.
- Pin the lab URL in `training/index.html` if Kibana is not on `localhost:5601` for students.
- `data/dedup-cache.json` must be on persistent storage, or suppression resets on restart.
- Do not put the platform behind the same origin as Kibana; students should see two clearly
  separate tools, which mirrors real SOC tooling.

## 11. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Training platform will not start | Port busy — it auto-selects the next free port. Or run `python scripts\serve_training.py --port 8081`. |
| `Could not find the data view: -` on the board | Saved objects did not import. Run `python -m src.main import-dashboard`, then `python scripts\build_dashboard.py --check`. |
| Board panels blank / stuck loading | Elasticsearch was OOM-killed. Check `docker compose logs elasticsearch \| Select-String "exit code 137"` and `docker stats es`. |
| No alerts after a re-run | Deduplication suppressed them. `Remove-Item .\data\dedup-cache.json`, then re-run `correlate --run-once`. |
| Alerts older than the time picker | Regenerate samples so timestamps are recent, and widen the board's time range. |
| Scenario answer does not match the data | Run `python scripts\validate_scenarios.py`; it re-asserts every answer key value against the live cluster. |
| Student notes lost | Notes live in `localStorage` only; a different browser or cleared cache loses them. |
| Styling looks unstyled | The CSS did not load — confirm `training/assets/css/bluecloud.css` is present and reachable. |
