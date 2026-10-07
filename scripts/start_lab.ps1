<#
.SYNOPSIS
    BlueCloud Cybersecurity Training Lab - one-command session starter (Windows PowerShell).

.DESCRIPTION
    Runs the full lab for a class session, in order:
      1. Start the Docker stack (Elasticsearch + Kibana)
      2. Wait for both services to be healthy
      3. Install the index templates
      4. Generate the five deterministic sample scenarios
      5. Ingest the samples into Elasticsearch
      6. Run one correlation cycle
      7. Import the SOC Triage Board into Kibana
      8. Start the training platform on http://localhost:8080

    Use .\scripts\setup.ps1 once beforehand for the virtualenv and dependencies.

.EXAMPLE
    .\scripts\start_lab.ps1

.EXAMPLE
    .\scripts\start_lab.ps1 -KeepLabData      # reuse the data already indexed

.EXAMPLE
    .\scripts\start_lab.ps1 -NoTrainingPlatform
#>
[CmdletBinding()]
param(
    [switch]$SkipSamples,
    [switch]$NoTrainingPlatform,
    [switch]$KeepLabData,
    # Which dataset this session is in service of. Auto reads the enterprise
    # generator's own definition from disk and picks accordingly.
    [ValidateSet("Auto", "Enterprise", "Demo")]
    [string]$DatasetMode = "Auto",
    [int]$Port = 8080
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$Python = if (Test-Path .\.venv\Scripts\python.exe) { ".\.venv\Scripts\python.exe" } else { "python" }

function Write-Step($message) {
    Write-Host "`n==> $message" -ForegroundColor Cyan
}

function Wait-For($name, $url, $test, $timeoutSeconds) {
    $deadline = (Get-Date).AddSeconds($timeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $body = Invoke-RestMethod -Uri $url -TimeoutSec 8
            if (& $test $body) { return $true }
        } catch { }
        Start-Sleep -Seconds 5
    }
    throw "$name did not become ready within $timeoutSeconds seconds. Check: docker compose logs"
}

# --- 1. Stack --------------------------------------------------------------
Write-Step "Starting Elasticsearch and Kibana"
. "scripts\ensure_lab_env.ps1" | Out-Null
New-LabEnv -ProjectRoot (Resolve-Path ".")
docker compose up -d
if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }

# --- 2. Health -------------------------------------------------------------
Write-Step "Waiting for Elasticsearch (green/yellow)"
Wait-For "Elasticsearch" "http://localhost:9200/_cluster/health" { param($b) $b.status -in @("green", "yellow") } 180 |
    Out-Null
Write-Host "    Elasticsearch is up"

Write-Step "Waiting for Kibana (available)"
Wait-For "Kibana" "http://localhost:5601/api/status" { param($b) $b.status.overall.level -eq "available" } 300 |
    Out-Null
Write-Host "    Kibana is available"

# --- 3. Templates ----------------------------------------------------------
Write-Step "Applying index templates"
& $Python -m src.main init-templates
if ($LASTEXITCODE -ne 0) { throw "init-templates failed" }

# --- 4-6. Data + correlation ----------------------------------------------
# The dataset this session runs on has to be decided BEFORE anything is
# deleted. A previous version reset whenever Elasticsearch held data, then
# generated the 50-event demonstration fixtures, then tried to ingest them from
# a directory that also held enterprise-14d_*. That directory is refused by the
# ingestion guard, so the reset had already destroyed the approved 9,584-event
# dataset and nothing could put it back. `reset_lab_data.py --print-mode`
# answers the same question the reset itself will enforce, so this stops before
# the destructive step rather than after it.
$resolvedMode = $null
if (-not $SkipSamples) {
    Write-Step "Determining which dataset this session runs on"
    $modeArg = $DatasetMode.ToLower()
    $probe = & $Python scripts/reset_lab_data.py --print-mode --mode $modeArg
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    Refusing to start a data session." -ForegroundColor Red
        Write-Host "    $($probe -join ' ')" -ForegroundColor Red
        Write-Host ""
        Write-Host "    Nothing has been deleted and nothing has been ingested." -ForegroundColor Yellow
        Write-Host "    Fix the rebuild source, or pass -KeepLabData to reuse the data" -ForegroundColor Yellow
        Write-Host "    that is already indexed." -ForegroundColor Yellow
        throw "dataset safety check failed; stopping before any reset"
    }
    $resolvedMode = ($probe | Select-Object -Last 1).Trim()
    Write-Host "    dataset mode: $resolvedMode"
}

if ($SkipSamples) {
    Write-Step "Skipping sample generation and ingestion (-SkipSamples)"
} else {
    # A previous session leaves lab data behind, and the Windows records carry
    # millisecond timestamps, so re-ingesting without a reset appends ~6
    # duplicate events per run and the lab stops matching the answer key.
    # Reset to the canonical state unless the instructor asks to keep it. The
    # mode is passed through so the reset refuses to delete anything it cannot
    # rebuild, whatever --yes says.
    $existing = & $Python -c "from src.elasticsearch_client import get_es_client; e=get_es_client(); print(e.count('normalized-events-*'))" 2>$null
    if ($KeepLabData) {
        Write-Step "Keeping existing lab data (-KeepLabData)"
    } elseif ($existing -and [int]$existing -gt 0) {
        Write-Step "Clearing previous lab data so the session starts clean"
        Write-Host "    Found $existing normalized event(s) from an earlier session."
        & $Python scripts/reset_lab_data.py --yes --mode $resolvedMode
        if ($LASTEXITCODE -ne 0) { throw "reset_lab_data failed" }
    } else {
        Write-Step "No previous lab data found"
    }

    if ($resolvedMode -eq "enterprise") {
        # Named files, never the directory: the per-scenario fixtures share
        # logs/generated, and a directory holding both datasets is refused.
        Write-Step "Ingesting the enterprise dataset by file"
        foreach ($kind in @("auth", "windows", "firewall")) {
            $file = & $Python -c "from src.normalization.enterprise_generator import dataset_paths; print(dataset_paths(r'.\logs\generated')['$kind'])"
            if (-not $file) { throw "could not resolve the enterprise $kind source path" }
            Write-Host "    $file"
            & $Python -m src.main ingest --file $file
            if ($LASTEXITCODE -ne 0) { throw "ingest of $kind failed" }
        }
    } else {
        Write-Step "Generating the five sample scenarios"
        & $Python -m src.main generate-samples --scenario all
        if ($LASTEXITCODE -ne 0) { throw "generate-samples failed" }

        Write-Step "Ingesting samples into Elasticsearch"
        & $Python -m src.main ingest --log-dir .\logs\generated
        if ($LASTEXITCODE -ne 0) { throw "ingest failed" }
    }
}

if ($SkipSamples -or $resolvedMode -ne "enterprise") {
    Write-Step "Running one correlation cycle"
    & $Python -m src.main correlate --run-once
    if ($LASTEXITCODE -ne 0) { throw "correlate failed" }
} else {
    # The enterprise dataset spans fourteen days. `correlate --run-once` scans
    # [now - 120min, now] and would see about an hour of it and produce nothing,
    # so the range backfill is used instead - same rules, same deduplicator,
    # same document ids, only the time range widened.
    Write-Step "Correlating the full enterprise date range"
    & $Python scripts/correlate_range.py --since 2026-09-16T00:00:00Z --until 2026-09-30T00:00:00Z --expect-alerts 4
    if ($LASTEXITCODE -ne 0) { throw "correlate_range failed" }
}

# --- 7. Dashboard ----------------------------------------------------------
Write-Step "Importing the SOC Triage Board"
& $Python -m src.main import-dashboard
if ($LASTEXITCODE -ne 0) { throw "import-dashboard failed" }

Write-Step "Verifying the lab"
& $Python scripts/validate_scenarios.py
if ($LASTEXITCODE -ne 0) { Write-Warning "Scenario validation reported problems (see above)." }

# --- 8. Training platform --------------------------------------------------
if ($NoTrainingPlatform) {
    Write-Host "`nTraining platform not started (-NoTrainingPlatform)." -ForegroundColor Yellow
} else {
    Write-Step "Starting the training platform on port $Port"
    Write-Host "    Press Ctrl+C to stop it." -ForegroundColor DarkGray
    & $Python scripts/serve_training.py --port $Port
}

Write-Host @"

Lab ready.
  Training platform  : http://localhost:$Port
  SOC Triage Board   : http://localhost:5601/app/dashboards#/view/siem-soc-triage-board
  Kibana Discover    : http://localhost:5601/app/discover
  Elasticsearch      : http://localhost:9200
  Instructor guide   : docs\INSTRUCTOR_GUIDE.md

Stop the stack with: docker compose stop
"@ -ForegroundColor Green
