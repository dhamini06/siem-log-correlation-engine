<#
.SYNOPSIS
    Lab #07 - SIEM Log Correlation Engine setup for Windows PowerShell.

.DESCRIPTION
    Creates the Python virtual environment, installs dependencies, starts the
    Docker stack (Elasticsearch + Kibana), waits for health, and applies the
    index templates.

.EXAMPLE
    .\scripts\setup.ps1
    .\scripts\setup.ps1 -SkipDocker
#>
[CmdletBinding()]
param(
    [switch]$SkipDocker,
    [switch]$SkipVenv
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

function Write-Step($message) {
    Write-Host "`n==> $message" -ForegroundColor Cyan
}

function Test-Command($name) {
    return [bool](Get-Command $name -ErrorAction SilentlyContinue)
}

# --- 1. Python environment -------------------------------------------------
if (-not $SkipVenv) {
    Write-Step "Creating virtual environment (.venv)"
    if (-not (Test-Path .venv)) {
        python -m venv .venv
    }
    Write-Step "Installing dependencies"
    & .\.venv\Scripts\python.exe -m pip install --upgrade pip | Out-Null
    & .\.venv\Scripts\python.exe -m pip install -r requirements.txt
    $Python = ".\.venv\Scripts\python.exe"
} else {
    $Python = "python"
    Write-Step "Skipping virtual environment (using system python)"
}

# --- 2. Docker stack -------------------------------------------------------
if (-not $SkipDocker) {
    if (-not (Test-Command docker)) {
        Write-Error "docker command not found. Install Docker Desktop or re-run with -SkipDocker."
    }

    Write-Step "Starting Elasticsearch and Kibana"
    docker compose up -d

    Write-Step "Waiting for Elasticsearch to report yellow/green (timeout 180s)"
    $deadline = (Get-Date).AddSeconds(180)
    $esReady = $false
    while ((Get-Date) -lt $deadline) {
        try {
            $health = Invoke-RestMethod -Uri "http://localhost:9200/_cluster/health" -TimeoutSec 5
            if ($health.status -in @("yellow", "green")) {
                Write-Host "    Elasticsearch status: $($health.status)"
                $esReady = $true
                break
            }
        } catch {
            Start-Sleep -Seconds 5
        }
    }
    if (-not $esReady) {
        Write-Error "Elasticsearch did not become healthy in time. Check: docker compose logs elasticsearch"
    }

    Write-Step "Waiting for Kibana (timeout 300s)"
    $deadline = (Get-Date).AddSeconds(300)
    $kibanaReady = $false
    while ((Get-Date) -lt $deadline) {
        try {
            $status = Invoke-RestMethod -Uri "http://localhost:5601/api/status" -TimeoutSec 5
            if ($status.status.overall.level -eq "available") {
                Write-Host "    Kibana is available"
                $kibanaReady = $true
                break
            }
        } catch {
            Start-Sleep -Seconds 5
        }
    }
    if (-not $kibanaReady) {
        Write-Warning "Kibana is not available yet. It may still be starting; check http://localhost:5601"
    }
} else {
    Write-Step "Skipping Docker startup (-SkipDocker)"
}

# --- 3. Index templates ----------------------------------------------------
Write-Step "Applying Elasticsearch index templates"
& $Python -m src.main init-templates
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Index templates were not applied. Re-run this script once Elasticsearch is up."
}

Write-Step "Setup complete"
Write-Host @"

Next steps:
  1. Generate sample logs      : $Python -m src.main generate-samples --scenario all
  2. Ingest into Elasticsearch : $Python -m src.main ingest --log-dir .\logs\generated
  3. Run correlation once      : $Python -m src.main correlate --run-once
  4. Run correlation daemon   : $Python -m src.main correlate
  5. Import the SOC dashboard  : $Python -m src.main import-dashboard
  6. Run the test suite        : $Python -m pytest tests -q

Dashboard : http://localhost:5601/app/dashboards#/view/siem-soc-triage-board
"@ -ForegroundColor Green
