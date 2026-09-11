# Ransomware Detection Platform - One-Click Presentation Launcher (PowerShell)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   RANSOMWARE DETECTION PLATFORM - PRESENTATION LAUNCHER" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# Check Python environment
$PythonExe = Join-Path $ScriptDir ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    Write-Host "[ERROR] Python virtual environment not found at $PythonExe" -ForegroundColor Red
    Exit 1
}

# Start Backend
Write-Host "[1/3] Starting FastAPI Backend on http://127.0.0.1:8000 ..." -ForegroundColor Green
Start-Process -FilePath "cmd.exe" -ArgumentList "/k cd /d `"$ScriptDir`" && `"$PythonExe`" -m uvicorn backend.app:app --host 127.0.0.1 --port 8000" -WindowStyle Normal

Start-Sleep -Seconds 3

# Start Frontend
Write-Host "[2/3] Starting TanStack React Frontend on http://localhost:8081 ..." -ForegroundColor Green
$FrontendDir = Join-Path $ScriptDir "ransomweb"
Start-Process -FilePath "cmd.exe" -ArgumentList "/k cd /d `"$FrontendDir`" && npm run dev -- --port 8081" -WindowStyle Normal

Start-Sleep -Seconds 3

# Open Browser
Write-Host "[3/3] Launching Web UI in default browser..." -ForegroundColor Green
Start-Process "http://localhost:8081/"

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   READY FOR PANEL PRESENTATION!" -ForegroundColor Cyan
Write-Host "   - Backend API: http://127.0.0.1:8000" -ForegroundColor Yellow
Write-Host "   - Frontend UI: http://localhost:8081" -ForegroundColor Yellow
Write-Host "   - Guide Doc:   PANEL_PRESENTATION_GUIDE.md" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
