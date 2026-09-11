@echo off
title Ransomware EDR - Presentation Launcher
echo ======================================================================
echo    RANSOMWARE DETECTION PLATFORM - PRESENTATION LAUNCHER
echo ======================================================================
echo.

cd /d "%~dp0"

echo [1/3] Checking Python Virtual Environment...
if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found at .venv\Scripts\python.exe!
    pause
    exit /b 1
)

echo [2/3] Starting FastAPI Backend on http://127.0.0.1:8000 ...
start "Ransomware Backend API (Port 8000)" cmd /k "cd /d "%~dp0" && .venv\Scripts\python.exe -m uvicorn backend.app:app --host 127.0.0.1 --port 8000"

timeout /t 3 /nobreak >nul

echo [3/3] Starting TanStack React UI on http://localhost:8081 ...
start "Ransomware Web Console (Port 8081)" cmd /k "cd /d "%~dp0ransomweb" && npm run dev -- --port 8081"

timeout /t 3 /nobreak >nul

echo.
echo Launching presentation dashboard in your browser...
start http://localhost:8081/

echo.
echo ======================================================================
echo   READY FOR PANEL PRESENTATION!
echo   - Backend URL:  http://127.0.0.1:8000
echo   - Frontend UI:  http://localhost:8081
echo   - Guide Doc:    PANEL_PRESENTATION_GUIDE.md
echo ======================================================================
echo.
pause
