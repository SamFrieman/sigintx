@echo off
REM SIGINTX — Unified dev launcher (Windows)
REM Starts the FastAPI backend + Vite frontend, both logging to ./logs/

setlocal

set ROOT=%~dp0
set LOG_DIR=%ROOT%logs
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

echo [SIGINTX] Starting backend...
start "SIGINTX Backend" cmd /k "cd /d %ROOT%backend && call venv\Scripts\activate && uvicorn main:app --reload --port 8000 2>&1 | tee ..\logs\backend.log"

echo [SIGINTX] Starting frontend...
start "SIGINTX Frontend" cmd /k "cd /d %ROOT%frontend && npm run dev 2>&1 | tee ..\logs\frontend.log"

echo.
echo  Backend  → http://localhost:8000
echo  Frontend → http://localhost:5173
echo  Logs     → %LOG_DIR%\
echo.
echo  Close the two terminal windows to stop all services.
