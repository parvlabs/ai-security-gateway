@echo off
echo ======================================================================
echo   Starting AI Security Gateway (AI-WAF Sentinel)
echo ======================================================================
echo   Dashboard:  http://localhost:8008/dashboard
echo   Swagger:    http://localhost:8008/docs
echo   Health:     http://localhost:8008/api/health
echo ======================================================================
python -m uvicorn app.main:app --host 0.0.0.0 --port 8008 --reload
pause
