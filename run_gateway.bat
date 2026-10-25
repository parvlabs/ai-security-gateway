@echo off
echo ======================================================================
echo   Starting AI Security Gateway (AI-WAF Sentinel)
echo ======================================================================
echo   Dashboard:  http://localhost:8080/dashboard
echo   Swagger:    http://localhost:8080/docs
echo   Health:     http://localhost:8080/api/health
echo ======================================================================
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
pause
