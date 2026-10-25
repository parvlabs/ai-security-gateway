Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Starting AI Security Gateway (AI-WAF Sentinel)" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Dashboard:  http://localhost:8080/dashboard" -ForegroundColor Yellow
Write-Host "  Swagger:    http://localhost:8080/docs" -ForegroundColor Yellow
Write-Host "  Health:     http://localhost:8080/api/health" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Cyan

python -m uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
