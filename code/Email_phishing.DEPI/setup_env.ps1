# tools/helper_scripts/setup_env.ps1
# Usage: run from project root
param()
Write-Host "Creating virtual environment and installing dependencies..."
python -m venv venv
& .\venv\Scripts\Activate.ps1
pip install --upgrade pip
if (Test-Path requirements.txt) {
    pip install -r requirements.txt
} else {
    Write-Host "No requirements.txt found - please create it."
}
Write-Host "Setup complete. To run API: .\venv\Scripts\Activate.ps1 ; uvicorn service.app:app --reload"
