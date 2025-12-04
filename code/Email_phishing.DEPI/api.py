# phish_api.py
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pathlib import Path
import shutil
import uuid
import json
import uvicorn

# use our core helpers (make sure phish_core.py exists and defines analyze_bytes & save_report)
try:
    from phish_core import analyze_bytes, save_report
except Exception as e:
    # If import fails, we still start the app but /analyze will return useful error
    analyze_bytes = None
    save_report = None
    IMPORT_ERROR = str(e)
else:
    IMPORT_ERROR = None

BASE = Path(__file__).parent.resolve()
TMP_DIR = BASE / "tmp_uploads"
REPORTS_DIR = BASE / "reports"
TMP_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

app = FastAPI(title="Email Phishing Analyzer API")

# allow local frontend / tests; tighten in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"status": "phish_api running", "import_error": IMPORT_ERROR}

@app.post("/analyze")
async def analyze_eml(file: UploadFile = File(...)):
    # ensure helper exists
    if analyze_bytes is None:
        raise HTTPException(status_code=500, detail=f"analyzer not available: {IMPORT_ERROR}")

    # read bytes from upload safely
    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"failed to read upload: {e}")

    # analyze bytes
    try:
        report = analyze_bytes(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"analysis error: {e}")

    # attach some metadata (optional)
    report.setdefault("_uploaded_filename", file.filename)

    # save report files (JSON + HTML) if save_report available
    try:
        if save_report:
            saved = save_report(report, outdir=str(REPORTS_DIR), as_html=True)
            report["_saved"] = saved
    except Exception as e:
        # non-fatal, include note
        report["_save_error"] = str(e)

    return JSONResponse(content=report)

@app.get("/reports/{name}", response_class=FileResponse)
async def get_report_file(name: str):
    p = REPORTS_DIR / name
    if not p.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(str(p))

if __name__ == "__main__":
    # run directly with python phish_api.py
    uvicorn.run("phish_api:app", host="127.0.0.1", port=8000, reload=True)
# phish_api.py
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pathlib import Path
import shutil
import uuid
import json
import uvicorn

# use our core helpers (make sure phish_core.py exists and defines analyze_bytes & save_report)
try:
    from phish_core import analyze_bytes, save_report
except Exception as e:
    # If import fails, we still start the app but /analyze will return useful error
    analyze_bytes = None
    save_report = None
    IMPORT_ERROR = str(e)
else:
    IMPORT_ERROR = None

BASE = Path(__file__).parent.resolve()
TMP_DIR = BASE / "tmp_uploads"
REPORTS_DIR = BASE / "reports"
TMP_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

app = FastAPI(title="Email Phishing Analyzer API")

# allow local frontend / tests; tighten in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"status": "phish_api running", "import_error": IMPORT_ERROR}

@app.post("/analyze")
async def analyze_eml(file: UploadFile = File(...)):
    # ensure helper exists
    if analyze_bytes is None:
        raise HTTPException(status_code=500, detail=f"analyzer not available: {IMPORT_ERROR}")

    # read bytes from upload safely
    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"failed to read upload: {e}")

    # analyze bytes
    try:
        report = analyze_bytes(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"analysis error: {e}")

    # attach some metadata (optional)
    report.setdefault("_uploaded_filename", file.filename)

    # save report files (JSON + HTML) if save_report available
    try:
        if save_report:
            saved = save_report(report, outdir=str(REPORTS_DIR), as_html=True)
            report["_saved"] = saved
    except Exception as e:
        # non-fatal, include note
        report["_save_error"] = str(e)

    return JSONResponse(content=report)

@app.get("/reports/{name}", response_class=FileResponse)
async def get_report_file(name: str):
    p = REPORTS_DIR / name
    if not p.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(str(p))

if __name__ == "__main__":
    # run directly with python phish_api.py
    uvicorn.run("phish_api:app", host="127.0.0.1", port=8000, reload=True)
