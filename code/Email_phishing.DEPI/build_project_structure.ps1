# build_project_structure.ps1
#
# هذا السكربت يقوم بإنشاء جميع المجلدات والملفات الأساسية لهيكلية SecureMailHQ.
# يجب تشغيله من المجلد الجذري للمشروع.
#

Write-Host "Starting to build SecureMailHQ project structure..." -ForegroundColor Yellow

# --- 1. إنشاء المجلدات الرئيسية ---
$directories = @("core", "service", "tools", "ui", "data/examples", "data/outputs", "infra", "docs", "tests")

foreach ($dir in $directories) {
    # استخدام Test-Path بشكل صريح يجعل الكود أوضح
    if (-not (Test-Path $dir -PathType Container)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        Write-Host "Created directory: $dir" -ForegroundColor Cyan
    } else {
        Write-Host "Directory exists: $dir" -ForegroundColor DarkGray
    }
}

Write-Host "`nDirectories created successfully." -ForegroundColor Green

# --- 2. إنشاء ملفات Python الأساسية والملفات القياسية للمشروع ---

# الملفات الجذرية
New-Item -Path ".gitignore" -ItemType File -Value "`nvenv/`n__pycache__/`n*.pyc`n/data/outputs/*`n*.log`n" | Out-Null
New-Item -Path "README.md" -ItemType File -Value "# SecureMailHQ - Email Security Analyzer" | Out-Null
New-Item -Path "config.ini" -ItemType File -Value "[DEFAULT]`nLOG_LEVEL=INFO`n" | Out-Null
Write-Host "Created root files (.gitignore, README.md, config.ini)." -ForegroundColor Green

# ملفات الـ Core
New-Item -Path "core/__init__.py" -ItemType File -Value "" | Out-Null
New-Item -Path "core/mail_parser.py" -ItemType File -Value "" | Out-Null
New-Item -Path "core/engine.py" -ItemType File -Value "" | Out-Null
New-Item -Path "core/link_inspector.py" -ItemType File -Value "" | Out-Null
New-Item -Path "core/hdr_inspector.py" -ItemType File -Value "" | Out-Null
New-Item -Path "core/text_inspector.py" -ItemType File -Value "" | Out-Null
New-Item -Path "core/attach_inspector.py" -ItemType File -Value "" | Out-Null
Write-Host "Created core files." -ForegroundColor Green

# ملفات الـ Service
New-Item -Path "service/__init__.py" -ItemType File -Value "" | Out-Null
New-Item -Path "service/app.py" -ItemType File -Value "" | Out-Null
New-Item -Path "service/service_core.py" -ItemType File -Value "" | Out-Null
Write-Host "Created service files." -ForegroundColor Green

# ملفات الـ Tools
New-Item -Path "tools/analyzer_cli.py" -ItemType File -Value "" | Out-Null
Write-Host "Created tools files." -ForegroundColor Green

# --- 3. إنشاء ملفات الواجهة الأمامية (UI) ---
New-Item -Path "ui/index.html" -ItemType File -Value "" | Out-Null
New-Item -Path "ui/ui.js" -ItemType File -Value "// JavaScript content goes here" | Out-Null
New-Item -Path "ui/ui.css" -ItemType File -Value "/* CSS content goes here */" | Out-Null
Write-Host "Created UI files." -ForegroundColor Green

Write-Host "`nAll files and directories created. Structure is ready!" -ForegroundColor Green