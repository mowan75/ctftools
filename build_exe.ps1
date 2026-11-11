# Build script (ASCII only: Windows PowerShell 5.1 reads .ps1 as ANSI)
# Usage: powershell -ExecutionPolicy Bypass -File build_exe.ps1
$ErrorActionPreference = "Stop"

$App = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $App

$Py = "python"
if (Test-Path (Join-Path $App ".venv\Scripts\python.exe")) {
    $Py = Join-Path $App ".venv\Scripts\python.exe"
}

Write-Host "[1/3] PyInstaller build"
& $Py -m PyInstaller --noconfirm --clean --windowed --onedir `
    --name CTF-Misc-Tool `
    --icon "$App\assets\app.ico" `
    --paths "$App\src" `
    --add-data "$App\assets;assets" `
    --collect-all cv2 --collect-all pyzbar --collect-all py7zr `
    --collect-all rapidocr_onnxruntime `
    --hidden-import windnd `
    --distpath "$App\build\dist" `
    --workpath "$App\build\work" `
    --specpath "$App\build\spec" `
    "$App\src\ctfmisc\__main__.py"
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

Write-Host "[2/3] copy artifacts back"
$Dist = Join-Path $App "build\dist\CTF-Misc-Tool"
Copy-Item (Join-Path $Dist "CTF-Misc-Tool.exe") $App -Force
if (Test-Path (Join-Path $App "_internal")) {
    Remove-Item (Join-Path $App "_internal") -Recurse -Force
}
Copy-Item (Join-Path $Dist "_internal") $App -Recurse -Force

# Trim: this tool does no video processing, drop OpenCV ffmpeg backend (~29 MB)
$ffmpeg = Get-ChildItem (Join-Path $App "_internal\cv2") -Filter "opencv_videoio_ffmpeg*.dll" -ErrorAction SilentlyContinue
if ($ffmpeg) { $ffmpeg | Remove-Item -Force }

Write-Host "[3/3] done -> $App\CTF-Misc-Tool.exe"