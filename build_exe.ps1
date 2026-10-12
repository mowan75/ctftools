# Build script (ASCII only: Windows PowerShell 5.1 reads .ps1 as ANSI)
# Usage: powershell -ExecutionPolicy Bypass -File build_exe.ps1
$ErrorActionPreference = "Stop"

$App  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent (Split-Path -Parent $App)
$Py   = "C:\Users\kun\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if (-not (Test-Path $Py)) { $Py = "python" }

Write-Host "[1/4] generate icon"
& $Py (Join-Path $Root "tools\make_icon.py")

Write-Host "[2/4] PyInstaller build"
& $Py -m PyInstaller --noconfirm --clean --windowed --onedir `
    --name CTF-Misc-Tool `
    --icon "$App\assets\app.ico" `
    --paths "$App\src" `
    --add-data "$App\assets;assets" `
    --collect-all cv2 --collect-all pyzbar --collect-all py7zr `
    --hidden-import windnd `
    --distpath "$Root\work\exe-dist" `
    --workpath "$Root\work\pyi-build" `
    --specpath "$Root\work\pyi-spec" `
    "$App\src\ctfmisc\__main__.py"

Write-Host "[3/4] copy to release dir"
$Dist = Join-Path $Root "work\exe-dist\CTF-Misc-Tool"
Copy-Item "$Dist\CTF-Misc-Tool.exe" $App -Force
if (Test-Path "$App\_internal") { Remove-Item "$App\_internal" -Recurse -Force }
Copy-Item "$Dist\_internal" $App -Recurse -Force

# Trim: this tool does no video processing, drop OpenCV ffmpeg backend (~29 MB)
$ffmpeg = Get-ChildItem "$App\_internal\cv2" -Filter "opencv_videoio_ffmpeg*.dll" -ErrorAction SilentlyContinue
if ($ffmpeg) { $ffmpeg | Remove-Item -Force }

Write-Host "[4/4] done -> $App\CTF-Misc-Tool.exe"
