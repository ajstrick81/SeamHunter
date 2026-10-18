# apk-autopsy installer / updater for Windows.
# Double-click install.cmd (or: powershell -ExecutionPolicy Bypass -File install.ps1).
# Installs to %LOCALAPPDATA%\apk-autopsy\app, puts `autopsy` on your user PATH, backs up any
# previous version to %LOCALAPPDATA%\apk-autopsy\versions, and runs the self-test.
# Re-running it with a newer zip's copy is the same as `autopsy update`.
param([string]$Root = $(if ($env:APK_AUTOPSY_HOME) { $env:APK_AUTOPSY_HOME } else { Join-Path $env:LOCALAPPDATA 'apk-autopsy' }))
$ErrorActionPreference = 'Stop'
$OnWindows = ($env:OS -eq 'Windows_NT')
$src = $PSScriptRoot
$app = Join-Path $Root 'app'
$bin = Join-Path $Root 'bin'

function Find-Python {
    foreach ($c in @(@('py', '-3'), @('python'), @('python3'))) {
        $exe = Get-Command $c[0] -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        $args_ = @($c[1..($c.Length)] | Where-Object { $_ }) + @('-c', 'import sys; print(sys.version_info[0]*100+sys.version_info[1]); print(sys.executable)')
        try { $out = & $exe.Source @args_ 2>$null } catch { continue }
        if ($LASTEXITCODE -eq 0 -and $out -and [int]$out[0] -ge 309) { return $out[1] }
    }
    return $null
}

Write-Host "apk-autopsy installer" -ForegroundColor Cyan
$py = Find-Python
if (-not $py) {
    Write-Host "Python 3.9+ not found." -ForegroundColor Yellow
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $ans = Read-Host "Install Python 3.12 with winget now? [Y/n]"
        if ($ans -eq '' -or $ans -match '^[Yy]') {
            winget install -e --id Python.Python.3.12 --scope user --accept-package-agreements --accept-source-agreements
            $env:Path = [Environment]::GetEnvironmentVariable('Path', 'User') + ';' + [Environment]::GetEnvironmentVariable('Path', 'Machine')
            $py = Find-Python
        }
    }
    if (-not $py) { throw "Install Python 3.9+ from https://www.python.org/downloads/ (tick 'Add to PATH'), then run this again." }
}
Write-Host "Python: $py"

$newVer = (Select-String -Path (Join-Path $src 'autopsy\__init__.py') -Pattern '__version__ = "(.+)"').Matches[0].Groups[1].Value
New-Item -ItemType Directory -Force -Path $app, $bin | Out-Null

$initPy = Join-Path $app 'autopsy\__init__.py'
if (Test-Path $initPy) {
    $oldVer = (Select-String -Path $initPy -Pattern '__version__ = "(.+)"').Matches[0].Groups[1].Value
    $bak = Join-Path $Root ("versions\{0}-{1}" -f $oldVer, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Force -Path $bak | Out-Null
    Get-ChildItem $app -Force | Where-Object { $_.Name -ne '.git' } | Copy-Item -Destination $bak -Recurse -Force
    Write-Host "Backed up $oldVer -> $bak"
}

$payload = 'autopsy', 'tests', 'docs', 'assets', 'README.md', 'CHANGELOG.md', 'autopsy_main.py', 'autopsy.bat', 'autopsy.sh', 'pyproject.toml', 'install.ps1', 'install.cmd', '.gitignore', 'HANDOFF.md'
foreach ($p in $payload) {
    $s = Join-Path $src $p
    if (-not (Test-Path $s)) { continue }
    $d = Join-Path $app $p
    if (Test-Path $d) { Remove-Item $d -Recurse -Force }
    Copy-Item $s $d -Recurse -Force
}
Get-ChildItem $app -Recurse -Force -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
# files from a downloaded zip carry the "from the internet" mark; clear it so scripts run
if ($OnWindows) { Get-ChildItem $app -Recurse -File | Unblock-File -ErrorAction SilentlyContinue }

# `autopsy` command: a .cmd shim in bin, bin on the user PATH
# prefer the py launcher at run time (survives Python upgrades); fall back to the Python found now
$shim = "@echo off`r`nwhere py >nul 2>nul && (py -3 `"$app\autopsy_main.py`" %*) || (`"$py`" `"$app\autopsy_main.py`" %*)`r`n"
Set-Content -Path (Join-Path $bin 'autopsy.cmd') -Value $shim -Encoding ASCII
$userPath = if ($OnWindows) { [Environment]::GetEnvironmentVariable('Path', 'User') } else { $null }
if (-not $userPath) { $userPath = '' }
if ($OnWindows -and (($userPath -split ';') -notcontains $bin)) {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $bin).TrimStart(';'), 'User')
    Write-Host "Added $bin to your PATH (open a NEW terminal to use 'autopsy')."
}
$env:Path = "$bin;$env:Path"

# SeamHunter desktop app: Desktop + Start-menu shortcuts that open `autopsy gui` with no console window
if ($OnWindows) {
    $pyw = Join-Path (Split-Path $py) 'pythonw.exe'
    if (-not (Test-Path $pyw)) { $pyw = $py }
    $ico = Join-Path $app 'assets\branding\seamhunter.ico'
    $ws = New-Object -ComObject WScript.Shell
    foreach ($dir in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs'))) {
        if (-not $dir) { continue }
        $lnk = $ws.CreateShortcut((Join-Path $dir 'SeamHunter.lnk'))
        $lnk.TargetPath = $pyw
        $lnk.Arguments = "`"$app\autopsy_main.py`" gui"
        $lnk.WorkingDirectory = $app
        if (Test-Path $ico) { $lnk.IconLocation = "$ico,0" }
        $lnk.Description = 'SeamHunter - find the seam, clip the ad (local static ad-seam analyzer)'
        $lnk.Save()
    }
    Write-Host "SeamHunter shortcuts: Desktop + Start menu"
}

# optional: make the install a local git repo so a local Claude session can diff/commit its fixes
if (Get-Command git -ErrorAction SilentlyContinue) {
    if (-not (Test-Path (Join-Path $app '.git'))) {
        git -C $app init -q
        git -C $app config user.name 'apk-autopsy local'
        git -C $app config user.email 'local@apk-autopsy'
    }
    git -C $app add -A | Out-Null
    git -C $app commit -q -m "install $newVer" 2>$null | Out-Null
}

Write-Host "Running self-test..."
Push-Location $app
& $py -m unittest discover -s tests -q
$ok = $LASTEXITCODE -eq 0
Pop-Location
if ($ok) {
    Write-Host "`napk-autopsy $newVer installed to $app" -ForegroundColor Green
    Write-Host "Try:   autopsy scan `"C:\path\to\app.apkm`"     (new terminal)"
    Write-Host "Update later:   autopsy update    (uses the newest apk-autopsy*.zip in Downloads)"
} else {
    Write-Host "Self-test FAILED. Previous version is in $Root\versions. Tell Claude the output above." -ForegroundColor Red
    exit 1
}
