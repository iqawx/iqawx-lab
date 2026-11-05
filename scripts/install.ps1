param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'IQAWX\bin'),
    [switch]$NoPath
)
$ErrorActionPreference = 'Stop'
$RootDir = Split-Path -Parent $PSScriptRoot
$Binary = Join-Path $RootDir 'iqaw.exe'
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    if (-not (Test-Path -LiteralPath (Join-Path $RootDir 'Cargo.toml'))) {
        throw 'iqaw.exe is missing. Extract the complete package first.'
    }
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw 'Install Rust 1.93+ and native build tools to build from source, or download a prebuilt package.'
    }
    Push-Location $RootDir
    try {
        & cargo build --release --locked --bin iqaw
        if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    } finally { Pop-Location }
    $Binary = Join-Path $RootDir 'target\release\iqaw.exe'
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -LiteralPath $Binary -Destination (Join-Path $InstallDir 'iqaw.exe') -Force
if (-not $NoPath) {
    $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $Entries = @($UserPath -split ';' | Where-Object { $_ })
    if ($Entries -notcontains $InstallDir) {
        [Environment]::SetEnvironmentVariable('Path', (($Entries + $InstallDir) -join ';'), 'User')
    }
    if (($env:Path -split ';') -notcontains $InstallDir) { $env:Path = "$InstallDir;$env:Path" }
}
Write-Host "Installed: $InstallDir\iqaw.exe"
Write-Host 'Open a new terminal, then run iqaw for the terminal menu, or iqaw --help for all commands.'
