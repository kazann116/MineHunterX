<#
.SYNOPSIS
  Сборка установщика MineHunter X: Release-сборка, (необязательно) подпись exe,
  компиляция installer\MineHunterX.iss в dist\MineHunterX-<версия>-setup.exe.

.PARAMETER Sign
  Подписать exe и установщик (параметры сертификата передаются в tools\sign.ps1:
  -Thumbprint или -PfxPath; пароль .pfx — переменная MH_SIGN_PFX_PASSWORD).

.PARAMETER SkipBuild
  Не пересобирать Release (использовать готовый build\Win64\Release\MineHunter.App.exe).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\make-installer.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\make-installer.ps1 -Sign -Thumbprint 0123ABCD...
#>
[CmdletBinding()]
param(
    [switch]$Sign,
    [string]$Thumbprint = '',
    [string]$PfxPath = '',
    [switch]$SkipBuild,
    [string]$Iscc = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if ($Iscc -eq '') {
    foreach ($candidate in @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe")) {
        if (Test-Path $candidate) { $Iscc = $candidate; break }
    }
}
if ($Iscc -eq '' -or -not (Test-Path $Iscc)) {
    throw 'Не найден Inno Setup 6 (ISCC.exe). Установите его с https://jrsoftware.org/isdl.php или укажите -Iscc.'
}

# Версия — из ядра (единственный источник).
$typesPas = Get-Content (Join-Path $root 'src\Core\MineHunter.Core.Types.pas') -Raw -Encoding UTF8
if ($typesPas -notmatch "MH_CORE_VERSION = '([0-9.]+)'") { throw 'Не найдена константа MH_CORE_VERSION' }
$version = $Matches[1]

if (-not $SkipBuild) {
    & (Join-Path $PSScriptRoot 'build.ps1') -Config Release
}
$exe = Join-Path $root 'build\Win64\Release\MineHunter.App.exe'
if (-not (Test-Path $exe)) { throw "Не найден $exe" }

$signArgs = @{}
if ($Thumbprint -ne '') { $signArgs.Thumbprint = $Thumbprint }
if ($PfxPath -ne '') { $signArgs.PfxPath = $PfxPath }
if ($Sign) {
    & (Join-Path $PSScriptRoot 'sign.ps1') -Files $exe @signArgs
}

$outDir = Join-Path $root 'dist'
New-Item -ItemType Directory -Force $outDir | Out-Null
$isccArgs = @(
    "/DAppVersion=$version",
    "/DRepoDir=$root",
    "/DSourceDir=$(Split-Path -Parent $exe)",
    "/DOutputDir=$outDir",
    '/Qp'
)
& $Iscc @isccArgs (Join-Path $root 'installer\MineHunterX.iss')
if ($LASTEXITCODE -ne 0) { throw "ISCC завершился с кодом $LASTEXITCODE" }

$setup = Join-Path $outDir "MineHunterX-$version-setup.exe"
if ($Sign) {
    & (Join-Path $PSScriptRoot 'sign.ps1') -Files $setup @signArgs
}
$hash = (Get-FileHash $setup -Algorithm SHA256).Hash
Write-Host "Установщик: $setup" -ForegroundColor Green
Write-Host "SHA-256: $hash"
