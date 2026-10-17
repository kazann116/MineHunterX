<#
.SYNOPSIS
  Сборка MineHunter X (приложение и тесты) через MSBuild, Win64.

.PARAMETER Config
  Debug или Release.

.PARAMETER BdsDir
  Каталог RAD Studio. По умолчанию — переменная окружения BDS или
  стандартный путь Delphi 12 Athens (Studio\23.0).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\build.ps1 -Config Release
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Config = 'Debug',
    [string]$BdsDir = $(if ($env:BDS) { $env:BDS } else { 'C:\Program Files (x86)\Embarcadero\Studio\23.0' })
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$rsvars = Join-Path $BdsDir 'bin\rsvars.bat'
if (-not (Test-Path $rsvars)) {
    throw "Не найден rsvars.bat: $rsvars. Укажите -BdsDir или переменную BDS."
}

# Переносим переменные окружения из rsvars.bat в текущий процесс.
cmd /c "`"$rsvars`" && set" | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($Matches[1])" -Value $Matches[2] }
}

$msbuild = Join-Path $env:FrameworkDir 'MSBuild.exe'
if (-not (Test-Path $msbuild)) { throw "Не найден MSBuild: $msbuild" }

$projects = @(
    'src\App\MineHunter.App.dproj',
    'tests\MineHunter.Tests.dproj',
    'tests\Soak\MineHunter.Soak.dproj'
)

foreach ($project in $projects) {
    $path = Join-Path $root $project
    Write-Host "==> $project ($Config|Win64)" -ForegroundColor Cyan
    & $msbuild $path /t:Build "/p:Config=$Config" /p:Platform=Win64 /nologo /v:minimal
    if ($LASTEXITCODE -ne 0) { throw "Сборка $project завершилась с кодом $LASTEXITCODE" }
}

Write-Host "Сборка завершена: $(Join-Path $root "build\Win64\$Config")" -ForegroundColor Green
