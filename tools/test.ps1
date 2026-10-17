<#
.SYNOPSIS
  Запуск тестов MineHunter X (DUnitX) с отчётом NUnit XML.

.PARAMETER Config
  Конфигурация сборки тестов: Debug или Release.

.PARAMETER Exclude
  Категории, которые нужно исключить (например, 'UI' на агенте без
  интерактивного рабочего стола).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\test.ps1 -Config Release
  powershell -ExecutionPolicy Bypass -File tools\test.ps1 -Exclude UI
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Config = 'Debug',
    [string[]]$Exclude = @()
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root "build\Win64\$Config\MineHunter.Tests.exe"
if (-not (Test-Path $exe)) {
    throw "Не найден $exe. Сначала выполните tools\build.ps1 -Config $Config."
}

$resultsDir = Join-Path $root 'build\test-results'
New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null
$xml = Join-Path $resultsDir "MineHunter.Tests.$Config.xml"

$arguments = @('--exitbehavior:Continue', '--consolemode:Quiet', "--xml:$xml")
if ($Exclude.Count -gt 0) {
    $arguments += "--exclude:$($Exclude -join ',')"
}

& $exe @arguments
$code = $LASTEXITCODE
Write-Host "Отчёт: $xml"
if ($code -ne 0) {
    Write-Host "Тесты завершились с кодом $code" -ForegroundColor Red
}
exit $code
