<#
.SYNOPSIS
  Подпись исполняемых файлов MineHunter X сертификатом разработчика (signtool).

.DESCRIPTION
  Подписанный exe не вызывает предупреждений SmartScreen «неизвестный издатель»
  (после набора репутации) и позволяет пользователю проверить, что файл не изменён.
  Используется SHA-256 и метка времени RFC 3161: подпись остаётся действительной
  после истечения срока сертификата.

  Сертификат задаётся одним из способов:
    -Thumbprint  отпечаток сертификата в хранилище «Личные» текущего пользователя
                 (в том числе на токене/HSM для EV-сертификатов);
    -PfxPath     файл .pfx; пароль — параметр -PfxPassword или переменная
                 окружения MH_SIGN_PFX_PASSWORD (не храните пароль в скриптах).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\sign.ps1 -Files build\Win64\Release\MineHunter.App.exe -Thumbprint 0123ABCD...
.EXAMPLE
  $env:MH_SIGN_PFX_PASSWORD = '***'; tools\sign.ps1 -Files dist\MineHunterX-0.1.0-setup.exe -PfxPath C:\keys\codesign.pfx
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]]$Files,
    [string]$Thumbprint = '',
    [string]$PfxPath = '',
    [string]$PfxPassword = $env:MH_SIGN_PFX_PASSWORD,
    [string]$TimestampUrl = 'http://timestamp.digicert.com',
    [string]$Description = 'MineHunter X',
    [string]$DescriptionUrl = 'https://github.com/kazann116/MineHunterX',
    [string]$SignTool = ''
)

$ErrorActionPreference = 'Stop'

function Find-SignTool {
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (-not (Test-Path $kits)) { return $null }
    Get-ChildItem $kits -Directory | Sort-Object Name -Descending | ForEach-Object {
        $candidate = Join-Path $_.FullName 'x64\signtool.exe'
        if (Test-Path $candidate) { return $candidate }
    } | Select-Object -First 1
}

if ($SignTool -eq '') { $SignTool = Find-SignTool }
if (-not $SignTool -or -not (Test-Path $SignTool)) {
    throw 'Не найден signtool.exe. Установите Windows SDK (компонент «Signing Tools») или укажите -SignTool.'
}
if ($Thumbprint -eq '' -and $PfxPath -eq '') {
    throw 'Не задан сертификат: укажите -Thumbprint (хранилище «Личные») или -PfxPath (файл .pfx).'
}

$certArgs = @()
if ($Thumbprint -ne '') {
    $certArgs = @('/sha1', ($Thumbprint -replace '\s', ''))
} else {
    if (-not (Test-Path $PfxPath)) { throw "Не найден файл сертификата: $PfxPath" }
    $certArgs = @('/f', $PfxPath)
    if ($PfxPassword) { $certArgs += @('/p', $PfxPassword) }
}

foreach ($file in $Files) {
    if (-not (Test-Path $file)) { throw "Не найден файл для подписи: $file" }
    Write-Host "Подпись: $file" -ForegroundColor Cyan
    & $SignTool sign /fd SHA256 /td SHA256 /tr $TimestampUrl /d $Description /du $DescriptionUrl @certArgs $file
    if ($LASTEXITCODE -ne 0) { throw "signtool sign завершился с кодом $LASTEXITCODE для $file" }
    & $SignTool verify /pa /q $file
    if ($LASTEXITCODE -ne 0) { throw "Подпись $file не прошла проверку (signtool verify)" }
}
Write-Host 'Подпись выполнена и проверена.' -ForegroundColor Green
