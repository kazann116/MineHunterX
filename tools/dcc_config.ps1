<#
.SYNOPSIS
  Builds a single .dpr with dcc64 using the compiler switches of the project
  configurations (tools/gen_dproj.py): Debug = DEBUG, no optimisation, range and
  overflow checks, stack frames, debug info; Release = RELEASE, optimisation, no
  debug info. Used by tools/binarylab_assert_trace.py for instrumented test copies.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\dcc_config.ps1 -Dpr build\tmp\trace\MineHunter.Tests.dpr -Out traceout-Debug -Config Debug
#>
param(
    [Parameter(Mandatory = $true)][string]$Dpr,
    [Parameter(Mandatory = $true)][string]$Out,
    [ValidateSet('Debug', 'Release')][string]$Config = 'Debug',
    [string]$BdsDir = $(if ($env:BDS) { $env:BDS } else { 'C:\Program Files (x86)\Embarcadero\Studio\23.0' })
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$outDir = Join-Path $root "build\tmp\$Out"
New-Item -ItemType Directory -Force $outDir | Out-Null
$search = @('src\Core', 'src\Core\Collectors', 'src\Core\BinaryLab', 'src\Storage', 'src\App',
    'tests\Unit', 'tests\Integration', 'tests\UI', 'tests\Fixtures') | ForEach-Object { Join-Path $root $_ }
$lib = "$BdsDir\lib\Win64\release;$BdsDir\Imports;$BdsDir\include"
if ($Config -eq 'Debug') {
    $switches = @('-DDEBUG', '-$O-', '-$R+', '-$Q+', '-$W+', '-$D+', '-$L+', '-V')
} else {
    $switches = @('-DRELEASE', '-$O+', '-$D-', '-$L-', '-$Y-')
}
& "$BdsDir\bin\dcc64.exe" -B -Q @switches "-NSSystem;Xml;Data;Datasnap;Web;Soap;Vcl;Vcl.Imaging;Vcl.Touch;Vcl.Samples;Vcl.Shell;Winapi;System.Win;Data.Win;Datasnap.Win;Web.Win;Soap.Win;Xml.Win" "-U$($search -join ';');$lib" "-I$lib" "-R$lib" "-NU$outDir" "-E$outDir" $Dpr
exit $LASTEXITCODE
