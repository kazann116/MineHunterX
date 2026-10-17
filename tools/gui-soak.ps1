<#
.SYNOPSIS
  Длительная проверка GUI MineHunter X: приложение работает заданное время,
  раз в 30 с проверяется отклик окна, память и дескрипторы; в конце окно
  закрывается штатно (WM_CLOSE) и проверяется код выхода.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\gui-soak.ps1 -Minutes 75
#>
[CmdletBinding()]
param(
    [int]$Minutes = 60,
    [string]$Exe = '',
    [string]$Report = ''
)

$ErrorActionPreference = 'Stop'
# В Windows PowerShell 5.1 $PSScriptRoot недоступен в значениях параметров по умолчанию.
$root = Split-Path -Parent $PSScriptRoot
if ($Exe -eq '') { $Exe = Join-Path $root 'build\Win64\Release\MineHunter.App.exe' }
if ($Report -eq '') { $Report = Join-Path $root 'build\reports\gui-soak-report.md' }
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class MHGuiSoak {
 public delegate bool EnumProc(IntPtr h, IntPtr l);
 [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, IntPtr l);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
 [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
 [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
 [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern uint RegisterWindowMessage(string name);
 [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeout(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint t, out IntPtr r);
 public static IntPtr FormOf(uint pid) { IntPtr found = IntPtr.Zero; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h, out p); var c = new StringBuilder(64); GetClassName(h,c,64); if (p==pid && c.ToString()=="TMainForm") { found = h; return false; } return true; }, IntPtr.Zero); return found; }
 // Окно отвечает, если обработало WM_NULL за 5 секунд.
 public static bool Responds(IntPtr h) { IntPtr r; return SendMessageTimeout(h, 0, IntPtr.Zero, IntPtr.Zero, 2, 5000, out r) != IntPtr.Zero; }
}
"@

$process = Start-Process $Exe -PassThru
Start-Sleep -Seconds 5
$form = [MHGuiSoak]::FormOf($process.Id)
$rows = @()
$hangs = 0
$started = Get-Date
$cores = [Environment]::ProcessorCount
$process.Refresh(); $lastCpu = $process.TotalProcessorTime.TotalMilliseconds; $lastTime = Get-Date
while (((Get-Date) - $started).TotalMinutes -lt $Minutes) {
    Start-Sleep -Seconds 30
    $process.Refresh()
    if ($process.HasExited) { break }
    $ok = [MHGuiSoak]::Responds($form)
    if (-not $ok) { $hangs++ }
    $now = Get-Date; $cpu = $process.TotalProcessorTime.TotalMilliseconds
    $pct = ($cpu - $lastCpu) / ($now - $lastTime).TotalMilliseconds / $cores * 100
    $lastCpu = $cpu; $lastTime = $now
    $rows += [pscustomobject]@{ Minute = [math]::Round(($now - $started).TotalMinutes, 1); Responding = $ok;
        Cpu = [math]::Round($pct, 3); PrivateMB = [math]::Round($process.PrivateMemorySize64 / 1MB, 1);
        Handles = $process.HandleCount }
}
$crashed = $process.HasExited
if (-not $crashed) {
    # «MineHunterX.Quit» — штатный выход (WM_CLOSE при включённом трее только скрывает окно).
    [void][MHGuiSoak]::PostMessage($form, [MHGuiSoak]::RegisterWindowMessage('MineHunterX.Quit'), [IntPtr]::Zero, [IntPtr]::Zero)
    $exited = $process.WaitForExit(30000)
} else { $exited = $true }
$exitCode = if ($exited) { $process.ExitCode } else { 'не завершилось' }
if (-not $exited) { $process.Kill() }

$first = $rows | Select-Object -Skip 4 -First 1
$last = $rows | Select-Object -Last 1
$avgCpu = ($rows | Select-Object -Skip 2 | Measure-Object -Property Cpu -Average).Average
$passed = (-not $crashed) -and ($hangs -eq 0) -and $exited -and ($exitCode -eq 0) -and
    (($last.PrivateMB - $first.PrivateMB) -lt 30) -and (($last.Handles - $first.Handles) -lt 100)
$lines = @('# GUI soak MineHunter X', '',
    "Дата: $($started.ToString('dd.MM.yyyy HH:mm')). Длительность: $Minutes мин, интервал опроса — настройка по умолчанию (2 с).",
    "Проверок отклика окна: $($rows.Count), зависаний (нет ответа за 5 с): $hangs. Аварийное завершение: $crashed.",
    "Штатное закрытие: $exited, код выхода: $exitCode.",
    "Средняя нагрузка приложения: $([math]::Round($avgCpu, 3))% CPU машины ($cores логических CPU).",
    "Рост частной памяти после прогрева: $([math]::Round($last.PrivateMB - $first.PrivateMB, 1)) МБ; дескрипторов: $($last.Handles - $first.Handles).",
    '', '| Минута | Отвечает | CPU, % | Частная память, МБ | Дескрипторов |', '|---|---|---|---|---|')
foreach ($row in $rows) { $lines += "| $($row.Minute) | $($row.Responding) | $($row.Cpu) | $($row.PrivateMB) | $($row.Handles) |" }
$lines += ''
$lines += $(if ($passed) { '**Итог: пройдено.**' } else { '**Итог: НЕ пройдено.**' })
New-Item -ItemType Directory -Force (Split-Path -Parent $Report) | Out-Null
$lines | Set-Content -Path $Report -Encoding UTF8
$lines | Select-Object -First 8
if ($passed) { exit 0 } else { exit 1 }
