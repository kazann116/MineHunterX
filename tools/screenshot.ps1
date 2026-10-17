<#
.SYNOPSIS
  Снимок окна MineHunter X для проверки интерфейса: запускает приложение,
  ждёт заданное время, сохраняет PNG окна и штатно закрывает приложение.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\screenshot.ps1 -Out build\shots\dashboard.png -Seconds 20
#>
[CmdletBinding()]
param(
    [string]$Exe = '',
    [string]$Out = '',
    [int]$Seconds = 20,
    [int]$Width = 1400,
    [int]$Height = 900,
    [string]$Keys = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ($Exe -eq '') { $Exe = Join-Path $root 'build\Win64\Release\MineHunter.App.exe' }
if ($Out -eq '') { $Out = Join-Path $root 'build\shots\window.png' }
New-Item -ItemType Directory -Force (Split-Path -Parent $Out) | Out-Null

Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class MHWin {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int ht, bool repaint);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
}
'@

$proc = Start-Process -FilePath $Exe -PassThru
try {
    $deadline = (Get-Date).AddSeconds(30)
    while ($proc.MainWindowHandle -eq 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300; $proc.Refresh() }
    $h = $proc.MainWindowHandle
    if ($h -eq 0) { throw 'Окно приложения не появилось' }
    [MHWin]::MoveWindow($h, 20, 20, $Width, $Height, $true) | Out-Null
    [MHWin]::SetForegroundWindow($h) | Out-Null
    Start-Sleep -Seconds $Seconds
    if ($Keys -ne '') {
        Add-Type -AssemblyName System.Windows.Forms
        [MHWin]::SetForegroundWindow($h) | Out-Null
        [System.Windows.Forms.SendKeys]::SendWait($Keys)
        Start-Sleep -Seconds 3
    }
    $r = New-Object MHWin+RECT
    [MHWin]::GetWindowRect($h, [ref]$r) | Out-Null
    $bmp = New-Object System.Drawing.Bitmap ($r.Right - $r.Left), ($r.Bottom - $r.Top)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $dc = $g.GetHdc()
    # PW_RENDERFULLCONTENT = 2: корректный снимок и для окон с DWM-композицией.
    [MHWin]::PrintWindow($h, $dc, 2) | Out-Null
    $g.ReleaseHdc($dc)
    $bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Output "Снимок: $Out"
}
finally {
    if (-not $proc.HasExited) {
        # WM_CLOSE — штатное закрытие.
        [MHWin]::PostMessage($proc.MainWindowHandle, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
        if (-not $proc.WaitForExit(15000)) { $proc.Kill() }
    }
}
