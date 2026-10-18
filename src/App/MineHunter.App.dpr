program MineHunter.App;

uses
  Vcl.Forms,
  MineHunter.Core.Lang in '..\Core\MineHunter.Core.Lang.pas',
  MineHunter.Core.Types in '..\Core\MineHunter.Core.Types.pas',
  MineHunter.Core.Interfaces in '..\Core\MineHunter.Core.Interfaces.pas',
  MineHunter.Core.Calc in '..\Core\MineHunter.Core.Calc.pas',
  MineHunter.Core.Logging in '..\Core\MineHunter.Core.Logging.pas',
  MineHunter.Core.Container in '..\Core\MineHunter.Core.Container.pas',
  MineHunter.Core.Scanner in '..\Core\MineHunter.Core.Scanner.pas',
  MineHunter.Core.Paths in '..\Core\MineHunter.Core.Paths.pas',
  MineHunter.Core.Serialization in '..\Core\MineHunter.Core.Serialization.pas',
  MineHunter.Collectors.SelfMonitor in '..\Core\Collectors\MineHunter.Collectors.SelfMonitor.pas',
  MineHunter.Collectors.Processes in '..\Core\Collectors\MineHunter.Collectors.Processes.pas',
  MineHunter.Collectors.Processes.WinApi in '..\Core\Collectors\MineHunter.Collectors.Processes.WinApi.pas',
  MineHunter.Collectors.System in '..\Core\Collectors\MineHunter.Collectors.System.pas',
  MineHunter.Collectors.Pdh in '..\Core\Collectors\MineHunter.Collectors.Pdh.pas',
  MineHunter.Collectors.Tamper in '..\Core\Collectors\MineHunter.Collectors.Tamper.pas',
  MineHunter.Collectors.Tamper.WinApi in '..\Core\Collectors\MineHunter.Collectors.Tamper.WinApi.pas',
  MineHunter.Analysis.Tamper in '..\Core\MineHunter.Analysis.Tamper.pas',
  MineHunter.Core.Quarantine in '..\Core\MineHunter.Core.Quarantine.pas',
  MineHunter.Core.Quarantine.WinApi in '..\Core\MineHunter.Core.Quarantine.WinApi.pas',
  MineHunter.Core.SelfAutostart in '..\Core\MineHunter.Core.SelfAutostart.pas',
  MineHunter.Core.Energy in '..\Core\MineHunter.Core.Energy.pas',
  MineHunter.Core.Inventory in '..\Core\MineHunter.Core.Inventory.pas',
  MineHunter.Core.Launches in '..\Core\MineHunter.Core.Launches.pas',
  MineHunter.Core.CheckReport in '..\Core\MineHunter.Core.CheckReport.pas',
  MineHunter.Analysis.Launches in '..\Core\MineHunter.Analysis.Launches.pas',
  MineHunter.Analysis.Disks in '..\Core\MineHunter.Analysis.Disks.pas',
  MineHunter.Analysis.Acknowledge in '..\Core\MineHunter.Analysis.Acknowledge.pas',
  MineHunter.Core.FileScan in '..\Core\MineHunter.Core.FileScan.pas',
  MineHunter.Core.FileScan.WinApi in '..\Core\MineHunter.Core.FileScan.WinApi.pas',
  MineHunter.Core.Updates in '..\Core\MineHunter.Core.Updates.pas',
  MineHunter.Core.Updates.WinApi in '..\Core\MineHunter.Core.Updates.WinApi.pas',
  MineHunter.App.Lang in 'MineHunter.App.Lang.pas',
  MineHunter.App.Theme in 'MineHunter.App.Theme.pas',
  MineHunter.Collectors.ProcessEvents in '..\Core\Collectors\MineHunter.Collectors.ProcessEvents.pas',
  MineHunter.Collectors.Disks in '..\Core\Collectors\MineHunter.Collectors.Disks.pas',
  MineHunter.Collectors.Disks.WinApi in '..\Core\Collectors\MineHunter.Collectors.Disks.WinApi.pas',
  MineHunter.Collectors.ProcessEvents.WinApi in '..\Core\Collectors\MineHunter.Collectors.ProcessEvents.WinApi.pas',
  MineHunter.Core.SelfAutostart.WinApi in '..\Core\MineHunter.Core.SelfAutostart.WinApi.pas',
  MineHunter.App.Notifier in 'MineHunter.App.Notifier.pas',
  MineHunter.App.DisksPage in 'MineHunter.App.DisksPage.pas',
  MineHunter.App.ListViews in 'MineHunter.App.ListViews.pas',
  MineHunter.App.LaunchesPage in 'MineHunter.App.LaunchesPage.pas',
  MineHunter.Collectors.Gpu in '..\Core\Collectors\MineHunter.Collectors.Gpu.pas',
  MineHunter.Collectors.Gpu.WinApi in '..\Core\Collectors\MineHunter.Collectors.Gpu.WinApi.pas',
  MineHunter.Collectors.Sensors in '..\Core\Collectors\MineHunter.Collectors.Sensors.pas',
  MineHunter.Collectors.Sensors.WinApi in '..\Core\Collectors\MineHunter.Collectors.Sensors.WinApi.pas',
  MineHunter.Collectors.System.WinApi in '..\Core\Collectors\MineHunter.Collectors.System.WinApi.pas',
  MineHunter.Collectors.Autostart in '..\Core\Collectors\MineHunter.Collectors.Autostart.pas',
  MineHunter.Collectors.Autostart.WinApi in '..\Core\Collectors\MineHunter.Collectors.Autostart.WinApi.pas',
  MineHunter.Collectors.Network in '..\Core\Collectors\MineHunter.Collectors.Network.pas',
  MineHunter.Collectors.Network.WinApi in '..\Core\Collectors\MineHunter.Collectors.Network.WinApi.pas',
  MineHunter.Collectors.Files in '..\Core\Collectors\MineHunter.Collectors.Files.pas',
  MineHunter.Collectors.Files.WinApi in '..\Core\Collectors\MineHunter.Collectors.Files.WinApi.pas',
  MineHunter.Collectors.Context in '..\Core\Collectors\MineHunter.Collectors.Context.pas',
  MineHunter.Collectors.Context.WinApi in '..\Core\Collectors\MineHunter.Collectors.Context.WinApi.pas',
  MineHunter.Analysis.Indicators in '..\Core\MineHunter.Analysis.Indicators.pas',
  MineHunter.Analysis.Engine in '..\Core\MineHunter.Analysis.Engine.pas',
  MineHunter.Analysis.Baseline in '..\Core\MineHunter.Analysis.Baseline.pas',
  MineHunter.Core.Settings in '..\Core\MineHunter.Core.Settings.pas',
  MineHunter.Core.Reports in '..\Core\MineHunter.Core.Reports.pas',
  MineHunter.Core.Actions in '..\Core\MineHunter.Core.Actions.pas',
  MineHunter.Core.Actions.WinApi in '..\Core\MineHunter.Core.Actions.WinApi.pas',
  MineHunter.Storage.SQLite in '..\Storage\MineHunter.Storage.SQLite.pas',
  MineHunter.App.Bootstrap in 'MineHunter.App.Bootstrap.pas',
  MineHunter.App.Display in 'MineHunter.App.Display.pas',
  MineHunter.App.ProcessView in 'MineHunter.App.ProcessView.pas',
  MineHunter.App.FindingsView in 'MineHunter.App.FindingsView.pas',
  MineHunter.App.Chart in 'MineHunter.App.Chart.pas',
  MineHunter.App.DashboardView in 'MineHunter.App.DashboardView.pas',
  MineHunter.App.Tiles in 'MineHunter.App.Tiles.pas',
  MineHunter.App.MainForm in 'MineHunter.App.MainForm.pas' {MainForm};

{$R 'MineHunter.App.Resources.res' 'MineHunter.App.Resources.rc'}
{$R 'MineHunter.App.Styles.res' 'MineHunter.App.Styles.rc'}

function LaunchParams: TArray<string>;
var
  I: Integer;
begin
  SetLength(Result, ParamCount);
  for I := 1 to ParamCount do
    Result[I - 1] := ParamStr(I);
end;

begin
  {$IFDEF DEBUG}
  ReportMemoryLeaksOnShutdown := True;
  {$ENDIF}
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.Title := 'MineHunter X';
  // Автозапуск с Windows (--minimized): окно не показывается, значок — в области уведомлений.
  Application.ShowMainForm := not MHHasMinimizedSwitch(LaunchParams);
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
