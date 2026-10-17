program MineHunter.App;

uses
  Vcl.Forms,
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

begin
  {$IFDEF DEBUG}
  ReportMemoryLeaksOnShutdown := True;
  {$ENDIF}
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.Title := 'MineHunter X';
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
