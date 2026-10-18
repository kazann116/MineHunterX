program MineHunter.Tests;

{
  Консольный запуск всех тестов MineHunter X (DUnitX).
  Код возврата: 0 — все тесты пройдены, 1 — есть провалы, 2 — сбой запуска.
  Отчёт NUnit XML: параметр --xml:<путь> (используется в CI).
  Фильтр категорий: --include:Unit / --exclude:UI.
}

{$APPTYPE CONSOLE}
{$STRONGLINKTYPES ON}
{$R '..\src\App\MineHunter.App.Styles.res' '..\src\App\MineHunter.App.Styles.rc'}

uses
  System.SysUtils,
  DUnitX.Loggers.Console,
  DUnitX.Loggers.Xml.NUnit,
  DUnitX.TestFramework,
  MineHunter.Core.Lang in '..\src\Core\MineHunter.Core.Lang.pas',
  MineHunter.Core.Types in '..\src\Core\MineHunter.Core.Types.pas',
  MineHunter.Core.Interfaces in '..\src\Core\MineHunter.Core.Interfaces.pas',
  MineHunter.Core.Calc in '..\src\Core\MineHunter.Core.Calc.pas',
  MineHunter.Core.Logging in '..\src\Core\MineHunter.Core.Logging.pas',
  MineHunter.Core.Container in '..\src\Core\MineHunter.Core.Container.pas',
  MineHunter.Core.Scanner in '..\src\Core\MineHunter.Core.Scanner.pas',
  MineHunter.Core.Paths in '..\src\Core\MineHunter.Core.Paths.pas',
  MineHunter.Core.Serialization in '..\src\Core\MineHunter.Core.Serialization.pas',
  MineHunter.Collectors.SelfMonitor in '..\src\Core\Collectors\MineHunter.Collectors.SelfMonitor.pas',
  MineHunter.Collectors.Processes in '..\src\Core\Collectors\MineHunter.Collectors.Processes.pas',
  MineHunter.Collectors.Processes.WinApi in '..\src\Core\Collectors\MineHunter.Collectors.Processes.WinApi.pas',
  MineHunter.Collectors.System in '..\src\Core\Collectors\MineHunter.Collectors.System.pas',
  MineHunter.Collectors.Pdh in '..\src\Core\Collectors\MineHunter.Collectors.Pdh.pas',
  MineHunter.Collectors.Tamper in '..\src\Core\Collectors\MineHunter.Collectors.Tamper.pas',
  MineHunter.Collectors.Tamper.WinApi in '..\src\Core\Collectors\MineHunter.Collectors.Tamper.WinApi.pas',
  MineHunter.Analysis.Tamper in '..\src\Core\MineHunter.Analysis.Tamper.pas',
  MineHunter.Core.Quarantine in '..\src\Core\MineHunter.Core.Quarantine.pas',
  MineHunter.Core.Quarantine.WinApi in '..\src\Core\MineHunter.Core.Quarantine.WinApi.pas',
  MineHunter.Core.SelfAutostart in '..\src\Core\MineHunter.Core.SelfAutostart.pas',
  MineHunter.Core.Energy in '..\src\Core\MineHunter.Core.Energy.pas',
  MineHunter.Core.Inventory in '..\src\Core\MineHunter.Core.Inventory.pas',
  MineHunter.Core.CheckReport in '..\src\Core\MineHunter.Core.CheckReport.pas',
  MineHunter.Analysis.Launches in '..\src\Core\MineHunter.Analysis.Launches.pas',
  MineHunter.Analysis.Disks in '..\src\Core\MineHunter.Analysis.Disks.pas',
  MineHunter.Core.FileScan in '..\src\Core\MineHunter.Core.FileScan.pas',
  MineHunter.Core.FileScan.WinApi in '..\src\Core\MineHunter.Core.FileScan.WinApi.pas',
  MineHunter.Tests.FileScan in 'Unit\MineHunter.Tests.FileScan.pas',
  MineHunter.Core.Updates in '..\src\Core\MineHunter.Core.Updates.pas',
  MineHunter.Core.Updates.WinApi in '..\src\Core\MineHunter.Core.Updates.WinApi.pas',
  MineHunter.App.Lang in '..\src\App\MineHunter.App.Lang.pas',
  MineHunter.App.Theme in '..\src\App\MineHunter.App.Theme.pas',
  MineHunter.Tests.Appearance in 'Unit\MineHunter.Tests.Appearance.pas',
  MineHunter.Tests.CoreLanguage in 'Unit\MineHunter.Tests.CoreLanguage.pas',
  MineHunter.Collectors.ProcessEvents in '..\src\Core\Collectors\MineHunter.Collectors.ProcessEvents.pas',
  MineHunter.Collectors.Disks in '..\src\Core\Collectors\MineHunter.Collectors.Disks.pas',
  MineHunter.Collectors.Disks.WinApi in '..\src\Core\Collectors\MineHunter.Collectors.Disks.WinApi.pas',
  MineHunter.Tests.Disks in 'Unit\MineHunter.Tests.Disks.pas',
  MineHunter.Collectors.ProcessEvents.WinApi in '..\src\Core\Collectors\MineHunter.Collectors.ProcessEvents.WinApi.pas',
  MineHunter.Tests.ProcessEvents in 'Unit\MineHunter.Tests.ProcessEvents.pas',
  MineHunter.Tests.Insights in 'Unit\MineHunter.Tests.Insights.pas',
  MineHunter.Core.SelfAutostart.WinApi in '..\src\Core\MineHunter.Core.SelfAutostart.WinApi.pas',
  MineHunter.App.Notifier in '..\src\App\MineHunter.App.Notifier.pas',
  MineHunter.App.DisksPage in '..\src\App\MineHunter.App.DisksPage.pas',
  MineHunter.App.ListViews in '..\src\App\MineHunter.App.ListViews.pas',
  MineHunter.Tests.Background in 'Unit\MineHunter.Tests.Background.pas',
  MineHunter.Collectors.Gpu in '..\src\Core\Collectors\MineHunter.Collectors.Gpu.pas',
  MineHunter.Collectors.Gpu.WinApi in '..\src\Core\Collectors\MineHunter.Collectors.Gpu.WinApi.pas',
  MineHunter.Collectors.Sensors in '..\src\Core\Collectors\MineHunter.Collectors.Sensors.pas',
  MineHunter.Collectors.Sensors.WinApi in '..\src\Core\Collectors\MineHunter.Collectors.Sensors.WinApi.pas',
  MineHunter.Tests.GpuSensors in 'Unit\MineHunter.Tests.GpuSensors.pas',
  MineHunter.Tests.AnalyzerGpu in 'Unit\MineHunter.Tests.AnalyzerGpu.pas',
  MineHunter.Tests.DashboardView in 'Unit\MineHunter.Tests.DashboardView.pas',
  MineHunter.Tests.Contracts in 'Unit\MineHunter.Tests.Contracts.pas',
  MineHunter.Tests.Tamper in 'Unit\MineHunter.Tests.Tamper.pas',
  MineHunter.Tests.Quarantine in 'Unit\MineHunter.Tests.Quarantine.pas',
  MineHunter.Tests.HardwareIntegration in 'Integration\MineHunter.Tests.HardwareIntegration.pas',
  MineHunter.Collectors.System.WinApi in '..\src\Core\Collectors\MineHunter.Collectors.System.WinApi.pas',
  MineHunter.Collectors.Autostart in '..\src\Core\Collectors\MineHunter.Collectors.Autostart.pas',
  MineHunter.Collectors.Autostart.WinApi in '..\src\Core\Collectors\MineHunter.Collectors.Autostart.WinApi.pas',
  MineHunter.Collectors.Network in '..\src\Core\Collectors\MineHunter.Collectors.Network.pas',
  MineHunter.Collectors.Network.WinApi in '..\src\Core\Collectors\MineHunter.Collectors.Network.WinApi.pas',
  MineHunter.Collectors.Files in '..\src\Core\Collectors\MineHunter.Collectors.Files.pas',
  MineHunter.Collectors.Files.WinApi in '..\src\Core\Collectors\MineHunter.Collectors.Files.WinApi.pas',
  MineHunter.Collectors.Context in '..\src\Core\Collectors\MineHunter.Collectors.Context.pas',
  MineHunter.Collectors.Context.WinApi in '..\src\Core\Collectors\MineHunter.Collectors.Context.WinApi.pas',
  MineHunter.Analysis.Indicators in '..\src\Core\MineHunter.Analysis.Indicators.pas',
  MineHunter.Analysis.Engine in '..\src\Core\MineHunter.Analysis.Engine.pas',
  MineHunter.Analysis.Baseline in '..\src\Core\MineHunter.Analysis.Baseline.pas',
  MineHunter.Core.Settings in '..\src\Core\MineHunter.Core.Settings.pas',
  MineHunter.Core.Reports in '..\src\Core\MineHunter.Core.Reports.pas',
  MineHunter.Core.Actions in '..\src\Core\MineHunter.Core.Actions.pas',
  MineHunter.Core.Actions.WinApi in '..\src\Core\MineHunter.Core.Actions.WinApi.pas',
  MineHunter.Storage.SQLite in '..\src\Storage\MineHunter.Storage.SQLite.pas',
  MineHunter.App.Bootstrap in '..\src\App\MineHunter.App.Bootstrap.pas',
  MineHunter.App.Display in '..\src\App\MineHunter.App.Display.pas',
  MineHunter.App.ProcessView in '..\src\App\MineHunter.App.ProcessView.pas',
  MineHunter.App.FindingsView in '..\src\App\MineHunter.App.FindingsView.pas',
  MineHunter.App.Chart in '..\src\App\MineHunter.App.Chart.pas',
  MineHunter.App.DashboardView in '..\src\App\MineHunter.App.DashboardView.pas',
  MineHunter.App.Tiles in '..\src\App\MineHunter.App.Tiles.pas',
  MineHunter.App.MainForm in '..\src\App\MineHunter.App.MainForm.pas' {MainForm},
  MineHunter.Tests.Fakes in 'Fixtures\MineHunter.Tests.Fakes.pas',
  MineHunter.Tests.FakeProcessApi in 'Fixtures\MineHunter.Tests.FakeProcessApi.pas',
  MineHunter.Tests.FakeSystemApi in 'Fixtures\MineHunter.Tests.FakeSystemApi.pas',
  MineHunter.Tests.Scenarios in 'Fixtures\MineHunter.Tests.Scenarios.pas',
  MineHunter.Tests.Analyzer in 'Unit\MineHunter.Tests.Analyzer.pas',
  MineHunter.Tests.FindingsView in 'Unit\MineHunter.Tests.FindingsView.pas',
  MineHunter.Tests.Autostart in 'Unit\MineHunter.Tests.Autostart.pas',
  MineHunter.Tests.NetworkContext in 'Unit\MineHunter.Tests.NetworkContext.pas',
  MineHunter.Tests.FileInspector in 'Unit\MineHunter.Tests.FileInspector.pas',
  MineHunter.Tests.StorageV2 in 'Unit\MineHunter.Tests.StorageV2.pas',
  MineHunter.Tests.Baseline in 'Unit\MineHunter.Tests.Baseline.pas',
  MineHunter.Tests.SettingsReports in 'Unit\MineHunter.Tests.SettingsReports.pas',
  MineHunter.Tests.AutostartIntegration in 'Integration\MineHunter.Tests.AutostartIntegration.pas',
  MineHunter.Tests.NetworkContextIntegration in 'Integration\MineHunter.Tests.NetworkContextIntegration.pas',
  MineHunter.Tests.FileInspectorIntegration in 'Integration\MineHunter.Tests.FileInspectorIntegration.pas',
  MineHunter.Tests.ActionsIntegration in 'Integration\MineHunter.Tests.ActionsIntegration.pas',
  MineHunter.Tests.Types in 'Unit\MineHunter.Tests.Types.pas',
  MineHunter.Tests.Calc in 'Unit\MineHunter.Tests.Calc.pas',
  MineHunter.Tests.Container in 'Unit\MineHunter.Tests.Container.pas',
  MineHunter.Tests.Logging in 'Unit\MineHunter.Tests.Logging.pas',
  MineHunter.Tests.Scanner in 'Unit\MineHunter.Tests.Scanner.pas',
  MineHunter.Tests.Display in 'Unit\MineHunter.Tests.Display.pas',
  MineHunter.Tests.Paths in 'Unit\MineHunter.Tests.Paths.pas',
  MineHunter.Tests.Serialization in 'Unit\MineHunter.Tests.Serialization.pas',
  MineHunter.Tests.ProcessCollector in 'Unit\MineHunter.Tests.ProcessCollector.pas',
  MineHunter.Tests.ProcessView in 'Unit\MineHunter.Tests.ProcessView.pas',
  MineHunter.Tests.SystemCollector in 'Unit\MineHunter.Tests.SystemCollector.pas',
  MineHunter.Tests.Storage in 'Unit\MineHunter.Tests.Storage.pas',
  MineHunter.Tests.Chart in 'Unit\MineHunter.Tests.Chart.pas',
  MineHunter.Tests.Collectors in 'Integration\MineHunter.Tests.Collectors.pas',
  MineHunter.Tests.UI.Smoke in 'UI\MineHunter.Tests.UI.Smoke.pas';

var
  LRunner: ITestRunner;
  LResults: IRunResults;
begin
  ReportMemoryLeaksOnShutdown := False; // утечки проверяются отдельными тестами
  try
    TDUnitX.CheckCommandLine;
    LRunner := TDUnitX.CreateRunner;
    LRunner.UseRTTI := True;
    LRunner.FailsOnNoAsserts := False;
    if TDUnitX.Options.ConsoleMode <> TDunitXConsoleMode.Off then
      LRunner.AddLogger(TDUnitXConsoleLogger.Create(TDUnitX.Options.ConsoleMode = TDunitXConsoleMode.Quiet));
    if TDUnitX.Options.XMLOutputFile <> '' then
      LRunner.AddLogger(TDUnitXXMLNUnitFileLogger.Create(TDUnitX.Options.XMLOutputFile));
    LResults := LRunner.Execute;
    if not LResults.AllPassed then
      System.ExitCode := EXIT_ERRORS;
    if TDUnitX.Options.ExitBehavior = TDUnitXExitBehavior.Pause then
    begin
      System.Write('Готово. Нажмите Enter...');
      System.Readln;
    end;
  except
    on E: Exception do
    begin
      System.Writeln(E.ClassName, ': ', E.Message);
      System.ExitCode := 2;
    end;
  end;
end.
