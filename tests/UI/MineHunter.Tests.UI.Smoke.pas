unit MineHunter.Tests.UI.Smoke;

{
  UI smoke: создание главного окна, навигация, запуск/остановка сканирования,
  применение настроек и закрытие во время сканирования.
  Окно не показывается на экране; события сканера доставляются через
  CheckSynchronize, как это делает цикл сообщений VCL.
}

interface

uses
  DUnitX.TestFramework,
  MineHunter.App.Bootstrap, MineHunter.App.MainForm, MineHunter.Tests.FakeProcessApi,
  MineHunter.Tests.FakeSystemApi;

type
  [TestFixture]
  [Category('UI')]
  TMainFormSmokeTests = class
  private
    FServices: TMHAppServices;
    FForm: TMainForm;
    FProcApi: TFakeProcessApi;
    FSysApi: TFakeSystemMetricsApi;
    FTempDir: string;
    function WaitForSnapshots(ACount: Integer; ATimeoutMs: Cardinal): Boolean;
    function WaitForHistory(ATimeoutMs: Cardinal): Boolean;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Create_StartsOnDashboardAndStopped;
    [Test] procedure Navigation_AllPagesReachable;
    [Test] procedure NavigationActions_SwitchPages;
    [Test] procedure StartScan_UpdatesDashboard_StopScan;
    [Test] procedure IntervalSetting_IsAppliedToScanner;
    [Test] procedure FreeWhileScanning_DoesNotCrash;
    [Test] procedure DefaultConfiguration_CreatesAndFrees;
    [Test] procedure Dashboard_GpuTemperaturesAndProcessColumns;
    [Test] procedure Processes_TableAndDetails;
    [Test] procedure Processes_SortByColumnClick;
    [Test] procedure Processes_Filter;
    [Test] procedure Processes_SelectionSurvivesResort;
    [Test] procedure Processes_SelectedProcessExited;
    [Test] procedure Processes_SourceFailure_KeepsLastData;
    [Test] procedure Processes_IdleProcessIsSelectable;
    [Test] procedure Dashboard_SystemChartsAndSummary;
    [Test] procedure History_LoadsFromStorageInBackground;
    [Test] procedure History_PeriodChange_Reloads;
    [Test] procedure Settings_RetentionAndPrivacy_AppliedToStorage;
    [Test] procedure Settings_ClearHistory_RequiresConfirmation;
    [Test] procedure StorageUnavailable_AppKeepsWorking;
    [Test] procedure Dashboard_ProtectionShowsAlerts;
    [Test] procedure Processes_RiskColumnAndFilters;
    [Test] procedure Findings_ListCardAndExport;
    [Test] procedure Findings_AllowProgram_AddsExclusionAndJournal;
    [Test] procedure Findings_StopProcess_RequiresConfirmation;
    [Test] procedure Findings_DefenderAndOpenLocation_ValidatePath;
    [Test] procedure Settings_AnalysisAreAppliedAndPersisted;
    [Test] procedure History_ComparisonWithBaseline;
    [Test] procedure Findings_Remediate_QuarantineAndRestore;
    [Test] procedure Background_TrayEconomyNotifyAndAutostart;
    [Test] procedure CheckNow_ReportChangesEnergyAndPrice;
  end;

implementation

uses
  System.SysUtils, System.Classes, System.Diagnostics, Winapi.Windows, System.DateUtils,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Core.Container,
  MineHunter.Core.Logging, MineHunter.Core.Scanner, MineHunter.App.Display,
  System.IOUtils, System.JSON, MineHunter.App.ProcessView, MineHunter.App.FindingsView,
  MineHunter.Core.Settings, MineHunter.Core.Serialization, MineHunter.Collectors.Processes,
  MineHunter.Collectors.SelfMonitor, MineHunter.Collectors.System, MineHunter.Storage.SQLite,
  MineHunter.Collectors.Gpu, MineHunter.Collectors.Sensors, MineHunter.Tests.GpuSensors,
  MineHunter.App.DashboardView, MineHunter.Core.Actions, MineHunter.Core.Quarantine,
  MineHunter.Tests.Quarantine, MineHunter.Tests.SettingsReports, MineHunter.Tests.Background,
  MineHunter.Core.SelfAutostart, MineHunter.Core.CheckReport,
  MineHunter.Tests.Fakes;

var
  // Подмена операций ОС для тестов действий (nil — настоящие операции).
  GTestQuarantineOps: IMHQuarantineOps;
  GTestSystemOps: IMHSystemOps;
  GTestRunKeyOps: IMHRunKeyOps;

function NewTempDir: string;
begin
  Result := TPath.Combine(TPath.GetTempPath, 'MineHunterTests\ui-' +
    TGUID.NewGuid.ToString.Replace('{', '').Replace('}', ''));
  ForceDirectories(Result);
end;

/// AHistoryPath = '' — хранилище, которое не удаётся открыть.
function NewTestServices(out AProcApi: TFakeProcessApi; out ASysApi: TFakeSystemMetricsApi;
  const AHistoryPath: string; AGpuApi: TFakeGpuApi = nil; ASensorApi: TFakeSensorApi = nil): TMHAppServices;
var
  LContainer: TMHContainer;
  LClock: IMHClock;
  LLogger: TMHMemoryLogger;
  LOptions: TMHScannerOptions;
  LApi: IMHProcessApi;
  LSysApi: IMHSystemMetricsApi;
  LSelf: TFakeCollector;
begin
  LContainer := TMHContainer.Create;
  LClock := TMHSystemClock.Create;
  LContainer.RegisterInstance<IMHClock>(LClock);
  LLogger := TMHMemoryLogger.Create(LClock);
  LContainer.RegisterInstance<IMHLogger>(LLogger);
  LContainer.RegisterInstance<IMHLogReader>(LLogger);
  // Синтетический процесс с PID текущего процесса — отображается в блоке самодиагностики.
  LSelf := TFakeCollector.Create(TMHSelfMonitorCollector.SourceIdValue, fcmSuccess,
    GetCurrentProcessId);
  LSelf.EmitMetrics := False; // как настоящий коллектор самодиагностики
  LContainer.RegisterInstance<IMHCollector>(LSelf as IMHCollector);
  // Синтетический список процессов для таблицы.
  AProcApi := TFakeProcessApi.Create(4);
  LApi := AProcApi;
  AProcApi.Add(4, 0, 'System', FAKE_BASE_TIME + 1, 10 * FAKE_SECOND);
  AProcApi.Add(100, 4, 'explorer.exe', FAKE_BASE_TIME + 2, 5 * FAKE_SECOND);
  AProcApi.Add(200, 100, 'chrome.exe', FAKE_BASE_TIME + 3, 1 * FAKE_SECOND);
  AProcApi.AddDenied(300, 4, 'protected.exe');
  LContainer.RegisterInstance<IMHCollector>(
    TMHProcessCollector.Create(LApi, LClock) as IMHCollector);
  // Эталонные системные метрики.
  ASysApi := TFakeSystemMetricsApi.Create;
  LSysApi := ASysApi;
  LContainer.RegisterInstance<IMHCollector>(
    TMHSystemCollector.Create(LSysApi, LClock) as IMHCollector);
  // Необязательные двойники видеокарты и датчиков (после процессов — как в приложении).
  if AGpuApi <> nil then
    LContainer.RegisterInstance<IMHCollector>(
      TMHGpuCollector.Create(AGpuApi as IMHGpuApi, LClock) as IMHCollector);
  if ASensorApi <> nil then
    LContainer.RegisterInstance<IMHCollector>(
      TMHSensorCollector.Create(ASensorApi as IMHSensorApi, LClock) as IMHCollector);
  LContainer.RegisterInstance<IMHAnalyzer>(TFakeAnalyzer.Create(False) as IMHAnalyzer);
  if GTestQuarantineOps <> nil then
    LContainer.RegisterInstance<IMHQuarantineOps>(GTestQuarantineOps);
  if GTestSystemOps <> nil then
    LContainer.RegisterInstance<IMHSystemOps>(GTestSystemOps);
  if GTestRunKeyOps <> nil then
    LContainer.RegisterInstance<IMHRunKeyOps>(GTestRunKeyOps);
  LContainer.RegisterSingleton<IMHRepository>(
    function: IMHRepository
    begin
      if AHistoryPath = '' then
        raise EMHStorageError.Create('simulated storage failure');
      Result := TMHSQLiteRepository.Create(AHistoryPath, TMHStorageOptions.Default,
        LClock, LContainer.Resolve<IMHLogger>);
    end);
  Result := TMHAppServices.Create(LContainer);
  LOptions := Result.Scanner.Options;
  LOptions.IntervalMs := TMHScannerOptions.MinIntervalMs;
  Result.Scanner.Options := LOptions;
end;

{ TMainFormSmokeTests }

procedure TMainFormSmokeTests.Setup;
begin
  // Тесты не читают и не пишут настройки пользователя.
  TMHAppServices.DefaultSettingsPath := '-';
  FTempDir := NewTempDir;
  FServices := NewTestServices(FProcApi, FSysApi, TPath.Combine(FTempDir, 'history.db'));
  FForm := TMainForm.CreateWithServices(nil, FServices);
end;

procedure TMainFormSmokeTests.TearDown;
begin
  FreeAndNil(FForm);
  FreeAndNil(FServices);
  FProcApi := nil; // принадлежат коллекторам, освобождаются вместе с сервисами
  FSysApi := nil;
  CheckSynchronize(0);
  TMHAppServices.DefaultHistoryPath := '';
  TMHAppServices.DefaultSettingsPath := '';
  try
    TDirectory.Delete(FTempDir, True);
  except
    // Временный каталог тестов; блокировка антивирусом не влияет на результат.
  end;
end;

function TMainFormSmokeTests.WaitForHistory(ATimeoutMs: Cardinal): Boolean;
var
  LWatch: TStopwatch;
begin
  LWatch := TStopwatch.StartNew;
  while FForm.HistoryLoading and (LWatch.ElapsedMilliseconds < ATimeoutMs) do
    CheckSynchronize(20);
  Result := not FForm.HistoryLoading;
end;

function TMainFormSmokeTests.WaitForSnapshots(ACount: Integer; ATimeoutMs: Cardinal): Boolean;
var
  LWatch: TStopwatch;
begin
  LWatch := TStopwatch.StartNew;
  while (FForm.SnapshotCount < ACount) and (LWatch.ElapsedMilliseconds < ATimeoutMs) do
    CheckSynchronize(50);
  Result := FForm.SnapshotCount >= ACount;
end;

procedure TMainFormSmokeTests.Create_StartsOnDashboardAndStopped;
begin
  Assert.AreEqual<TMHPage>(pgDashboard, FForm.ActivePage);
  Assert.IsTrue(FForm.actStart.Enabled);
  Assert.IsFalse(FForm.actStop.Enabled);
  Assert.AreEqual(5, FForm.lbNav.Items.Count);
  Assert.IsTrue(string(FForm.lblScanState.Caption).Contains('остановлено'),
    'Состояние должно быть описано текстом');
end;

procedure TMainFormSmokeTests.Navigation_AllPagesReachable;
var
  LPage: TMHPage;
begin
  for LPage := Low(TMHPage) to High(TMHPage) do
  begin
    FForm.NavigateTo(LPage);
    Assert.AreEqual<TMHPage>(LPage, FForm.ActivePage);
    Assert.AreEqual(Integer(Ord(LPage)), FForm.lbNav.ItemIndex, 'Список навигации синхронизирован');
    Assert.IsTrue(string(FForm.Caption).Contains(FForm.lbNav.Items[Ord(LPage)]));
  end;
end;

procedure TMainFormSmokeTests.NavigationActions_SwitchPages;
begin
  FForm.actNavSettings.Execute;
  Assert.AreEqual<TMHPage>(pgSettings, FForm.ActivePage);
  FForm.actNavFindings.Execute;
  Assert.AreEqual<TMHPage>(pgFindings, FForm.ActivePage);
  FForm.actNavDashboard.Execute;
  Assert.AreEqual<TMHPage>(pgDashboard, FForm.ActivePage);
  FForm.lbNav.ItemIndex := Ord(pgHistory);
  FForm.lbNavClick(FForm.lbNav);
  Assert.AreEqual<TMHPage>(pgHistory, FForm.ActivePage);
end;

procedure TMainFormSmokeTests.StartScan_UpdatesDashboard_StopScan;
begin
  FForm.actStart.Execute;
  Assert.IsTrue(FServices.Scanner.IsRunning);
  Assert.IsFalse(FForm.actStart.Enabled);
  Assert.IsTrue(FForm.actStop.Enabled);
  Assert.IsTrue(WaitForSnapshots(2, 5000), 'Форма должна получить снимки сканера');

  Assert.AreEqual(4, FForm.lvSources.Items.Count);
  Assert.AreEqual('self', FForm.lvSources.Items[0].Caption);
  Assert.AreEqual('processes', FForm.lvSources.Items[1].Caption);
  Assert.AreEqual('system', FForm.lvSources.Items[2].Caption);
  Assert.AreEqual('storage', FForm.lvSources.Items[3].Caption);
  Assert.AreEqual(MHFormatSourceState(ssSuccess), FForm.lvSources.Items[0].SubItems[0]);
  Assert.AreEqual(FormatFloat('0.0', 12.5) + ' %', FForm.lblSelfCpu.Caption);
  Assert.AreNotEqual(MH_NO_DATA, FForm.lblSelfUpdated.Caption);

  FForm.actStop.Execute;
  Assert.IsFalse(FServices.Scanner.IsRunning);
  Assert.IsTrue(FForm.actStart.Enabled);
  Assert.IsTrue(FForm.lvEvents.Items.Count > 0, 'Журнал событий должен отображаться');
end;

procedure TMainFormSmokeTests.IntervalSetting_IsAppliedToScanner;
begin
  FForm.NavigateTo(pgSettings);
  FForm.cbInterval.ItemIndex := 2;
  FForm.cbIntervalChange(FForm.cbInterval);
  Assert.AreEqual<Cardinal>(3000, FServices.Scanner.Options.IntervalMs);
  FForm.cbInterval.ItemIndex := 0;
  FForm.cbIntervalChange(FForm.cbInterval);
  Assert.AreEqual<Cardinal>(1000, FServices.Scanner.Options.IntervalMs);
end;

procedure TMainFormSmokeTests.FreeWhileScanning_DoesNotCrash;
begin
  FForm.StartScan;
  Assert.IsTrue(WaitForSnapshots(1, 5000));
  Sleep(400); // в очереди главного потока остаются недоставленные события
  FreeAndNil(FForm);
  // После уничтожения формы очередь не должна содержать обращений к ней.
  CheckSynchronize(0);
  Assert.IsFalse(FServices.Scanner.IsRunning);
end;

procedure TMainFormSmokeTests.DefaultConfiguration_CreatesAndFrees;
var
  LForm: TMainForm;
begin
  // Стандартная конфигурация приложения (реальные коллекторы, история — во временном каталоге).
  TMHAppServices.DefaultHistoryPath := TPath.Combine(FTempDir, 'default.db');
  TMHAppServices.DefaultSettingsPath := TPath.Combine(FTempDir, 'settings.json');
  LForm := TMainForm.Create(nil);
  try
    Assert.IsNotNull(LForm.Services);
    LForm.Services.Scanner.ScanOnce;
    Assert.AreEqual(1, LForm.SnapshotCount);
    Assert.AreEqual(11, LForm.lvSources.Items.Count);
    Assert.AreEqual('system', LForm.lvSources.Items[0].Caption);
    Assert.AreEqual('processes', LForm.lvSources.Items[1].Caption);
    Assert.AreEqual('gpu', LForm.lvSources.Items[2].Caption);
    Assert.AreEqual('sensors', LForm.lvSources.Items[3].Caption);
    Assert.AreEqual('autostart', LForm.lvSources.Items[4].Caption);
    Assert.AreEqual('tamper', LForm.lvSources.Items[5].Caption);
    Assert.AreEqual('network', LForm.lvSources.Items[6].Caption);
    Assert.AreEqual('files', LForm.lvSources.Items[7].Caption);
    Assert.AreEqual('context', LForm.lvSources.Items[8].Caption);
    Assert.AreEqual('self', LForm.lvSources.Items[9].Caption);
    Assert.AreEqual('storage', LForm.lvSources.Items[10].Caption);
    Assert.AreEqual(MHFormatSourceState(ssSuccess), LForm.lvSources.Items[10].SubItems[0],
      'История стандартной конфигурации записывается');
    Assert.IsNotNull(LForm.Services.Analyzer, 'Стандартный анализатор угроз подключён');
    Assert.IsNotNull(LForm.Services.Baselines, 'Профиль нормы подключён');
    Assert.AreEqual(TPath.Combine(FTempDir, 'default.db'), LForm.Services.Storage.FileName);
    Assert.IsTrue(LForm.lvProcesses.Items.Count > 10, 'Реальный список процессов Windows');
  finally
    LForm.Free;
  end;
end;

procedure SelectRow(AForm: TMainForm; AIndex: Integer);
begin
  AForm.lvProcesses.ItemIndex := AIndex;
  AForm.lvProcesses.Items[AIndex].Selected := True;
end;

procedure TMainFormSmokeTests.Processes_TableAndDetails;
var
  LIndex: Integer;
begin
  FServices.Scanner.ScanOnce;
  FForm.NavigateTo(pgProcesses);
  Assert.AreEqual(4, FForm.lvProcesses.Items.Count);
  Assert.IsTrue(string(FForm.lblProcCount.Caption).Contains('4'));
  Assert.IsTrue(string(FForm.mmProcDetails.Text).Contains('Выберите процесс'));

  LIndex := FForm.ProcessModel.IndexOf(TMHProcessId.Create(200, FAKE_BASE_TIME + 3));
  SelectRow(FForm, LIndex);
  Assert.IsTrue(FForm.SelectedProcess = TMHProcessId.Create(200, FAKE_BASE_TIME + 3));
  Assert.IsTrue(string(FForm.mmProcDetails.Text).Contains('chrome.exe'));
  Assert.IsTrue(string(FForm.mmProcDetails.Text).Contains('explorer.exe (PID 100)'),
    'В подробностях должен быть указан родитель');
  Assert.IsTrue(string(FForm.mmProcDetails.Text).Contains('C:\Fake\chrome.exe'));

  LIndex := FForm.ProcessModel.IndexOf(TMHProcessId.Create(300, 0));
  SelectRow(FForm, LIndex);
  Assert.IsTrue(string(FForm.mmProcDetails.Text).Contains('нет доступа'));
  Assert.IsTrue(string(FForm.mmProcDetails.Text).Contains('не признак угрозы'));
end;

procedure TMainFormSmokeTests.Processes_SortByColumnClick;
begin
  FServices.Scanner.ScanOnce;
  Assert.IsTrue(string(FForm.lvProcesses.Columns[Ord(pcCpu)].Caption).Contains('▼'));
  FForm.lvProcessesColumnClick(FForm.lvProcesses, FForm.lvProcesses.Columns[Ord(pcName)]);
  Assert.AreEqual<TMHProcessColumn>(pcName, FForm.ProcessModel.SortColumn);
  Assert.IsTrue(string(FForm.lvProcesses.Columns[Ord(pcName)].Caption).Contains('▲'));
  Assert.IsFalse(string(FForm.lvProcesses.Columns[Ord(pcCpu)].Caption).Contains('▼'));
  Assert.AreEqual('chrome.exe', FForm.ProcessModel[0].Name);
end;

procedure TMainFormSmokeTests.Processes_Filter;
begin
  FServices.Scanner.ScanOnce;
  FForm.edProcFilter.Text := 'CHROME';
  Assert.AreEqual(1, FForm.lvProcesses.Items.Count);
  Assert.IsTrue(string(FForm.lblProcCount.Caption).Contains('1'));
  FForm.edProcFilter.Text := '';
  Assert.AreEqual(4, FForm.lvProcesses.Items.Count);
end;

procedure TMainFormSmokeTests.Processes_SelectionSurvivesResort;
var
  LId: TMHProcessId;
begin
  FServices.Scanner.ScanOnce;
  LId := TMHProcessId.Create(200, FAKE_BASE_TIME + 3);
  SelectRow(FForm, FForm.ProcessModel.IndexOf(LId));
  // chrome.exe начинает активно использовать CPU и поднимается в начало списка.
  FProcApi.AdvanceWall(FAKE_SECOND);
  FProcApi.SetCpu(200, 4 * FAKE_SECOND);
  FServices.Scanner.ScanOnce;
  Assert.AreEqual(0, FForm.ProcessModel.IndexOf(LId));
  Assert.IsTrue(FForm.SelectedProcess = LId, 'Выбор привязан к процессу, а не к строке');
  Assert.AreEqual(0, FForm.lvProcesses.ItemIndex);
  Assert.IsTrue(string(FForm.mmProcDetails.Text).Contains('chrome.exe'));
end;

procedure TMainFormSmokeTests.Processes_SelectedProcessExited;
begin
  FServices.Scanner.ScanOnce;
  SelectRow(FForm, FForm.ProcessModel.IndexOf(TMHProcessId.Create(200, FAKE_BASE_TIME + 3)));
  FProcApi.Remove(200);
  FServices.Scanner.ScanOnce;
  Assert.AreEqual(3, FForm.lvProcesses.Items.Count);
  Assert.AreEqual(-1, FForm.lvProcesses.ItemIndex);
  Assert.IsTrue(string(FForm.mmProcDetails.Text).Contains('больше не выполняется'));
end;

procedure TMainFormSmokeTests.Processes_SourceFailure_KeepsLastData;
begin
  FServices.Scanner.ScanOnce;
  FProcApi.EnumerateFails := True;
  FServices.Scanner.ScanOnce;
  Assert.AreEqual(4, FForm.lvProcesses.Items.Count,
    'Сбой источника не должен очищать таблицу');
  Assert.IsTrue(FForm.lvSources.Items[1].SubItems[0].Contains(MHSourceStateToString(ssError)));
end;

procedure TMainFormSmokeTests.Processes_IdleProcessIsSelectable;
var
  LDetails: TMHRawProcessDetails;
begin
  // Регрессия: идентичность PID 0 без времени создания совпадает с TMHProcessId.Empty.
  FProcApi.Add(0, 0, '[System Process]', 0);
  LDetails := Default(TMHRawProcessDetails);
  LDetails.Status := pqOk;
  FProcApi.SetDetails(0, LDetails);
  FServices.Scanner.ScanOnce;
  SelectRow(FForm, FForm.ProcessModel.IndexOf(TMHProcessId.Create(0, 0)));
  Assert.IsTrue(FForm.HasSelectedProcess);
  Assert.IsTrue(string(FForm.mmProcDetails.Text).Contains('[System Process]'));
end;

procedure TMainFormSmokeTests.Dashboard_SystemChartsAndSummary;
var
  LPoints: TArray<TMHMetric>;
begin
  FServices.Scanner.ScanOnce;
  FSysApi.Advance(10000000, 8, 25);
  FServices.Scanner.ScanOnce;
  LPoints := FForm.LiveCpuChart.Points;
  Assert.AreEqual(2, Integer(Length(LPoints)));
  Assert.IsFalse(LPoints[0].HasValue, 'Первый замер CPU — разрыв, а не ноль');
  Assert.AreEqual(25.0, LPoints[1].Value, 0.01);
  Assert.AreEqual(62.5, FForm.LiveMemoryChart.Points[1].Value, 0.01);
  Assert.AreEqual(12.5, FForm.LiveDiskChart.Points[1].Value, 0.01);
  // Карточки «Сейчас»: значения и «нет данных» у недоступных показателей.
  Assert.AreEqual('25 %', FForm.DashboardTile(tkCpu).Data.Value);
  Assert.AreEqual<TMHTileState>(tsOk, FForm.DashboardTile(tkCpu).Data.State);
  Assert.AreEqual('63 %', FForm.DashboardTile(tkMemory).Data.Value);
  Assert.IsTrue(FForm.DashboardTile(tkMemory).Data.Detail.Contains('из'));
  Assert.AreEqual(MH_NO_DATA, FForm.DashboardTile(tkGpu).Data.Value,
    'Недоступные метрики отображаются как «нет данных»');
  Assert.AreEqual<TMHTileState>(tsNoData, FForm.DashboardTile(tkGpu).Data.State);
  Assert.AreEqual(MH_NO_DATA, FForm.DashboardTile(tkTemperature).Data.Value);
  Assert.IsTrue(Length(FForm.DashboardReasons.Items) >= 3, 'Причины перечислены списком');
  Assert.IsTrue(FForm.LiveCpuChart.SummaryText.Contains('сейчас 25'));
end;

procedure TMainFormSmokeTests.History_LoadsFromStorageInBackground;
var
  I: Integer;
begin
  for I := 1 to 3 do
  begin
    FSysApi.Advance(10000000, 8, 40);
    FServices.Scanner.ScanOnce;
  end;
  FForm.NavigateTo(pgHistory);
  Assert.IsTrue(WaitForHistory(5000), 'История должна загрузиться');
  Assert.IsTrue(Length(FForm.HistoryChart(0).Points) > 0, 'CPU из истории');
  Assert.IsTrue(Length(FForm.HistoryChart(1).Points) > 0, 'Память из истории');
  Assert.IsFalse(string(FForm.lblHistoryStatus.Caption).Contains('Загрузка'));
  Assert.IsFalse(string(FForm.lblHistoryStatus.Caption).Contains('недоступна'));
end;

procedure TMainFormSmokeTests.History_PeriodChange_Reloads;
begin
  FServices.Scanner.ScanOnce;
  FForm.NavigateTo(pgHistory);
  // Повторные запросы во время загрузки не создают параллельных потоков.
  FForm.cbHistoryPeriod.ItemIndex := 3;
  FForm.cbHistoryPeriodChange(FForm.cbHistoryPeriod);
  FForm.btnHistoryRefreshClick(FForm.btnHistoryRefresh);
  Assert.IsTrue(WaitForHistory(5000));
  Assert.IsTrue(Length(FForm.HistoryChart(1).Points) > 0);
end;

procedure TMainFormSmokeTests.Settings_RetentionAndPrivacy_AppliedToStorage;
begin
  FForm.NavigateTo(pgSettings);
  Assert.IsTrue(FForm.cbRetention.Enabled);
  Assert.AreEqual(2, FForm.cbRetention.ItemIndex, 'По умолчанию 7 дней');
  Assert.IsTrue(FForm.chkStorePaths.Checked);
  Assert.AreEqual(FServices.Storage.FileName, string(FForm.lblStoragePath.Caption));

  FForm.cbRetention.ItemIndex := 4;
  FForm.cbRetentionChange(FForm.cbRetention);
  Assert.AreEqual(30, FServices.Storage.Options.RetentionDays);
  FForm.chkStorePaths.Checked := False; // вызывает OnClick
  Assert.IsFalse(FServices.Storage.Options.StoreProcessPaths);
end;

procedure TMainFormSmokeTests.Settings_ClearHistory_RequiresConfirmation;
var
  LAsked: Integer;
begin
  FServices.Scanner.ScanOnce;
  FServices.Scanner.ScanOnce;
  LAsked := 0;
  FForm.ConfirmAction :=
    function(const AQuestion: string): Boolean
    begin
      Inc(LAsked);
      Result := False;
    end;
  FForm.btnClearHistoryClick(FForm.btnClearHistory);
  Assert.AreEqual(1, LAsked);
  Assert.AreEqual<Int64>(2, FServices.Storage.GetStats.SnapshotCount, 'Без подтверждения ничего не удаляется');

  FForm.ConfirmAction :=
    function(const AQuestion: string): Boolean
    begin
      Inc(LAsked);
      Result := True;
    end;
  FForm.btnClearHistoryClick(FForm.btnClearHistory);
  Assert.AreEqual(2, LAsked);
  Assert.AreEqual<Int64>(0, FServices.Storage.GetStats.SnapshotCount);
  Assert.IsTrue(string(FForm.lblStorageStats.Caption).Contains('Записей нет'));
end;

procedure TMainFormSmokeTests.Dashboard_GpuTemperaturesAndProcessColumns;
var
  LServices: TMHAppServices;
  LForm: TMainForm;
  LProc: TFakeProcessApi;
  LSys: TFakeSystemMetricsApi;
  LGpu: TFakeGpuApi;
  LSensors: TFakeSensorApi;
  LGpuIntf: IMHGpuApi;
  LSensorIntf: IMHSensorApi;
  LSample: TMHGpuCounterSample;
  LSensor: TMHGpuSensor;
  LDisk: TMHTemperatureReading;
  LSummary: string;
  I, LRow: Integer;
begin
  LGpu := TFakeGpuApi.Create;
  LGpuIntf := LGpu;
  LGpu.Counters.Available := True;
  LSample.InstanceName := 'pid_200_luid_0x00000000_0x000102c2_phys_0_eng_0_engtype_3D';
  LSample.Value := 35;
  LGpu.Counters.Engines := [LSample];
  LSensor := Default(TMHGpuSensor);
  LSensor.AdapterName := 'GeForce';
  LSensor.Source := 'D3DKMT';
  LSensor.HasTemperature := True;
  LSensor.TemperatureCelsius := 47;
  LGpu.Sensors := [LSensor];
  LSensors := TFakeSensorApi.Create;
  LSensorIntf := LSensors;
  LDisk := Default(TMHTemperatureReading);
  LDisk.Device := 'NVMe';
  LDisk.Celsius := 52;
  LSensors.Disks := [LDisk];
  LDisk.Device := 'HDD';
  LDisk.Celsius := 41;
  LSensors.Disks := LSensors.Disks + [LDisk];
  LSensors.CpuReason := 'запустите LibreHardwareMonitor';

  LServices := NewTestServices(LProc, LSys, TPath.Combine(FTempDir, 'gpu.db'), LGpu, LSensors);
  try
    LForm := TMainForm.CreateWithServices(nil, LServices);
    try
      LServices.Scanner.ScanOnce;
      LSys.Advance(10000000, 8, 25);
      LServices.Scanner.ScanOnce;
      Assert.AreEqual(35.0, LForm.LiveGpuChart.Points[High(LForm.LiveGpuChart.Points)].Value, 0.01,
        'Живой график видеокарты');
      Assert.AreEqual('35 %', LForm.DashboardTile(tkGpu).Data.Value);
      Assert.IsTrue(LForm.DashboardTile(tkGpu).Data.Detail.Contains('вычисления 0 %'),
        LForm.DashboardTile(tkGpu).Data.Detail);
      LSummary := LForm.DashboardTile(tkTemperature).Data.Detail;
      Assert.AreEqual('52 °C', LForm.DashboardTile(tkTemperature).Data.Value,
        'Ближе всех к порогу — накопитель 52 °C (порог по умолчанию 65 °C)');
      Assert.IsTrue(LSummary.Contains('у накопителя, порог 65 °C'), LSummary);
      Assert.IsTrue(LSummary.Contains('видеокарта 47 °C'), LSummary);
      Assert.IsTrue(string(LForm.lblWhySlow.Caption).Contains('тормозить или греться'));
      // Колонки «Память» и «GPU» идут сразу после CPU, как в диспетчере задач.
      Assert.AreEqual('Память', string(LForm.lvProcesses.Columns[3].Caption).Replace(' ▲', '').Replace(' ▼', ''));
      Assert.AreEqual('GPU', string(LForm.lvProcesses.Columns[4].Caption).Replace(' ▲', '').Replace(' ▼', ''));
      LRow := -1;
      for I := 0 to LForm.lvProcesses.Items.Count - 1 do
        if LForm.lvProcesses.Items[I].Caption = 'chrome.exe' then
          LRow := I;
      Assert.IsTrue(LRow >= 0);
      Assert.AreEqual(MHFormatMetric(TMHMetric.Available(mkGpuPercent, 35, 0)),
        LForm.lvProcesses.Items[LRow].SubItems[3]);
    finally
      LForm.Free;
    end;
  finally
    LServices.Free;
  end;
end;

procedure TMainFormSmokeTests.StorageUnavailable_AppKeepsWorking;
var
  LServices: TMHAppServices;
  LForm: TMainForm;
  LProc: TFakeProcessApi;
  LSys: TFakeSystemMetricsApi;
  LStatus: TMHSourceStatus;
begin
  LServices := NewTestServices(LProc, LSys, '');
  try
    Assert.IsNull(LServices.MetricHistory);
    Assert.IsTrue(LServices.StorageError.Contains('simulated storage failure'));
    LForm := TMainForm.CreateWithServices(nil, LServices);
    try
      Assert.IsFalse(LServices.Scanner.ScanOnce.FindSource(TMHScanner.StorageSourceId, LStatus),
        'Без хранилища сканирование работает без статуса записи');
      Assert.AreEqual(4, LForm.lvProcesses.Items.Count);
      LForm.NavigateTo(pgHistory);
      Assert.IsTrue(string(LForm.lblHistoryStatus.Caption).Contains('История недоступна'));
      LForm.NavigateTo(pgSettings);
      Assert.IsFalse(LForm.cbRetention.Enabled);
      Assert.IsFalse(LForm.btnClearHistory.Enabled);
      Assert.IsTrue(string(LForm.lblStorageStats.Caption).Contains('simulated storage failure'));
    finally
      LForm.Free;
    end;
  finally
    LServices.Free;
  end;
end;

procedure TMainFormSmokeTests.Dashboard_ProtectionShowsAlerts;
begin
  Assert.IsTrue(string(FForm.lblAlerts.Caption).Contains('Ожидание'), 'До первого анализа');
  FServices.Scanner.ScanOnce;
  Assert.IsTrue(string(FForm.lblAlerts.Caption).Contains('Требуют проверки: 1'),
    string(FForm.lblAlerts.Caption));
  Assert.IsTrue(string(FForm.lblWhySlow.Caption).StartsWith('Почему компьютер может тормозить'));
  Assert.IsNotEmpty(string(FForm.lblRights.Caption));
  FForm.btnGoFindingsClick(nil);
  Assert.AreEqual<TMHPage>(pgFindings, FForm.ActivePage);
end;

procedure TMainFormSmokeTests.Processes_RiskColumnAndFilters;
var
  LIndex: Integer;
begin
  FServices.Scanner.ScanOnce;
  LIndex := FForm.ProcessModel.IndexOf(TMHProcessId.Create(200, FAKE_BASE_TIME + 3));
  Assert.AreEqual<TMHRiskLevel>(rlNeedsReview, FForm.ProcessModel.RiskOf(FForm.ProcessModel[LIndex]));
  Assert.AreEqual(MHRiskLevelToString(rlNeedsReview), FForm.lvProcesses.Items[LIndex].SubItems[9]);
  FForm.chkOnlyFindings.Checked := True;
  Assert.AreEqual(1, FForm.lvProcesses.Items.Count);
  FForm.chkOnlyFindings.Checked := False;
  FForm.chkOnlyUnsigned.Checked := True;
  Assert.AreEqual(0, FForm.lvProcesses.Items.Count, 'У поддельных процессов подпись не проверялась');
  FForm.chkOnlyUnsigned.Checked := False;
  Assert.AreEqual(4, FForm.lvProcesses.Items.Count);
end;

procedure TMainFormSmokeTests.Findings_ListCardAndExport;
var
  LHtml, LJson: string;
  LValue: TJSONValue;
begin
  FServices.Scanner.ScanOnce;
  FForm.NavigateTo(pgFindings);
  Assert.AreEqual(1, FForm.lvFindings.Items.Count);
  Assert.IsTrue(string(FForm.mmCard.Text).Contains('Выберите находку'));
  FForm.SelectFinding('test:finding');
  Assert.IsTrue(string(FForm.mmCard.Text).Contains('test finding'), string(FForm.mmCard.Text));
  Assert.IsTrue(string(FForm.mmCard.Text).Contains('chrome.exe'));
  Assert.IsTrue(string(FForm.mmCard.Text).Contains('Рекомендации'));
  Assert.IsTrue(FForm.btnStopProcess.Enabled, 'Процесс выполняется — остановка доступна');

  LHtml := TPath.Combine(FTempDir, 'report.html');
  LJson := TPath.Combine(FTempDir, 'report.json');
  FForm.ExportReport(LHtml, True);
  FForm.ExportReport(LJson, False);
  Assert.IsTrue(TFile.ReadAllText(LHtml, TEncoding.UTF8).Contains('test finding'));
  Assert.IsFalse(TFile.ReadAllText(LHtml, TEncoding.UTF8).ToLower.Contains('<script'));
  LValue := TJSONObject.ParseJSONValue(TFile.ReadAllText(LJson, TEncoding.UTF8));
  try
    Assert.IsNotNull(LValue, 'Отчёт JSON корректен');
  finally
    LValue.Free;
  end;
  FForm.ExportFindingCard(TPath.Combine(FTempDir, 'card.html'), True);
  Assert.IsTrue(TFile.ReadAllText(TPath.Combine(FTempDir, 'card.html'), TEncoding.UTF8).Contains('test finding'));

  FForm.cbFindingsMinLevel.ItemIndex := 2; // «подозрительно» и выше
  FForm.cbFindingsMinLevelChange(nil);
  Assert.AreEqual(0, FForm.lvFindings.Items.Count);
  FForm.cbFindingsMinLevel.ItemIndex := 0;
  FForm.cbFindingsMinLevelChange(nil);
  FForm.cbFindingsMode.ItemIndex := 1; // история находок из базы
  FForm.cbFindingsModeChange(nil);
  Assert.AreEqual(1, FForm.lvFindings.Items.Count, 'Находка сохранена в истории');
end;

procedure TMainFormSmokeTests.Findings_AllowProgram_AddsExclusionAndJournal;
var
  LActions: TArray<TMHActionRecord>;
begin
  FServices.Scanner.ScanOnce;
  FForm.SelectFinding('test:finding');
  FForm.ConfirmAction :=
    function(const AQuestion: string): Boolean
    begin
      Result := AQuestion.Contains('chrome.exe');
    end;
  FForm.btnAllowClick(nil);
  Assert.AreEqual(1, Integer(Length(FServices.Settings.Exclusions)));
  Assert.AreEqual(MHProgramKey('C:\Fake\chrome.exe', 'chrome.exe'), FServices.Settings.Exclusions[0].Key);
  Assert.AreEqual(0, FForm.lvFindings.Items.Count, 'Находка снята после добавления в исключения');
  Assert.AreEqual(1, FForm.lvExclusions.Items.Count);
  LActions := FServices.ActionLog.LoadActions(10);
  Assert.AreEqual('exclusion-add', LActions[0].Action);
  Assert.IsTrue(FForm.lvActionLog.Items.Count >= 1);

  FForm.lvExclusions.ItemIndex := 0;
  FForm.ConfirmAction :=
    function(const AQuestion: string): Boolean
    begin
      Result := True;
    end;
  FForm.btnRemoveExclusionClick(nil);
  Assert.AreEqual(0, Integer(Length(FServices.Settings.Exclusions)));
end;

procedure TMainFormSmokeTests.Findings_StopProcess_RequiresConfirmation;
var
  LAsked: string;
begin
  FServices.Scanner.ScanOnce;
  FForm.SelectFinding('test:finding');
  LAsked := '';
  FForm.ConfirmAction :=
    function(const AQuestion: string): Boolean
    begin
      LAsked := AQuestion;
      Result := False; // пользователь отказался — ничего не выполняется
    end;
  FForm.btnStopProcessClick(nil);
  Assert.IsTrue(LAsked.Contains('PID 200'), LAsked);
  Assert.IsTrue(LAsked.Contains('не удаляется'));
  Assert.AreEqual(0, Integer(Length(FServices.ActionLog.LoadActions(10))), 'Действие не выполнялось');
end;

procedure TMainFormSmokeTests.Findings_DefenderAndOpenLocation_ValidatePath;
var
  LWatch: TStopwatch;
begin
  FServices.Scanner.ScanOnce;
  FForm.SelectFinding('test:finding');
  // C:\Fake\chrome.exe не существует: действия отклоняются без запуска внешних программ.
  FForm.btnOpenLocationClick(nil);
  Assert.IsNotEmpty(string(FForm.lblCardStatus.Caption));
  FForm.btnDefenderClick(nil);
  LWatch := TStopwatch.StartNew;
  while FForm.DefenderRunning and (LWatch.ElapsedMilliseconds < 10000) do
    CheckSynchronize(20);
  Assert.IsFalse(FForm.DefenderRunning);
  Assert.IsFalse(string(FForm.lblCardStatus.Caption).Contains('проверяет'), string(FForm.lblCardStatus.Caption));
end;

procedure TMainFormSmokeTests.Settings_AnalysisAreAppliedAndPersisted;
var
  LServices: TMHAppServices;
  LForm: TMainForm;
  LProc: TFakeProcessApi;
  LSys: TFakeSystemMetricsApi;
  LPath: string;
begin
  LPath := TPath.Combine(FTempDir, 'persist-settings.json');
  TMHAppServices.DefaultSettingsPath := LPath;
  LServices := NewTestServices(LProc, LSys, TPath.Combine(FTempDir, 'persist.db'));
  try
    LForm := TMainForm.CreateWithServices(nil, LServices);
    try
      LForm.cbHighCpu.ItemIndex := 3; // 40%
      LForm.cbHighCpuChange(nil);
      LForm.cbSustained.ItemIndex := 0; // 5 мин
      LForm.cbSustainedChange(nil);
      LForm.chkRedactReports.Checked := False;
      Assert.AreEqual(40.0, LServices.Settings.Analyzer.HighCpuPercent, 0.001);
      Assert.AreEqual(5, LServices.Settings.Analyzer.SustainedMinutes);
      Assert.IsFalse(LServices.Settings.RedactPathsInReports);
      Assert.IsTrue(TFile.Exists(LPath), 'Настройки сохранены на диск');
      Assert.AreEqual(40.0, MHSettingsFromJson(TFile.ReadAllText(LPath, TEncoding.UTF8)).Analyzer.HighCpuPercent, 0.001);
    finally
      LForm.Free;
    end;
  finally
    LServices.Free;
    TMHAppServices.DefaultSettingsPath := '-';
  end;
end;

procedure TMainFormSmokeTests.History_ComparisonWithBaseline;
begin
  FServices.Scanner.ScanOnce;
  FServices.Scanner.ScanOnce;
  FForm.NavigateTo(pgHistory);
  Assert.IsTrue(WaitForHistory(5000));
  Assert.AreEqual(3, FForm.lvComparison.Items.Count, 'CPU, память, диск');
  Assert.IsTrue(string(FForm.lblBaselineInfo.Caption).Contains('Профиль нормы'),
    string(FForm.lblBaselineInfo.Caption));
  Assert.IsTrue(FForm.lvDeviations.Items.Count >= 1);
  FForm.btnRebuildBaselineClick(nil);
  Assert.IsTrue(string(FForm.lblBaselineInfo.Caption).Contains('перестраивается'));
end;

procedure TMainFormSmokeTests.Findings_Remediate_QuarantineAndRestore;
var
  LServices: TMHAppServices;
  LForm: TMainForm;
  LProc: TFakeProcessApi;
  LSys: TFakeSystemMetricsApi;
  LFs: TFakeQuarantineOps;
  LOs: TFakeSystemOps;
  LAsked: string;
begin
  LFs := TFakeQuarantineOps.Create;
  GTestQuarantineOps := LFs;
  LOs := TFakeSystemOps.Create;
  GTestSystemOps := LOs;
  LFs.AddFile('C:\Fake\chrome.exe', 'payload');
  try
    LServices := NewTestServices(LProc, LSys, TPath.Combine(FTempDir, 'remediate.db'));
    try
      LForm := TMainForm.CreateWithServices(nil, LServices);
      try
        Assert.IsNotNull(LForm.RemediateButton);
        Assert.IsFalse(LForm.RemediateButton.Enabled, 'Без выбранной находки исправлять нечего');
        Assert.AreEqual(0, LForm.QuarantineList.Items.Count);
        LServices.Scanner.ScanOnce;
        LForm.SelectFinding('test:finding');
        Assert.IsTrue(LForm.RemediateButton.Enabled);

        // Отказ — ничего не меняется.
        LAsked := '';
        LForm.ConfirmAction :=
          function(const AQuestion: string): Boolean
          begin
            LAsked := AQuestion;
            Result := False;
          end;
        LForm.RemediateSelected;
        Assert.IsTrue(LAsked.Contains('C:\Fake\chrome.exe'), LAsked);
        Assert.IsTrue(LAsked.Contains('PID 200'), LAsked);
        Assert.IsTrue(LAsked.Contains('Карантин'), 'План объясняет, как откатить');
        Assert.IsTrue(LFs.FileExists('C:\Fake\chrome.exe'));
        Assert.AreEqual(0, LOs.TerminateCalls);

        // Согласие — процесс останавливается, файл перемещается в карантин.
        LForm.ConfirmAction :=
          function(const AQuestion: string): Boolean
          begin
            Result := True;
          end;
        LForm.RemediateSelected;
        Assert.IsFalse(LFs.FileExists('C:\Fake\chrome.exe'), 'Файл перемещён в карантин');
        Assert.AreEqual(1, LForm.QuarantineList.Items.Count);
        Assert.IsTrue(LForm.QuarantineList.Items[0].SubItems[1].Contains('chrome.exe'));
        Assert.IsTrue(string(LForm.lblCardStatus.Caption).Contains('Исправление'),
          string(LForm.lblCardStatus.Caption));

        // Восстановление из списка.
        LForm.QuarantineList.Items[0].Selected := True;
        LForm.RestoreSelectedQuarantine;
        Assert.IsTrue(LFs.FileExists('C:\Fake\chrome.exe'), 'Файл возвращён на место');
        Assert.AreEqual(0, LForm.QuarantineList.Items.Count);
        Assert.IsTrue(Length(LServices.ActionLog.LoadActions(20)) >= 2, 'Действия записаны в журнал');
      finally
        LForm.Free;
      end;
    finally
      LServices.Free;
    end;
  finally
    GTestQuarantineOps := nil;
    GTestSystemOps := nil;
    CheckSynchronize(0);
  end;
end;

procedure TMainFormSmokeTests.Background_TrayEconomyNotifyAndAutostart;
var
  LServices: TMHAppServices;
  LForm: TMainForm;
  LProc: TFakeProcessApi;
  LSys: TFakeSystemMetricsApi;
  LRun: TFakeRunKeyOps;
  LFinding: TMHFinding;
  LNormal: Cardinal;
begin
  LRun := TFakeRunKeyOps.Create;
  GTestRunKeyOps := LRun;
  try
    LServices := NewTestServices(LProc, LSys, TPath.Combine(FTempDir, 'background.db'));
    try
      LForm := TMainForm.CreateWithServices(nil, LServices);
      try
        Assert.IsNotNull(LForm.TrayIcon);
        Assert.IsFalse(LForm.TrayIcon.Visible, 'Тесты не добавляют значок в область уведомлений');
        Assert.IsTrue(LForm.TrayCheckBox.Checked);
        Assert.IsTrue(LForm.NotifyCheckBox.Checked);
        Assert.IsTrue(LForm.EconomyCheckBox.Checked);
        Assert.IsFalse(LForm.AutostartCheckBox.Checked);

        // Экономный режим: скрытое окно опрашивает реже, открытое — как в настройках.
        LNormal := LServices.Settings.IntervalMs;
        LForm.HideToTray;
        Assert.IsTrue(LForm.HiddenToTray);
        Assert.AreEqual(TMHAppSettings.EconomyIntervalMs, LServices.Scanner.Options.IntervalMs);
        LForm.ShowFromTray;
        Assert.AreEqual(LNormal, LServices.Scanner.Options.IntervalMs);
        LForm.EconomyCheckBox.Checked := False; // OnClick сохраняет настройку
        Assert.IsFalse(LServices.Settings.EconomyWhenHidden);
        LForm.HideToTray;
        Assert.AreEqual(LNormal, LServices.Scanner.Options.IntervalMs, 'Экономный режим выключен');
        LForm.ShowFromTray;

        // Уведомления о новых тревогах.
        LFinding := Default(TMHFinding);
        LFinding.Key := 'notify:test';
        LFinding.Title := 'Скрытый майнер';
        LFinding.Level := rlHighlySuspicious;
        LFinding.Score := 95;
        Assert.IsTrue(LForm.NotifyAlerts([LFinding], Now));
        Assert.AreEqual(1, LForm.NoticeCount);
        Assert.AreEqual('notify:test', LForm.LastNotice.FindingKey);
        Assert.IsFalse(LForm.NotifyAlerts([LFinding], Now), 'Повтор не уведомляет');
        LForm.NotifyCheckBox.Checked := False;
        Assert.IsFalse(LServices.Settings.NotifyAlerts);
        LFinding.Key := 'notify:other';
        Assert.IsFalse(LForm.NotifyAlerts([LFinding], IncMinute(Now, 5)), 'Уведомления выключены');

        // Автозапуск самого MineHunter X — запись в ветке Run и журнал действий.
        LForm.AutostartCheckBox.Checked := True;
        Assert.IsTrue(LRun.Values.ContainsKey(TMHSelfAutostart.ValueName));
        Assert.IsTrue(LRun.Values[TMHSelfAutostart.ValueName].EndsWith('--minimized'));
        Assert.AreEqual('self-autostart-on', LServices.ActionLog.LoadActions(1)[0].Action);
        LForm.AutostartCheckBox.Checked := False;
        Assert.IsFalse(LRun.Values.ContainsKey(TMHSelfAutostart.ValueName));
        LRun.WriteFails := True;
        LForm.AutostartCheckBox.Checked := True;
        Assert.IsFalse(LForm.AutostartCheckBox.Checked, 'Флажок отражает фактическое состояние');
      finally
        LForm.Free;
      end;
    finally
      LServices.Free;
    end;
  finally
    GTestRunKeyOps := nil;
    CheckSynchronize(0);
  end;
end;

procedure TMainFormSmokeTests.CheckNow_ReportChangesEnergyAndPrice;
var
  LReports: Integer;
  LLast: TMHCheckReport;
begin
  LReports := 0;
  FForm.ShowCheckReport :=
    procedure(AReport: TMHCheckReport)
    begin
      Inc(LReports);
      LLast := AReport;
    end;
  Assert.IsNotNull(FForm.CheckNowButton);
  Assert.IsFalse(FServices.Scanner.IsRunning);
  // Наблюдение остановлено — проверка выполняется сразу.
  FForm.CheckNow;
  Assert.AreEqual(1, LReports);
  Assert.IsFalse(FForm.CheckPending);
  Assert.IsTrue(FForm.CheckNowButton.Enabled);
  Assert.IsNotEmpty(LLast.Headline);
  Assert.IsTrue(LLast.Text.Contains('1. ТРЕВОГИ'));
  Assert.IsTrue(LLast.Text.Contains('3. ЧТО ИЗМЕНИЛОСЬ'));
  Assert.AreEqual(1, FForm.CheckCount);
  // Обычный цикл отчёт не показывает.
  FServices.Scanner.ScanOnce;
  Assert.AreEqual(1, LReports);

  // «История»: панель изменений и электроэнергии заполняется фоновым загрузчиком.
  FForm.NavigateTo(pgHistory);
  Assert.IsTrue(WaitForHistory(10000));
  Assert.IsNotNull(FForm.ChangesList);
  Assert.IsTrue(string(FForm.EnergyLabel.Caption).Contains('Электроэнергия'),
    string(FForm.EnergyLabel.Caption));

  // Цена электроэнергии: некорректное значение отклоняется.
  FForm.PriceEdit.Text := '7,5';
  Assert.IsTrue(FForm.ApplyPriceText);
  Assert.AreEqual(7.5, FServices.Settings.ElectricityPrice, 0.0001);
  FForm.PriceEdit.Text := 'дорого';
  Assert.IsFalse(FForm.ApplyPriceText);
  Assert.AreEqual(7.5, FServices.Settings.ElectricityPrice, 0.0001);
  FForm.PriceEdit.Text := '-3';
  Assert.IsFalse(FForm.ApplyPriceText);
end;

initialization
  TDUnitX.RegisterTestFixture(TMainFormSmokeTests);

end.
