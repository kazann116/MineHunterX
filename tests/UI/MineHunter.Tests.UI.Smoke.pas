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
    function WaitForBinaryLab(ATimeoutMs: Cardinal): Boolean;
    function WriteSample(const AName: string; APatch: Boolean): string;
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
    [Test] procedure Appearance_SettingsExportImportAndUpdates;
    [Test] procedure Disks_PageTablesScanAndActions;
    [Test] procedure Scroll_ListKeepsPositionAndWheelScrollsPage;
    [Test] procedure Scroll_SelectedBelowThenScrolledUp_StaysUp;
    [Test] procedure Findings_AcknowledgeAndRemoveMark;
    [Test] procedure Launches_PageShowsJournalWithFilter;
    [Test] procedure Devices_NetworkAndGpuTabsWithTotalsAndCharts;
    [Test] procedure Disks_AttributesOfSelectedDisk;
    [Test] procedure Pages_TablesShownWholeAndWheelScrollsPage;
    [Test] procedure Settings_CheckedFindingsAfterAllowedPrograms_DataFolder;
    [Test] procedure FileActions_LaunchesAndProcesses;
    [Test] procedure Settings_RefreshRates;
    [Test] procedure BinaryLab_PageAndMenus;
    [Test] procedure BinaryLab_AnalyzeNavigateFindExportCompare;
    [Test] procedure BinaryLab_ErrorsCancelAndCloseWhileBusy;
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
  MineHunter.Core.SelfAutostart, MineHunter.Core.CheckReport, MineHunter.Core.Updates,
  MineHunter.Tests.Appearance, MineHunter.Tests.Disks, MineHunter.Tests.FileScan,
  MineHunter.Collectors.Disks, MineHunter.Core.FileScan, MineHunter.App.DisksPage,
  Winapi.CommCtrl, Winapi.Messages, Vcl.Forms, Vcl.Controls, System.Types, MineHunter.App.ListViews,
  MineHunter.Tests.Fakes, MineHunter.Core.DataDir, MineHunter.App.FileActions, Vcl.StdCtrls,
  Vcl.ComCtrls, MineHunter.App.BinaryLabPage, MineHunter.BinaryLab.Types, MineHunter.BinaryLab.Source,
  MineHunter.BinaryLab.Anomalies, MineHunter.Tests.PeBuilder;

var
  // Подмена операций ОС для тестов действий (nil — настоящие операции).
  GTestQuarantineOps: IMHQuarantineOps;
  GTestSystemOps: IMHSystemOps;
  GTestRunKeyOps: IMHRunKeyOps;
  GTestDiskApi: IMHDiskApi;

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
  if GTestDiskApi <> nil then
    LContainer.RegisterInstance<IMHCollector>(TMHDiskCollector.Create(GTestDiskApi, LClock) as IMHCollector);
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

function TMainFormSmokeTests.WaitForBinaryLab(ATimeoutMs: Cardinal): Boolean;
var
  LWatch: TStopwatch;
begin
  // Результаты потока BinaryLab приходят через TThread.Queue — как в цикле сообщений.
  LWatch := TStopwatch.StartNew;
  while FForm.BinaryLabPage.Busy and (LWatch.ElapsedMilliseconds < ATimeoutMs) do
    CheckSynchronize(20);
  Result := not FForm.BinaryLabPage.Busy;
end;

function TMainFormSmokeTests.WriteSample(const AName: string; APatch: Boolean): string;
var
  LBuilder: TTestPeBuilder;
  LCode: TBytes;
begin
  LCode := TestCodeBytes(6000);
  if APatch then
    LCode[200] := $CC;
  LBuilder := TTestPeBuilder.Create;
  try
    LBuilder.AddSection('.text', LCode, SCN_TEXT);
    LBuilder.AddSection('.data', TestConcat([TestAscii('stratum+tcp://pool.supportxmr.com:3333'), TestBytes([0]),
      TestAscii('powershell -enc SQBFAFgA'), TestBytes([0, 0])]), SCN_DATA);
    LBuilder.AddImport('KERNEL32.dll', ['LoadLibraryA', 'GetProcAddress']);
    if APatch then
      LBuilder.AddImport('ADVAPI32.dll', ['RegSetValueExW']);
    LBuilder.Overlay := TestMinimalPe;
    Result := TPath.Combine(FTempDir, AName);
    TFile.WriteAllBytes(Result, LBuilder.Build);
  finally
    LBuilder.Free;
  end;
end;

procedure TMainFormSmokeTests.BinaryLab_PageAndMenus;
var
  LPage: TMHBinaryLabPage;
begin
  Assert.AreEqual('BinaryLab', FForm.lbNav.Items[Ord(pgBinaryLab)]);
  FForm.NavigateTo(pgBinaryLab);
  Assert.AreEqual(Ord(pgBinaryLab), Ord(FForm.ActivePage));
  Assert.AreEqual(Ord(pgSettings), Ord(High(TMHPage)), 'Настройки — последняя страница');
  LPage := FForm.BinaryLabPage;
  Assert.IsNotNull(LPage);
  Assert.AreEqual(7, LPage.Tabs.PageCount);
  Assert.IsTrue(LPage.OpenButton.Enabled);
  Assert.IsFalse(LPage.CompareButton.Enabled, 'Сравнивать не с чем');
  Assert.IsFalse(LPage.ExportButton.Enabled);
  Assert.IsFalse(LPage.CancelButton.Enabled);
  Assert.IsFalse(LPage.Busy);
  // «Открыть в BinaryLab» во всех таблицах с файлами.
  Assert.IsTrue(Assigned(FForm.ProcessActions.OnBinaryLab));
  Assert.IsTrue(Assigned(FForm.ChangesActions.OnBinaryLab));
  Assert.IsTrue(Assigned(FForm.LaunchesPage.Actions.OnBinaryLab));
  Assert.IsNotNull(FServices.BinaryVerdicts);
  Assert.IsNotNull(FServices.FileApi);
end;

procedure TMainFormSmokeTests.BinaryLab_AnalyzeNavigateFindExportCompare;
var
  LPage: TMHBinaryLabPage;
  LPath, LOther: string;
  LVerdict: TMHBinaryVerdict;
  LOffset: Int64;
  LNode: TTreeNode;
  I: Integer;
begin
  LPath := WriteSample('sample.exe', False);
  LOther := WriteSample('patched.exe', True);
  LPage := FForm.BinaryLabPage;
  // Открытие из меню процесса/запуска — то же, что OpenInBinaryLab.
  FForm.OpenInBinaryLab(LPath);
  Assert.AreEqual(Ord(pgBinaryLab), Ord(FForm.ActivePage));
  Assert.IsTrue(LPage.Busy, 'Анализ идёт в фоне');
  Assert.IsTrue(LPage.CancelButton.Enabled);
  Assert.IsTrue(WaitForBinaryLab(30000), 'Анализ завершился');
  Assert.AreEqual('', LPage.LastError);
  Assert.IsTrue(LPage.HasReport);
  Assert.AreEqual(LPath, LPage.Report.Path);
  Assert.IsTrue(LPage.Report.HasAnomaly(BL_MINING_STRINGS));
  // Вкладки заполнены.
  Assert.AreEqual(Integer(Length(LPage.Report.Anomalies)), LPage.AnomalyList.Items.Count);
  Assert.IsTrue(LPage.InfoList.Items.Count > 5);
  Assert.IsTrue(LPage.StructureTree.Items.Count > 5);
  Assert.IsTrue(LPage.EntropyMap.BlockCount > 0);
  Assert.IsTrue(LPage.EmbeddedList.Items.Count >= 1, 'Программа в оверлее');
  Assert.IsTrue(LPage.StringsList.Items.Count >= 2, 'Индикаторы: пул и команда');
  Assert.AreEqual<Int64>(TFile.GetSize(LPath), LPage.HexView.DataSize);
  Assert.IsTrue(string(LPage.VerdictLabel.Caption) <> '');
  Assert.IsTrue(LPage.CompareButton.Enabled and LPage.ExportButton.Enabled);
  // Результат передан анализатору угроз.
  Assert.IsTrue(FServices.BinaryVerdicts.TryGet(LPath, '', LVerdict));
  Assert.IsTrue(Length(LVerdict.Evidence) > 0);
  Assert.IsTrue(LVerdict.MiningSignal);
  Assert.IsTrue(string(LPage.VerdictNote.Caption) <> '');
  // Фильтр строк.
  LPage.StringsCategory.ItemIndex := 0;
  LPage.StringsCategory.OnChange(LPage.StringsCategory);
  I := LPage.StringsList.Items.Count;
  LPage.StringsFilter.Text := 'stratum';
  Assert.IsTrue((LPage.StringsList.Items.Count >= 1) and (LPage.StringsList.Items.Count < I));
  // Структура: выбор секции показывает её и ставит Hex на её начало.
  LNode := nil;
  for I := 0 to LPage.StructureTree.Items.Count - 1 do
    if LPage.StructureTree.Items[I].Text = '.data' then
      LNode := LPage.StructureTree.Items[I];
  Assert.IsNotNull(LNode);
  LPage.StructureTree.Selected := LNode;
  Assert.AreEqual(1, LPage.DetailsList.Items.Count);
  Assert.AreEqual<Int64>(LPage.Report.Pe.Sections[1].RawOffset, LPage.HexView.SelStart);
  // Переход к смещению и разбор записи смещения.
  Assert.IsTrue(TMHBinaryLabPage.ParseOffset('0x40', LOffset));
  Assert.AreEqual<Int64>($40, LOffset);
  Assert.IsTrue(TMHBinaryLabPage.ParseOffset('1F4h', LOffset));
  Assert.AreEqual<Int64>($1F4, LOffset);
  Assert.IsTrue(TMHBinaryLabPage.ParseOffset('128', LOffset));
  Assert.AreEqual<Int64>(128, LOffset);
  Assert.IsTrue(TMHBinaryLabPage.ParseOffset('ff', LOffset), 'Буквы — шестнадцатеричное');
  Assert.IsFalse(TMHBinaryLabPage.ParseOffset('', LOffset));
  Assert.IsFalse(TMHBinaryLabPage.ParseOffset('12x', LOffset));
  LPage.ShowOffset($80, 4);
  Assert.AreEqual(TMHBinaryLabPage.TabHex, LPage.Tabs.ActivePageIndex);
  Assert.AreEqual<Int64>($80, LPage.HexView.SelStart);
  // Поиск в фоне.
  LPage.FindPattern(MHTextPattern('STRATUM', False), True);
  Assert.IsTrue(WaitForBinaryLab(10000));
  Assert.IsTrue(LPage.LastFindOffset > 0, 'Найдено без учёта регистра');
  Assert.AreEqual<Int64>(LPage.LastFindOffset, LPage.HexView.SelStart);
  LPage.FindPattern(MHTextPattern('no such text in file', False), False);
  Assert.IsTrue(WaitForBinaryLab(10000));
  Assert.AreEqual<Int64>(-1, LPage.LastFindOffset);
  // Экспорт.
  LPage.ExportReport(TPath.Combine(FTempDir, 'r.html'));
  LPage.ExportReport(TPath.Combine(FTempDir, 'r.json'));
  Assert.IsTrue(TFile.Exists(TPath.Combine(FTempDir, 'r.html')) and TFile.Exists(TPath.Combine(FTempDir, 'r.json')));
  // Сравнение с изменённой копией.
  LPage.CompareWith(LOther);
  Assert.IsTrue(WaitForBinaryLab(30000));
  Assert.AreEqual('', LPage.LastError);
  Assert.IsTrue(LPage.HasDiff);
  Assert.IsFalse(LPage.Diff.Identical);
  Assert.IsTrue(LPage.DiffList.Items.Count > 0);
  Assert.AreEqual(TMHBinaryLabPage.TabDiff, LPage.Tabs.ActivePageIndex);
  LPage.ExportDiff(TPath.Combine(FTempDir, 'd.html'));
  Assert.IsTrue(TFile.Exists(TPath.Combine(FTempDir, 'd.html')));
  // Отчёт после сравнения остаётся отчётом первого файла.
  Assert.AreEqual(LPath, LPage.Report.Path);
end;

procedure TMainFormSmokeTests.BinaryLab_ErrorsCancelAndCloseWhileBusy;
var
  LPage: TMHBinaryLabPage;
  LBig: string;
begin
  LPage := FForm.BinaryLabPage;
  LPage.OpenFile(TPath.Combine(FTempDir, 'нет такого файла.exe'));
  Assert.IsTrue(WaitForBinaryLab(10000));
  Assert.IsTrue(LPage.LastError <> '', 'Ошибка открытия показана');
  Assert.IsFalse(LPage.HasReport);
  Assert.IsTrue(LPage.OpenButton.Enabled);
  // Отмена: большой файл, отмена сразу после начала.
  LBig := TPath.Combine(FTempDir, 'big.bin');
  TFile.WriteAllBytes(LBig, TestRandomBytes(40 * 1024 * 1024));
  LPage.OpenFile(LBig);
  LPage.Cancel;
  Assert.IsTrue(WaitForBinaryLab(30000));
  Assert.IsFalse(LPage.Busy);
  // Закрытие окна во время анализа: поток останавливается, события не приходят в уничтоженную страницу.
  LPage.OpenFile(LBig);
  Assert.IsTrue(LPage.Busy);
  FreeAndNil(FForm);
  CheckSynchronize(50);
  Assert.Pass('Окно закрыто во время анализа без ошибок');
end;

procedure TMainFormSmokeTests.Create_StartsOnDashboardAndStopped;
begin
  Assert.AreEqual<TMHPage>(pgDashboard, FForm.ActivePage);
  Assert.IsTrue(FForm.actStart.Enabled);
  Assert.IsFalse(FForm.actStop.Enabled);
  Assert.AreEqual(Ord(High(TMHPage)) + 1, FForm.lbNav.Items.Count);
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
    Assert.AreEqual(14, LForm.lvSources.Items.Count);
    Assert.AreEqual('system', LForm.lvSources.Items[0].Caption);
    Assert.AreEqual('processes', LForm.lvSources.Items[1].Caption);
    Assert.AreEqual('processevents', LForm.lvSources.Items[2].Caption);
    Assert.AreEqual('gpu', LForm.lvSources.Items[3].Caption);
    Assert.AreEqual('sensors', LForm.lvSources.Items[4].Caption);
    Assert.AreEqual('netadapters', LForm.lvSources.Items[5].Caption);
    Assert.AreEqual('disks', LForm.lvSources.Items[6].Caption);
    Assert.AreEqual('autostart', LForm.lvSources.Items[7].Caption);
    Assert.AreEqual('tamper', LForm.lvSources.Items[8].Caption);
    Assert.AreEqual('network', LForm.lvSources.Items[9].Caption);
    Assert.AreEqual('files', LForm.lvSources.Items[10].Caption);
    Assert.AreEqual('context', LForm.lvSources.Items[11].Caption);
    Assert.AreEqual('self', LForm.lvSources.Items[12].Caption);
    Assert.AreEqual('storage', LForm.lvSources.Items[13].Caption);
    Assert.AreEqual(MHFormatSourceState(ssSuccess), LForm.lvSources.Items[13].SubItems[0],
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
        // Интервал экономного режима — из «Частоты обновления».
        LForm.RefreshCombos[0].ItemIndex := LForm.RefreshCombos[0].Items.Count - 1; // 5 мин
        LForm.RefreshCombos[0].OnChange(LForm.RefreshCombos[0]);
        Assert.AreEqual(300, LServices.Settings.EconomyIntervalSec);
        Assert.IsTrue(string(LForm.EconomyCheckBox.Caption).Contains('300'), LForm.EconomyCheckBox.Caption);
        LForm.HideToTray;
        Assert.AreEqual<Cardinal>(300000, LServices.Scanner.Options.IntervalMs);
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

procedure TMainFormSmokeTests.Appearance_SettingsExportImportAndUpdates;
var
  LPath, LError: string;
  LHttp: TFakeHttpGet;
  LWatch: TStopwatch;
  LSettings: TMHAppSettings;
  LAsked: Integer;
begin
  // Обновления по умолчанию не проверяются — без согласия запросов в интернет нет.
  Assert.IsFalse(FForm.UpdatesCheckBox.Checked);
  Assert.AreEqual(0, FForm.UpdateCount);

  // Экспорт и импорт настроек.
  LSettings := FServices.Settings;
  LSettings.ElectricityPrice := 9.25;
  LSettings.NotifyAlerts := False;
  FServices.ApplySettings(LSettings);
  LPath := TPath.Combine(FTempDir, 'exported-settings.json');
  Assert.IsTrue(FForm.ExportSettingsTo(LPath, LError), LError);
  LSettings := FServices.Settings;
  LSettings.ElectricityPrice := 1;
  LSettings.NotifyAlerts := True;
  FServices.ApplySettings(LSettings);
  LAsked := 0;
  FForm.ConfirmAction :=
    function(const AQuestion: string): Boolean
    begin
      Inc(LAsked);
      Result := False;
    end;
  Assert.IsFalse(FForm.ImportSettingsFrom(LPath, LError), 'Без подтверждения настройки не меняются');
  Assert.AreEqual(1.0, FServices.Settings.ElectricityPrice, 0.0001);
  FForm.ConfirmAction :=
    function(const AQuestion: string): Boolean
    begin
      Inc(LAsked);
      Result := True;
    end;
  Assert.IsTrue(FForm.ImportSettingsFrom(LPath, LError), LError);
  Assert.AreEqual(2, LAsked);
  Assert.AreEqual(9.25, FServices.Settings.ElectricityPrice, 0.0001);
  Assert.IsFalse(FServices.Settings.NotifyAlerts);
  Assert.IsFalse(FForm.NotifyCheckBox.Checked, 'Элементы настроек обновлены');
  Assert.AreEqual('settings-import', FServices.ActionLog.LoadActions(1)[0].Action);
  // Повреждённый и отсутствующий файлы.
  TFile.WriteAllText(TPath.Combine(FTempDir, 'broken.json'), '{"version":', TEncoding.UTF8);
  Assert.IsFalse(FForm.ImportSettingsFrom(TPath.Combine(FTempDir, 'broken.json'), LError));
  Assert.IsNotEmpty(LError);
  Assert.IsFalse(FForm.ImportSettingsFrom(TPath.Combine(FTempDir, 'missing.json'), LError));
  Assert.AreEqual(2, LAsked, 'Некорректный файл отклоняется до вопроса');

  // Проверка обновлений через поддельный HTTP: результат приходит в главный поток.
  LHttp := TFakeHttpGet.Create;
  LHttp.Status := 200;
  LHttp.Body := '{"tag_name":"v99.0.0","html_url":"https://github.com/kazann116/MineHunterX/releases/tag/v99.0.0"}';
  FForm.UpdateHttp := LHttp;
  FForm.StartUpdateCheck;
  LWatch := TStopwatch.StartNew;
  while FForm.UpdateRunning and (LWatch.ElapsedMilliseconds < 10000) do
    CheckSynchronize(20);
  Assert.IsFalse(FForm.UpdateRunning);
  Assert.AreEqual(1, FForm.UpdateCount);
  Assert.AreEqual(Ord(usAvailable), Ord(FForm.UpdateResult.State));
  Assert.AreEqual(1, LHttp.Calls);

  // Язык и тема сохраняются в настройках (язык применится после перезапуска).
  FForm.LanguageCombo.ItemIndex := 1;
  FForm.LanguageCombo.OnChange(FForm.LanguageCombo);
  Assert.AreEqual(Ord(ulEnglish), Ord(FServices.Settings.Language));
  FForm.ThemeCombo.ItemIndex := 1;
  FForm.ThemeCombo.OnChange(FForm.ThemeCombo);
  Assert.AreEqual(Ord(utDark), Ord(FServices.Settings.Theme));
end;

procedure TMainFormSmokeTests.Disks_PageTablesScanAndActions;
var
  LServices: TMHAppServices;
  LForm: TMainForm;
  LProc: TFakeProcessApi;
  LSys: TFakeSystemMetricsApi;
  LFs: TFakeScanFs;
  LQuarantineFs: TFakeQuarantineOps;
  LPage: TMHDisksPage;
  LWatch: TStopwatch;
  LStates: string;
  I, LHits: Integer;
begin
  GTestDiskApi := FakeDiskSet;
  LQuarantineFs := TFakeQuarantineOps.Create;
  GTestQuarantineOps := LQuarantineFs;
  LQuarantineFs.AddFile('D:\Downloads\xmrig.exe', 'MZ');
  try
    LServices := NewTestServices(LProc, LSys, TPath.Combine(FTempDir, 'disks.db'));
    try
      LForm := TMainForm.CreateWithServices(nil, LServices);
      try
        LPage := LForm.DisksPage;
        Assert.IsNotNull(LPage);
        LForm.NavigateTo(pgDisks);
        Assert.AreEqual(Ord(pgDisks), Ord(LForm.ActivePage));
        LServices.Scanner.ScanOnce;
        Assert.AreEqual(3, LPage.DisksView.Items.Count, 'Каждый физический диск — строкой и «Всего»');
        Assert.AreEqual('Всего', LPage.DisksView.Items[2].Caption);
        Assert.AreEqual('ST2000DM008', LPage.DisksView.Items[0].SubItems[0]);
        Assert.AreEqual('C: D:', LPage.DisksView.Items[0].SubItems[3]);
        Assert.AreEqual(3, LPage.VolumesView.Items.Count);
        LStates := '';
        for I := 0 to LPage.VolumesView.Items.Count - 1 do
          LStates := LStates + LPage.VolumesView.Items[I].Caption + '=' + LPage.VolumesView.Items[I].SubItems[6] + ' ';
        Assert.IsTrue(LStates.Contains('E:=⚠ почти заполнен'), LStates);
        Assert.IsTrue(LStates.Contains('C:=норма'), LStates);

        // Проверка файлов на виртуальной файловой системе.
        LFs := TFakeScanFs.Create;
        LFs.AddFile('D:\Downloads\xmrig.exe', 'MZ');
        LFs.AddFile('D:\Downloads\config.json', '{"donate-level": 1, "url": "stratum+tcp://p:1"}');
        LFs.AddFile('D:\Docs\letter.txt', 'hello');
        LPage.ScanFs := LFs;
        LPage.ScanRoots := ['D:\'];
        LPage.StartScan;
        Assert.IsTrue(LPage.ScanRunning);
        LWatch := TStopwatch.StartNew;
        while LPage.ScanRunning and (LWatch.ElapsedMilliseconds < 15000) do
          CheckSynchronize(20);
        Assert.IsFalse(LPage.ScanRunning);
        Assert.AreEqual(1, LPage.ScanCount);
        LHits := Length(LPage.ScanHits);
        Assert.AreEqual(2, LHits);
        Assert.AreEqual(2, LPage.HitsView.Items.Count);
        Assert.IsTrue(LServices.Settings.LastFileScanUtc > 0, 'Время проверки запомнено');
        Assert.IsTrue(string(LPage.ScanLabel.Caption).Contains('найдено 2'), string(LPage.ScanLabel.Caption));
        Assert.AreEqual('file-scan', LServices.ActionLog.LoadActions(1)[0].Action);

        // Карантин из результатов (с подтверждением) и «это мой файл».
        LForm.ConfirmAction :=
          function(const AQuestion: string): Boolean
          begin
            Result := True;
          end;
        for I := 0 to LPage.HitsView.Items.Count - 1 do
          if string(LPage.HitsView.Items[I].SubItems[2]).ToLower.EndsWith('xmrig.exe') then
            LPage.HitsView.Items[I].Selected := True;
        LPage.QuarantineSelected;
        Assert.IsFalse(LQuarantineFs.FileExists('D:\Downloads\xmrig.exe'), 'Файл перемещён в карантин');
        Assert.AreEqual(1, Integer(Length(LPage.ScanHits)));
        LPage.HitsView.Items[0].Selected := True;
        LPage.AllowSelected;
        Assert.AreEqual(0, Integer(Length(LPage.ScanHits)));
        Assert.AreEqual(1, Integer(Length(LServices.Settings.Exclusions)));

        // Повторная проверка: исключённый файл больше не находится.
        LPage.StartScan;
        LWatch := TStopwatch.StartNew;
        while LPage.ScanRunning and (LWatch.ElapsedMilliseconds < 15000) do
          CheckSynchronize(20);
        Assert.AreEqual(1, Integer(Length(LPage.ScanHits)), 'Остался только xmrig.exe в виртуальной ФС');

        // Отмена.
        LPage.StartScan;
        LPage.CancelScan;
        LWatch := TStopwatch.StartNew;
        while LPage.ScanRunning and (LWatch.ElapsedMilliseconds < 15000) do
          CheckSynchronize(20);
        Assert.IsFalse(LPage.ScanRunning);

        // Плановая проверка: включается флажком, срабатывает только в простое.
        LPage.WeeklyCheckBox.Checked := True;
        Assert.IsTrue(LServices.Settings.FileScanWeekly);
      finally
        LForm.Free;
      end;
    finally
      LServices.Free;
    end;
  finally
    GTestDiskApi := nil;
    GTestQuarantineOps := nil;
    CheckSynchronize(0);
  end;
end;

procedure TMainFormSmokeTests.Scroll_ListKeepsPositionAndWheelScrollsPage;
var
  I, LTop: Integer;
  LRect: TRect;
  LHandled: Boolean;
  LPoint: TPoint;
begin
  // Окно показывается: прокрутка и поиск окна под курсором требуют настоящей геометрии.
  FForm.SetBounds(0, 0, 1200, 800);
  FForm.Show;
  // Поверх остальных окон: поиск окна под курсором (WindowFromPoint) не должен попасть в чужое окно.
  SetWindowPos(FForm.Handle, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE or SWP_NOSIZE or SWP_NOACTIVATE);
  try
    for I := 1 to 150 do
      FProcApi.Add(1000 + I, 4, Format('proc%.3d.exe', [I]), FAKE_BASE_TIME + UInt64(I));
    FServices.Scanner.ScanOnce;
    FForm.NavigateTo(pgProcesses);
    Application.ProcessMessages;
    Assert.IsTrue(FForm.lvProcesses.Items.Count > 100, 'строк: ' + IntToStr(FForm.lvProcesses.Items.Count));
    // Пользователь выбрал строку вверху и прокрутил таблицу вниз.
    FForm.lvProcesses.ItemIndex := 1;
    Application.ProcessMessages;
    Assert.IsTrue(ListView_GetItemRect(FForm.lvProcesses.Handle, 0, LRect, LVIR_BOUNDS), 'прямоугольник строки');
    ListView_Scroll(FForm.lvProcesses.Handle, 0, (LRect.Bottom - LRect.Top) * 80);
    LTop := MHListTopIndex(FForm.lvProcesses);
    Assert.IsTrue(LTop > 50, IntToStr(LTop));
    FServices.Scanner.ScanOnce;
    Application.ProcessMessages;
    Assert.AreEqual(LTop, MHListTopIndex(FForm.lvProcesses), 'Обновление не возвращает к выделенной строке');
    Assert.AreEqual(1, FForm.lvProcesses.ItemIndex, 'Выделение сохранено');

    // Колесо над «Обзором» прокручивает страницу.
    FForm.NavigateTo(pgDashboard);
    FForm.ClientHeight := 400; // страница не помещается — появляется полоса прокрутки
    Application.ProcessMessages;
    FForm.sbDashboard.VertScrollBar.Position := 0;
    LPoint := FForm.sbDashboard.ClientToScreen(Point(FForm.sbDashboard.ClientWidth div 2, 20));
    LHandled := False;
    FForm.OnMouseWheel(FForm, [], -WHEEL_DELTA, LPoint, LHandled);
    Assert.IsTrue(LHandled, 'колесо не обработано; под курсором: ' + FindVCLWindow(LPoint).ClassName + ', полоса: ' +
      BoolToStr(FForm.sbDashboard.VertScrollBar.IsScrollBarVisible, True));
    Assert.IsTrue(FForm.sbDashboard.VertScrollBar.Position > 0, 'Страница прокручена колесом');
    // Над таблицей колесо достаётся самой таблице.
    LPoint := FForm.lvSources.ClientToScreen(Point(10, 10));
    if FindVCLWindow(LPoint) = FForm.lvSources then
    begin
      LHandled := False;
      FForm.OnMouseWheel(FForm, [], -WHEEL_DELTA, LPoint, LHandled);
      Assert.IsFalse(LHandled);
    end;
  finally
    SetWindowPos(FForm.Handle, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE or SWP_NOSIZE or SWP_NOACTIVATE);
    FForm.Hide;
  end;
end;

procedure TMainFormSmokeTests.Scroll_SelectedBelowThenScrolledUp_StaysUp;
var
  I, LRow: Integer;
  LRect: TRect;
  LSelectedName: string;
begin
  // Сценарий из отзыва: прокрутил вниз, выделил строку, вернулся наверх —
  // обновление не должно уводить таблицу обратно к выделенной строке, даже если
  // порядок строк изменился.
  FForm.SetBounds(0, 0, 1200, 800);
  FForm.Show;
  try
    for I := 1 to 150 do
      FProcApi.Add(1000 + I, 4, Format('proc%.3d.exe', [I]), FAKE_BASE_TIME + UInt64(I));
    FServices.Scanner.ScanOnce;
    FForm.NavigateTo(pgProcesses);
    Application.ProcessMessages;
    Assert.IsTrue(ListView_GetItemRect(FForm.lvProcesses.Handle, 0, LRect, LVIR_BOUNDS));
    ListView_Scroll(FForm.lvProcesses.Handle, 0, (LRect.Bottom - LRect.Top) * 110);
    LRow := MHListTopIndex(FForm.lvProcesses) + 3;
    FForm.lvProcesses.Items[LRow].Selected := True;
    FForm.lvProcesses.Items[LRow].Focused := True;
    Application.ProcessMessages;
    LSelectedName := FForm.lvProcesses.Items[LRow].Caption;
    // Пользователь вернулся наверх.
    FForm.lvProcesses.Perform(WM_VSCROLL, SB_TOP, 0);
    Application.ProcessMessages;
    Assert.AreEqual(0, MHListTopIndex(FForm.lvProcesses));
    // Порядок строк меняется: новые процессы и нагрузка.
    for I := 1 to 5 do
      FProcApi.Add(2000 + I, 4, Format('aaa%.3d.exe', [I]), FAKE_BASE_TIME + UInt64(500 + I));
    FProcApi.SetCpu(1000 + 140, 50000000);
    for I := 1 to 3 do
    begin
      FServices.Scanner.ScanOnce;
      Application.ProcessMessages;
      Assert.AreEqual(0, MHListTopIndex(FForm.lvProcesses), 'Цикл ' + IntToStr(I) + ': таблица вернулась к выделенной строке');
    end;
    Assert.IsNotNull(FForm.lvProcesses.Selected, 'Выделение сохранено');
    Assert.AreEqual(LSelectedName, FForm.lvProcesses.Selected.Caption);
  finally
    FForm.Hide;
  end;
end;

procedure TMainFormSmokeTests.Findings_AcknowledgeAndRemoveMark;
var
  LAsked: string;
begin
  FServices.Scanner.ScanOnce;
  FForm.SelectFinding('test:finding');
  Assert.IsTrue(FForm.AckButton.Enabled);
  LAsked := '';
  FForm.ConfirmAction :=
    function(const AQuestion: string): Boolean
    begin
      LAsked := AQuestion;
      Result := False;
    end;
  FForm.AcknowledgeSelected;
  Assert.IsTrue(LAsked.Contains('test finding'), LAsked);
  Assert.AreEqual(0, Integer(Length(FServices.Settings.Acknowledged)), 'Без подтверждения ничего не меняется');
  FForm.ConfirmAction :=
    function(const AQuestion: string): Boolean
    begin
      Result := True;
    end;
  FForm.SelectFinding('test:finding');
  FForm.AcknowledgeSelected;
  Assert.AreEqual(1, Integer(Length(FServices.Settings.Acknowledged)));
  Assert.AreEqual('test:finding', FServices.Settings.Acknowledged[0].Key);
  Assert.AreEqual(0, FForm.lvFindings.Items.Count, 'Находка сразу убрана из тревог');
  Assert.AreEqual(1, FForm.AckList.Items.Count);
  Assert.AreEqual('acknowledge', FServices.ActionLog.LoadActions(1)[0].Action);
  FForm.AckList.Items[0].Selected := True;
  FForm.RemoveSelectedAcknowledgement;
  Assert.AreEqual(0, Integer(Length(FServices.Settings.Acknowledged)));
  Assert.AreEqual(0, FForm.AckList.Items.Count);
end;

procedure TMainFormSmokeTests.Launches_PageShowsJournalWithFilter;
var
  LSnapshot: TMHSnapshot;
  LRecord: TMHLaunchRecord;
  LNow: TDateTime;
  I: Integer;
begin
  LNow := FServices.Clock.NowUtc;
  LSnapshot := TMHSnapshot.Create(1, LNow);
  for I := 1 to 3 do
  begin
    LRecord := Default(TMHLaunchRecord);
    LRecord.Pid := 1000 + I;
    LRecord.CreateTime := UInt64(133000000000000000) + UInt64(I) * UInt64(10000000);
    LRecord.StartUtc := LNow - I / MinsPerDay;
    LRecord.Name := Format('app%d.exe', [I]);
    LRecord.ImagePath := 'C:\Apps\' + LRecord.Name;
    LRecord.ParentName := 'explorer.exe';
    LRecord.Source := 'poll';
    if I = 2 then
      LRecord.ExitUtc := LRecord.StartUtc + 5 / SecsPerDay;
    LSnapshot.LaunchEvents := LSnapshot.LaunchEvents + [LRecord];
  end;
  FServices.Storage.SaveSnapshot(LSnapshot);
  FForm.NavigateTo(pgLaunches);
  Assert.AreEqual(Ord(pgLaunches), Ord(FForm.ActivePage));
  Assert.AreEqual(3, FForm.LaunchesPage.List.Items.Count);
  Assert.AreEqual('app1.exe', FForm.LaunchesPage.List.Items[0].SubItems[0], 'Новые первыми');
  Assert.AreEqual('explorer.exe', FForm.LaunchesPage.List.Items[0].SubItems[2]);
  Assert.AreEqual('работает', FForm.LaunchesPage.List.Items[0].SubItems[3]);
  Assert.IsTrue(FForm.LaunchesPage.List.Items[1].SubItems[3].Contains('5'), 'app2 работала 5 с');
  FForm.LaunchesPage.FilterEdit.Text := 'APP3'; // OnChange перечитывает журнал
  Assert.AreEqual(1, FForm.LaunchesPage.List.Items.Count);
  Assert.AreEqual('app3.exe', FForm.LaunchesPage.List.Items[0].SubItems[0]);
end;

procedure TMainFormSmokeTests.Settings_RefreshRates;
var
  LCombo: TComboBox;
begin
  Assert.AreEqual(6, Integer(Length(FForm.RefreshCombos)));
  Assert.IsTrue(FForm.RefreshBox.Top > FForm.gbStorage.Top, 'После «Истории наблюдений»');
  Assert.IsTrue(FForm.gbAnalysis.Top > FForm.RefreshBox.Top);
  // Значения по умолчанию выбраны.
  Assert.AreEqual('раз в 5 с', string(FForm.RefreshCombos[1].Text));
  Assert.AreEqual('раз в 10 мин', string(FForm.RefreshCombos[4].Text));
  // Датчики видеокарт — «выкл.».
  LCombo := FForm.RefreshCombos[1];
  LCombo.ItemIndex := 0;
  LCombo.OnChange(LCombo);
  Assert.AreEqual(0, FServices.Settings.Refresh.GpuSensorsSec);
  Assert.IsTrue(string(LCombo.Text).Contains('Проверить сейчас'), LCombo.Text);
  // «Запуски» — только по кнопке.
  LCombo := FForm.RefreshCombos[5];
  LCombo.ItemIndex := 0;
  LCombo.OnChange(LCombo);
  Assert.AreEqual(0, FServices.Settings.LaunchesReloadSec);
  Assert.AreEqual(0, FForm.LaunchesPage.ReloadSec);
  // Основной опрос: больше вариантов (до минуты).
  Assert.AreEqual(8, FForm.cbInterval.Items.Count);
end;

procedure TMainFormSmokeTests.FileActions_LaunchesAndProcesses;
var
  LRecord: TMHLaunchRecord;
  LTarget: TMHFileTarget;
  LText: string;
begin
  // «Запуски»: путь, параметры, кто запустил — в подробностях.
  LRecord := Default(TMHLaunchRecord);
  LRecord.Pid := 4242;
  LRecord.Name := 'setup.exe';
  LRecord.ImagePath := 'C:\Users\User\Downloads\setup.exe';
  LRecord.CommandLine := '"C:\Users\User\Downloads\setup.exe" /S';
  LRecord.ParentPid := 100;
  LRecord.ParentName := 'explorer.exe';
  LRecord.StartUtc := FServices.Clock.NowUtc;
  LTarget := FForm.LaunchesPage.TargetOf(LRecord);
  LText := MHFileDetailsText(LTarget);
  Assert.IsTrue(LText.Contains('Параметры запуска: /S'), LText);
  Assert.IsTrue(LText.Contains('Кто запустил: explorer.exe (PID 100)'), LText);
  Assert.IsTrue(FForm.LaunchesPage.List.PopupMenu <> nil, 'Меню действий в «Запусках»');
  // «Процессы»: выбранная строка — путь, PID и подпись.
  FServices.Scanner.ScanOnce;
  FForm.NavigateTo(pgProcesses);
  Application.ProcessMessages;
  Assert.IsTrue(FForm.lvProcesses.Items.Count > 0);
  FForm.lvProcesses.ItemIndex := 0;
  Assert.IsTrue(FForm.ProcessTarget(LTarget));
  Assert.IsNotEmpty(LTarget.Title);
  Assert.IsTrue(string.Join(' ', LTarget.Details).Contains('PID'));
  Assert.IsTrue(FForm.lvProcesses.PopupMenu = FForm.ProcessActions.Menu);
  Assert.IsTrue(FForm.ChangesList.PopupMenu = FForm.ChangesActions.Menu, 'Меню в «Что изменилось»');
end;

procedure TMainFormSmokeTests.Settings_CheckedFindingsAfterAllowedPrograms_DataFolder;
var
  LRoot, LTarget, LError, LAsked: string;
  LRestarted: Boolean;
  LPointer: TMHDataDirPointer;
begin
  // «Проверенные находки» — сразу после «Разрешённых программ», затем журнал действий.
  Assert.IsTrue(FForm.AckBox.Top > FForm.gbExclusions.Top);
  Assert.IsTrue(FForm.AckBox.Top - (FForm.gbExclusions.Top + FForm.gbExclusions.Height) <= 24,
    'Сразу под «Разрешёнными программами»');
  Assert.IsTrue(FForm.gbActionLog.Top > FForm.AckBox.Top + FForm.AckBox.Height, 'Журнал действий — ниже');

  // Папка данных: подтверждение, указатель и перезапуск (в тестовой стандартной папке).
  LRoot := TPath.Combine(TPath.GetTempPath, 'MineHunterTests\ui-datadir-' +
    TGUID.NewGuid.ToString.Replace('{', '').Replace('}', ''));
  try
    FForm.DataDirRoot := TPath.Combine(LRoot, 'Standard');
    ForceDirectories(FForm.DataDirRoot);
    LTarget := TPath.Combine(LRoot, 'Moved');
    LRestarted := False;
    FForm.RestartAction :=
      procedure
      begin
        LRestarted := True;
      end;
    LAsked := '';
    FForm.ConfirmAction :=
      function(const AQuestion: string): Boolean
      begin
        LAsked := AQuestion;
        Result := False;
      end;
    Assert.IsFalse(FForm.ChangeDataFolder(LTarget, LError));
    Assert.IsTrue(LAsked.Contains(LTarget), LAsked);
    Assert.IsTrue(LAsked.Contains('останется'), 'Старая папка не удаляется: ' + LAsked);
    Assert.IsFalse(LRestarted, 'Без подтверждения ничего не меняется');
    Assert.IsFalse(MHReadDataDirPointer(FForm.DataDirRoot, LPointer));
    FForm.ConfirmAction :=
      function(const AQuestion: string): Boolean
      begin
        Result := True;
      end;
    Assert.IsTrue(FForm.ChangeDataFolder(LTarget, LError), LError);
    Assert.IsTrue(LRestarted, 'Перезапуск для переноса');
    Assert.IsTrue(MHReadDataDirPointer(FForm.DataDirRoot, LPointer));
    Assert.AreEqual(LTarget, LPointer.DataDir);
    Assert.IsTrue(FForm.DefaultDataButton.Enabled, 'Можно вернуть стандартную папку');
    Assert.IsFalse(FForm.ChangeDataFolder('relative', LError));
    Assert.IsNotEmpty(LError);
  finally
    try
      TDirectory.Delete(LRoot, True);
    except
      // Временный каталог тестов.
    end;
  end;
end;

function IoProcess(APid: Cardinal; const AName: string): TMHProcessInfo;
begin
  Result := TMHProcessInfo.Create(TMHProcessId.Create(APid, APid), AName, Now);
  Result.IoRead := TMHMetric.Available(mkDiskReadBytesPerSec, 1024 * 1024, Now);
  Result.IoWrite := TMHMetric.Available(mkDiskWriteBytesPerSec, 0, Now);
end;

procedure TMainFormSmokeTests.Pages_TablesShownWholeAndWheelScrollsPage;
var
  LPage: TMHDisksPage;
  LSnapshot: TMHSnapshot;
  LVolumes: TArray<TMHVolumeInfo>;
  I, LBefore, LIoHeight: Integer;
  LHandled: Boolean;
  LPoint: TPoint;
  LMsg: TMsg;
begin
  FForm.SetBounds(0, 0, 1200, 700);
  FForm.Show;
  SetWindowPos(FForm.Handle, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE or SWP_NOSIZE or SWP_NOACTIVATE);
  try
    // «Устройства»: 14 разделов — таблица целиком, прокручивается вся вкладка.
    LPage := FForm.DisksPage;
    FForm.NavigateTo(pgDisks);
    LPage.Tabs.ActivePageIndex := 0;
    SetLength(LVolumes, 14);
    for I := 0 to High(LVolumes) do
    begin
      LVolumes[I] := Default(TMHVolumeInfo);
      LVolumes[I].Name := Chr(Ord('C') + I) + ':';
      LVolumes[I].TotalBytes := Int64(100) * 1024 * 1024 * 1024;
      LVolumes[I].FreeBytes := Int64(50) * 1024 * 1024 * 1024;
    end;
    LSnapshot := TMHSnapshot.Create(1, FServices.Clock.NowUtc);
    LSnapshot.Volumes := LVolumes;
    LPage.UpdateSnapshot(LSnapshot);
    Application.ProcessMessages;
    Assert.AreEqual(14, LPage.VolumesView.Items.Count);
    Assert.IsFalse(MHListCanScroll(LPage.VolumesView), 'Разделы — без своей прокрутки');
    Assert.IsFalse(MHListCanScroll(LPage.IoView));
    // Высота «Кто читает и пишет» не зависит от числа программ (иначе прыгает полоса прокрутки).
    LIoHeight := LPage.IoView.Height;
    LSnapshot := TMHSnapshot.Create(2, FServices.Clock.NowUtc);
    LSnapshot.Volumes := LVolumes;
    LSnapshot.Processes := [IoProcess(4001, 'a.exe'), IoProcess(4002, 'b.exe')];
    LPage.UpdateSnapshot(LSnapshot);
    Assert.AreEqual(2, LPage.IoView.Items.Count);
    Assert.AreEqual(LIoHeight, LPage.IoView.Height, 'Две программы — та же высота');
    LSnapshot := TMHSnapshot.Create(3, FServices.Clock.NowUtc);
    LSnapshot.Volumes := LVolumes;
    LPage.UpdateSnapshot(LSnapshot);
    Assert.AreEqual(LIoHeight, LPage.IoView.Height, 'Ни одной — та же высота');
    Assert.IsTrue(LPage.DiskScroll.VertScrollBar.IsScrollBarVisible, 'Прокручивается вкладка');
    LPage.DiskScroll.VertScrollBar.Position := 0;
    LPoint := LPage.VolumesView.ClientToScreen(Point(20, 40));
    LHandled := False;
    FForm.OnMouseWheel(FForm, [], -WHEEL_DELTA, LPoint, LHandled);
    Assert.IsTrue(LHandled, 'Колесо над таблицей без прокрутки — странице');
    Assert.IsTrue(LPage.DiskScroll.VertScrollBar.Position > 0);
    // То же через сообщение приложения — независимо от того, у какого элемента фокус.
    LPage.DiskScroll.VertScrollBar.Position := 0;
    FForm.lbNav.SetFocus;
    LMsg := Default(TMsg);
    LMsg.message := WM_MOUSEWHEEL;
    LMsg.wParam := WPARAM(Cardinal(Word(SmallInt(-WHEEL_DELTA))) shl 16);
    LMsg.lParam := LPARAM(Cardinal(Word(LPoint.X)) or (Cardinal(Word(LPoint.Y)) shl 16));
    LHandled := False;
    FForm.HandleAppMessage(LMsg, LHandled);
    Assert.IsTrue(LHandled, 'Колесо обработано до раздачи по фокусу');
    Assert.IsTrue(LPage.DiskScroll.VertScrollBar.Position > 0, 'Прокручена страница под курсором, а не список разделов');

    // «История»: сравнение с нормой и «что изменилось» — целиком, страница прокручивается.
    FForm.NavigateTo(pgHistory);
    Application.ProcessMessages;
    Assert.IsTrue(FForm.pnlBaseline.Parent = FForm.HistoryScroll, 'Сравнение — на прокручиваемой странице');
    FForm.lvComparison.Items.Clear;
    for I := 1 to 6 do
      FForm.lvComparison.Items.Add.Caption := 'row' + IntToStr(I);
    FForm.lvDeviations.Items.Clear;
    for I := 1 to 8 do
      FForm.lvDeviations.Items.Add.Caption := 'prog' + IntToStr(I);
    FForm.LayoutHistory;
    Application.ProcessMessages;
    Assert.IsFalse(MHListCanScroll(FForm.lvComparison), 'Таблица сравнения без своей прокрутки');
    Assert.IsFalse(MHListCanScroll(FForm.lvDeviations));
    Assert.IsFalse(MHListCanScroll(FForm.ChangesList));
    Assert.IsTrue(FForm.lvDeviations.Top >= FForm.lvComparison.Top + FForm.lvComparison.Height,
      'Таблицы не наезжают друг на друга');
    Assert.IsTrue(FForm.HistoryScroll.VertScrollBar.IsScrollBarVisible, 'Страница «История» прокручивается');
    LBefore := FForm.HistoryScroll.VertScrollBar.Position;
    LPoint := FForm.HistoryScroll.ClientToScreen(Point(FForm.HistoryScroll.ClientWidth div 2, 40));
    LHandled := False;
    FForm.OnMouseWheel(FForm, [], -WHEEL_DELTA, LPoint, LHandled);
    Assert.IsTrue(FForm.HistoryScroll.VertScrollBar.Position > LBefore, 'Колесо прокручивает «Историю»');
  finally
    SetWindowPos(FForm.Handle, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE or SWP_NOSIZE or SWP_NOACTIVATE);
    FForm.Hide;
  end;
end;

procedure TMainFormSmokeTests.Disks_AttributesOfSelectedDisk;
var
  LPage: TMHDisksPage;
  LSnapshot: TMHSnapshot;
  LDisk: TMHDiskInfo;
  LAttribute: TMHDiskAttribute;
begin
  LPage := FForm.DisksPage;
  LSnapshot := TMHSnapshot.Create(1, FServices.Clock.NowUtc);
  LDisk := TMHDiskInfo.Create(0, 'WDC WD10JUCT');
  LDisk.Bus := 'SATA';
  LSnapshot.Disks := [LDisk];
  LDisk := TMHDiskInfo.Create(1, 'WD Blue SN570');
  LDisk.Bus := 'NVMe';
  LDisk.AttributesSource := 'NVMe';
  LAttribute := Default(TMHDiskAttribute);
  LAttribute.Id := 12;
  LAttribute.Current := -1;
  LAttribute.Worst := -1;
  LAttribute.Threshold := -1;
  LAttribute.Raw := 1748;
  LDisk.Attributes := [LAttribute];
  LAttribute.Id := 2;
  LAttribute.Raw := 305;
  LDisk.Attributes := LDisk.Attributes + [LAttribute];
  LSnapshot.Disks := LSnapshot.Disks + [LDisk];
  LPage.UpdateSnapshot(LSnapshot);
  // Без выбора — первый диск с атрибутами.
  Assert.IsTrue(string(LPage.AttributesCaption.Caption).Contains('SN570'), LPage.AttributesCaption.Caption);
  Assert.AreEqual(2, LPage.AttributesView.Items.Count);
  Assert.AreEqual('0C', LPage.AttributesView.Items[0].Caption);
  Assert.AreEqual('Часы работы', LPage.AttributesView.Items[0].SubItems[0]);
  Assert.AreEqual('1748 ч', LPage.AttributesView.Items[0].SubItems[1]);
  Assert.AreEqual('32 °C', LPage.AttributesView.Items[1].SubItems[1]);
  // Выбран SATA-диск без SMART — понятная причина.
  LPage.DisksView.Items[0].Selected := True;
  Assert.IsTrue(string(LPage.AttributesCaption.Caption).Contains('WD10JUCT'), LPage.AttributesCaption.Caption);
  Assert.AreEqual(1, LPage.AttributesView.Items.Count);
  Assert.IsTrue(LPage.AttributesView.Items[0].SubItems[0].Contains('правами администратора'), LPage.AttributesView.Items[0].SubItems[0]);
  // Обновление сохраняет выбранный диск и его график (не сбрасывается на «Всего»).
  LPage.UpdateSnapshot(LSnapshot);
  Assert.IsTrue(string(LPage.AttributesCaption.Caption).Contains('WD10JUCT'));
  Assert.IsTrue(LPage.DiskChart.Title.Contains('WD10JUCT'), LPage.DiskChart.Title);
  LPage.UpdateSnapshot(LSnapshot);
  Assert.IsTrue(LPage.DiskChart.Title.Contains('WD10JUCT'), 'Второе обновление: ' + LPage.DiskChart.Title);
  // NVMe-диск: наработка и прочие поля пришли в таблицу дисков.
  LPage.DisksView.Items[1].Selected := True;
  Assert.AreEqual(2, LPage.AttributesView.Items.Count);
end;

procedure TMainFormSmokeTests.Devices_NetworkAndGpuTabsWithTotalsAndCharts;
var
  LPage: TMHDisksPage;
  LSnapshot: TMHSnapshot;
  LNet: TMHNetAdapterInfo;
  LGpu: TMHGpuAdapterInfo;
  I: Integer;
begin
  LPage := FForm.DisksPage;
  Assert.AreEqual(3, LPage.Tabs.PageCount, 'Диски, сеть, видеокарты');
  for I := 1 to 5 do
  begin
    LSnapshot := TMHSnapshot.Create(I, FServices.Clock.NowUtc + I / SecsPerDay);
    LNet := Default(TMHNetAdapterInfo);
    LNet.Index := 5;
    LNet.Name := 'Ethernet';
    LNet.Kind := nkEthernet;
    LNet.Physical := True;
    LNet.Connected := True;
    LNet.LinkSpeedBps := 1000000000;
    LNet.HasRate := True;
    LNet.ReceiveBytesPerSec := 1000 * I;
    LNet.SendBytesPerSec := 100;
    LSnapshot.NetAdapters := [LNet];
    LNet.Index := 6;
    LNet.Name := 'Wi-Fi';
    LNet.Kind := nkWifi;
    LNet.ReceiveBytesPerSec := 500;
    LSnapshot.NetAdapters := LSnapshot.NetAdapters + [LNet];
    LGpu := Default(TMHGpuAdapterInfo);
    LGpu.Key := 'luid_a_phys_0';
    LGpu.Name := 'GPU A';
    LGpu.HasLoad := True;
    LGpu.LoadPercent := 10 * I;
    LGpu.HasPower := True;
    LGpu.PowerWatts := 50;
    LSnapshot.GpuAdapters := [LGpu];
    LGpu.Key := 'luid_b_phys_0';
    LGpu.Name := 'GPU B';
    LGpu.LoadPercent := 5;
    LSnapshot.GpuAdapters := LSnapshot.GpuAdapters + [LGpu];
    LPage.RecordHistory(LSnapshot);
  end;
  LPage.UpdateSnapshot(LSnapshot);
  Assert.AreEqual(3, LPage.NetView.Items.Count, 'Два адаптера и «Всего»');
  Assert.AreEqual('Всего', LPage.NetView.Items[2].Caption);
  Assert.AreEqual('проводная (Ethernet)', LPage.NetView.Items[0].SubItems[0]);
  Assert.AreEqual('40 кбит/с', LPage.NetView.Items[0].SubItems[3], 'Приём — в битах, как в диспетчере задач');
  Assert.AreEqual(3, LPage.GpuView.Items.Count, 'Две видеокарты и «Всего»');
  Assert.AreEqual('50 %', LPage.GpuView.Items[2].SubItems[0], 'Всего — самая загруженная');
  Assert.AreEqual('100 Вт', LPage.GpuView.Items[2].SubItems[5], 'Мощность суммируется');
  // График по умолчанию — «Всего»; выбор строки — график этого устройства.
  Assert.AreEqual(5, Integer(Length(LPage.NetChart.Points)));
  Assert.IsTrue(LPage.NetChart.Title.Contains('Всего'));
  // Две линии: приём (сумма 5000 + 500) и передача (100 + 100) — отдельно.
  Assert.AreEqual(5, Integer(Length(LPage.NetChart.SecondPoints)), 'Вторая линия — передача');
  Assert.AreEqual(5500.0, LPage.NetChart.Points[4].Value, 0.01);
  Assert.AreEqual(200.0, LPage.NetChart.SecondPoints[4].Value, 0.01);
  Assert.IsTrue(LPage.NetChart.SummaryText.Contains('Передача'), LPage.NetChart.SummaryText);
  LPage.GpuView.Items[1].Selected := True;
  Assert.IsTrue(LPage.GpuChart.Title.Contains('GPU B'), LPage.GpuChart.Title);
  Assert.AreEqual(5.0, LPage.GpuChart.Points[0].Value, 0.01);
  // Следующий цикл пересобирает таблицы — выбранная видеокарта и её график остаются.
  LPage.RecordHistory(LSnapshot);
  LPage.UpdateSnapshot(LSnapshot);
  Assert.IsNotNull(LPage.GpuView.Selected, 'Выделение пережило обновление');
  Assert.AreEqual('GPU B', LPage.GpuView.Selected.Caption);
  Assert.IsTrue(LPage.GpuChart.Title.Contains('GPU B'), LPage.GpuChart.Title);
  LPage.NetView.Items[0].Selected := True;
  LPage.UpdateSnapshot(LSnapshot);
  Assert.AreEqual('Ethernet', LPage.NetView.Selected.Caption);
  Assert.IsTrue(LPage.NetChart.Title.Contains('Ethernet'), LPage.NetChart.Title);
  Assert.IsTrue(LPage.GpuChart.Title.Contains('GPU B'), 'Выбор в другой таблице не сбрасывает график видеокарты');
end;

initialization
  TDUnitX.RegisterTestFixture(TMainFormSmokeTests);

end.
