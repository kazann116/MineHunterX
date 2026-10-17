unit MineHunter.Tests.Insights;

{
  Оценка электроэнергии, учёт «что изменилось» (извлечение из снимка и
  хранилище схемы 3), внеочередная проверка сканера и отчёт «Проверить сейчас».
}

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Core.Energy,
  MineHunter.Core.Inventory, MineHunter.Core.CheckReport, MineHunter.Storage.SQLite,
  MineHunter.Tests.Fakes;

type
  [TestFixture]
  [Category('Unit')]
  TEnergyTests = class
  public
    [Test] procedure ConstantPower_TwoHours;
    [Test] procedure Gaps_AreNotCounted;
    [Test] procedure NoDataAndNegative_Ignored;
    [Test] procedure SinglePoint_AverageOnly;
    [Test] procedure Empty_NoData;
    [Test] procedure Cost_EdgeCases;
    [Test] procedure Formatting;
  end;

  [TestFixture]
  [Category('Unit')]
  TInventoryExtractTests = class
  public
    [Test] procedure Extract_AllKinds_Deduplicated;
    [Test] procedure Extract_WithoutPaths_UsesNames;
    [Test] procedure KindNames_RoundTrip;
  end;

  [TestFixture]
  [Category('Storage')]
  TInventoryStorageTests = class
  private
    FDir: string;
    FClock: TFakeClock;
    FClockIntf: IMHClock;
    FLoggerIntf: IMHLogger;
    function Open: TMHSQLiteRepository;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure InitialStateIsNotAChange_NewEntriesAre;
    [Test] procedure Refresh_IsThrottled;
    [Test] procedure Maintenance_And_Clear;
    [Test] procedure PowerMetric_IsStored;
  end;

  [TestFixture]
  [Category('Unit')]
  TScannerRefreshTests = class
  public
    [Test] procedure RequestRefresh_InvalidatesCachesOnce;
  end;

  [TestFixture]
  [Category('Unit')]
  TCheckReportTests = class
  public
    [Test] procedure Clean_AllSectionsPresent;
    [Test] procedure Threat_ExplainedWithEvidence;
    [Test] procedure Changes_GroupedAndLimited;
    [Test] procedure Energy_AndLimitations;
  end;

implementation

uses
  System.IOUtils, System.DateUtils, System.Math,
  MineHunter.Core.Scanner, MineHunter.Core.Logging;

function Power(AWatts: Double; ATime: TDateTime): TMHMetric;
begin
  Result := TMHMetric.Available(mkGpuPowerWatts, AWatts, ATime);
end;

{ TEnergyTests }

procedure TEnergyTests.ConstantPower_TwoHours;
var
  LSeries: TArray<TMHMetric>;
  LEnergy: TMHEnergyEstimate;
  I: Integer;
begin
  // Точки в обратном порядке — функция сортирует сама.
  for I := 120 downto 0 do
    LSeries := LSeries + [Power(100, FAKE_NOW + I / MinsPerDay)];
  LEnergy := MHEstimateEnergy(LSeries, 6);
  Assert.IsTrue(LEnergy.HasData);
  Assert.AreEqual(0.2, LEnergy.KWh, 0.0001);
  Assert.AreEqual(2.0, LEnergy.CoveredHours, 0.0001);
  Assert.AreEqual(100.0, LEnergy.AverageWatts, 0.0001);
  Assert.AreEqual(100.0, LEnergy.PeakWatts, 0.0001);
  Assert.AreEqual(1.2, LEnergy.Cost, 0.0001);
  Assert.AreEqual(14.4, LEnergy.CostPerDay, 0.0001);
  Assert.AreEqual(432.0, LEnergy.CostPerMonth, 0.0001);
end;

procedure TEnergyTests.Gaps_AreNotCounted;
var
  LEnergy: TMHEnergyEstimate;
begin
  // 10 минут измерений, затем программа была закрыта 3 часа, затем ещё 10 минут.
  LEnergy := MHEstimateEnergy([Power(200, FAKE_NOW), Power(200, FAKE_NOW + 10 / MinsPerDay),
    Power(200, FAKE_NOW + 190 / MinsPerDay), Power(200, FAKE_NOW + 200 / MinsPerDay)], 5, 15);
  Assert.AreEqual(20 / 60, LEnergy.CoveredHours, 0.0001);
  Assert.AreEqual(200 * (20 / 60) / 1000, LEnergy.KWh, 0.00001);
  // Трапеция: переход 100 → 300 Вт за час даёт 200 Вт·ч.
  LEnergy := MHEstimateEnergy([Power(100, FAKE_NOW), Power(300, FAKE_NOW + 1 / HoursPerDay)], 1, 120);
  Assert.AreEqual(0.2, LEnergy.KWh, 0.0001);
  Assert.AreEqual(300.0, LEnergy.PeakWatts, 0.0001);
end;

procedure TEnergyTests.NoDataAndNegative_Ignored;
var
  LEnergy: TMHEnergyEstimate;
begin
  LEnergy := MHEstimateEnergy([TMHMetric.NoData(mkGpuPowerWatts, FAKE_NOW), Power(-5, FAKE_NOW),
    Power(NaN, FAKE_NOW), Power(50, FAKE_NOW), Power(50, FAKE_NOW + 1 / HoursPerDay)], 10, 120);
  Assert.AreEqual(0.05, LEnergy.KWh, 0.0001);
  Assert.AreEqual(0.5, LEnergy.Cost, 0.0001);
end;

procedure TEnergyTests.SinglePoint_AverageOnly;
var
  LEnergy: TMHEnergyEstimate;
begin
  LEnergy := MHEstimateEnergy([Power(150, FAKE_NOW)], 6);
  Assert.IsTrue(LEnergy.HasData);
  Assert.AreEqual(0.0, LEnergy.KWh, 0.0001, 'Одной точки мало для энергии');
  Assert.AreEqual(150.0, LEnergy.AverageWatts, 0.0001);
  Assert.AreEqual(21.6, LEnergy.CostPerDay, 0.0001, 'Но стоимость суток при такой мощности известна');
end;

procedure TEnergyTests.Empty_NoData;
begin
  Assert.IsFalse(MHEstimateEnergy([], 6).HasData);
  Assert.IsFalse(MHEstimateEnergy([TMHMetric.NoData(mkGpuPowerWatts, FAKE_NOW)], 6).HasData);
end;

procedure TEnergyTests.Cost_EdgeCases;
begin
  Assert.AreEqual(0.6, MHEnergyCost(100, 1, 6), 0.0001);
  Assert.AreEqual(0.0, MHEnergyCost(-100, 1, 6), 0.0001);
  Assert.AreEqual(0.0, MHEnergyCost(100, 0, 6), 0.0001);
  Assert.AreEqual(0.0, MHEnergyCost(100, 1, 0), 0.0001);
  Assert.AreEqual(0.0, MHEnergyCost(NaN, 1, 6), 0.0001);
end;

procedure TEnergyTests.Formatting;
begin
  Assert.IsTrue(MHFormatMoney(12.345).EndsWith('₽'));
  Assert.IsTrue(MHFormatMoney(12.345).Contains('12'));
  Assert.IsFalse(MHFormatMoney(1234.5).Contains(FormatSettings.DecimalSeparator + '5'), 'Крупные суммы без копеек');
  Assert.AreEqual('850 Вт·ч', MHFormatEnergy(0.85));
  Assert.IsTrue(MHFormatEnergy(2.5).EndsWith('кВт·ч'));
  Assert.AreEqual('0 Вт·ч', MHFormatEnergy(-1));
end;

{ Inventory }

function SnapshotWith(ATime: TDateTime; const AAutostart: array of string;
  const APrograms: array of string): TMHSnapshot;
var
  LName: string;
  LEntry: TMHAutostartEntry;
  LInfo: TMHProcessInfo;
  LPid: Cardinal;
begin
  Result := TMHSnapshot.Create(1, ATime);
  for LName in AAutostart do
  begin
    LEntry := Default(TMHAutostartEntry);
    LEntry.Kind := akRegistryRun;
    LEntry.Name := LName;
    LEntry.Location := 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run';
    LEntry.ImagePath := 'C:\Users\u\AppData\Roaming\' + LName + '.exe';
    LEntry.Enabled := True;
    Result.Autostart := Result.Autostart + [LEntry];
  end;
  LPid := 100;
  for LName in APrograms do
  begin
    Inc(LPid);
    LInfo := TMHProcessInfo.Create(TMHProcessId.Create(LPid, LPid), LName, ATime);
    LInfo.ImagePath := 'C:\Apps\' + LName;
    LInfo.SourceId := 'processes';
    Result.Processes := Result.Processes + [LInfo];
  end;
end;

procedure TInventoryExtractTests.Extract_AllKinds_Deduplicated;
var
  LSnapshot: TMHSnapshot;
  LItems: TArray<TMHInventoryItem>;
  LTamper: TMHTamperEntry;
  LInfo: TMHProcessInfo;
  LCount: array[TMHInventoryKind] of Integer;
  LItem: TMHInventoryItem;
begin
  LSnapshot := SnapshotWith(FAKE_NOW, ['Updater', 'Updater'], ['a.exe', 'b.exe', 'a.exe']);
  // Второй экземпляр той же программы (другой PID) и процесс без пути.
  LInfo := TMHProcessInfo.Create(TMHProcessId.Create(900, 900), 'System', FAKE_NOW);
  LSnapshot.Processes := LSnapshot.Processes + [LInfo];
  LTamper := TMHTamperEntry.Create(tpDefenderExclusion, 'C:\ProgramData', 'C:\ProgramData',
    'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths');
  LSnapshot.Tamper := [LTamper];
  LItems := MHInventoryFromSnapshot(LSnapshot, True);
  FillChar(LCount, SizeOf(LCount), 0);
  for LItem in LItems do
  begin
    Inc(LCount[LItem.Kind]);
    Assert.AreEqual(LItem.Key, LItem.Key.ToLower, 'Ключи без учёта регистра');
    Assert.AreEqual(FAKE_NOW, LItem.FirstSeenUtc);
  end;
  Assert.AreEqual(1, LCount[ikAutostart]);
  Assert.AreEqual(1, LCount[ikTamper]);
  Assert.AreEqual(2, LCount[ikProgram], 'Программы без пути пропускаются, повторы объединяются');
end;

procedure TInventoryExtractTests.Extract_WithoutPaths_UsesNames;
var
  LItem: TMHInventoryItem;
begin
  for LItem in MHInventoryFromSnapshot(SnapshotWith(FAKE_NOW, ['Updater'], ['a.exe']), False) do
  begin
    Assert.AreEqual('', LItem.ImagePath, 'Пути не сохраняются');
    if LItem.Kind = ikProgram then
      Assert.AreEqual('a.exe', LItem.Key);
  end;
end;

procedure TInventoryExtractTests.KindNames_RoundTrip;
var
  LKind, LParsed: TMHInventoryKind;
begin
  for LKind := Low(TMHInventoryKind) to High(TMHInventoryKind) do
  begin
    Assert.IsTrue(MHTryInventoryKindFromName(MHInventoryKindToName(LKind), LParsed));
    Assert.AreEqual(Ord(LKind), Ord(LParsed));
    Assert.IsNotEmpty(MHInventoryKindTitle(LKind));
  end;
  Assert.IsFalse(MHTryInventoryKindFromName('unknown', LParsed));
end;

{ TInventoryStorageTests }

procedure TInventoryStorageTests.Setup;
begin
  FDir := TPath.Combine(TPath.GetTempPath, 'MineHunterTests\inv-' +
    TGUID.NewGuid.ToString.Replace('{', '').Replace('}', ''));
  ForceDirectories(FDir);
  FClock := TFakeClock.Create(FAKE_NOW);
  FClockIntf := FClock;
  FLoggerIntf := TRecordingLogger.Create;
end;

procedure TInventoryStorageTests.TearDown;
begin
  FClockIntf := nil;
  FLoggerIntf := nil;
  try
    TDirectory.Delete(FDir, True);
  except
    // Временный каталог тестов.
  end;
end;

function TInventoryStorageTests.Open: TMHSQLiteRepository;
begin
  Result := TMHSQLiteRepository.Create(TPath.Combine(FDir, 'history.db'), TMHStorageOptions.Default,
    FClockIntf, FLoggerIntf);
end;

procedure TInventoryStorageTests.InitialStateIsNotAChange_NewEntriesAre;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LChanges: TArray<TMHInventoryItem>;
  LStart: TDateTime;
begin
  LStart := FAKE_NOW - 2;
  LRepo := Open;
  LIntf := LRepo;
  Assert.AreEqual(0.0, LRepo.InventoryStartUtc, 'Учёт пуст');
  LRepo.SaveSnapshot(SnapshotWith(LStart, ['Updater'], ['a.exe']));
  // В пределах исходного окна — ещё исходное состояние.
  LRepo.SaveSnapshot(SnapshotWith(IncMinute(LStart, 10), ['Updater', 'Helper'], ['a.exe']));
  LRepo.SaveSnapshot(SnapshotWith(IncDay(LStart, 1), ['Updater', 'Helper', 'Miner'], ['a.exe', 'xmrig.exe']));
  Assert.AreEqual(LStart, LRepo.InventoryStartUtc, 1 / SecsPerDay);

  LChanges := LRepo.LoadInventoryChanges(LStart - 1, 100);
  Assert.AreEqual(2, Integer(Length(LChanges)), 'Только появившееся после исходного окна');
  Assert.AreEqual(IncDay(LStart, 1), LChanges[0].FirstSeenUtc, 1 / SecsPerDay);
  Assert.IsTrue((LChanges[0].Name = 'Miner') or (LChanges[1].Name = 'Miner'));
  Assert.IsTrue((LChanges[0].Name = 'xmrig.exe') or (LChanges[1].Name = 'xmrig.exe'));
  // Окно «с какого времени».
  Assert.AreEqual(0, Integer(Length(LRepo.LoadInventoryChanges(IncDay(LStart, 1) + 1 / MinsPerDay, 100))));
  Assert.AreEqual(1, Integer(Length(LRepo.LoadInventoryChanges(LStart - 1, 1))), 'Ограничение количества');
  Assert.AreEqual(0, Integer(Length(LRepo.LoadInventoryChanges(LStart - 1, 0))));
  LIntf := nil;
end;

procedure TInventoryStorageTests.Refresh_IsThrottled;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LStart: TDateTime;
begin
  LStart := FAKE_NOW - 1;
  LRepo := Open;
  LIntf := LRepo;
  LRepo.SaveSnapshot(SnapshotWith(LStart, ['Updater'], []));
  // Через 40 минут, но в пределах MH_INVENTORY_REFRESH_SECONDS от предыдущей записи
  // учёта объект не записывается…
  LRepo.SaveSnapshot(SnapshotWith(IncSecond(LStart, 10), ['Updater', 'Early'], []));
  LRepo.SaveSnapshot(SnapshotWith(IncMinute(LStart, 40), ['Updater', 'Late'], []));
  Assert.AreEqual(1, Integer(Length(LRepo.LoadInventoryChanges(LStart - 1, 100))));
  Assert.AreEqual('Late', LRepo.LoadInventoryChanges(LStart - 1, 100)[0].Name);
  LIntf := nil;
end;

procedure TInventoryStorageTests.Maintenance_And_Clear;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
begin
  LRepo := Open;
  LIntf := LRepo;
  LRepo.SaveSnapshot(SnapshotWith(FAKE_NOW - 60, ['Ancient'], []));
  LRepo.SaveSnapshot(SnapshotWith(FAKE_NOW - 1, ['Recent'], []));
  LRepo.RunMaintenance;
  // Запись старше MinInventoryRetentionDays удалена — «начало учёта» сдвинулось.
  Assert.AreEqual(FAKE_NOW - 1, LRepo.InventoryStartUtc, 1 / SecsPerDay);
  LRepo.Clear;
  Assert.AreEqual(0.0, LRepo.InventoryStartUtc);
  LRepo.SaveSnapshot(SnapshotWith(FAKE_NOW, ['AfterClear'], []));
  Assert.AreEqual(FAKE_NOW, LRepo.InventoryStartUtc, 1 / SecsPerDay, 'После очистки учёт начинается заново');
  LIntf := nil;
end;

procedure TInventoryStorageTests.PowerMetric_IsStored;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LSnapshot: TMHSnapshot;
  LSeries: TArray<TMHMetric>;
begin
  LRepo := Open;
  LIntf := LRepo;
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW - 1 / HoursPerDay);
  LSnapshot.Metrics := [Power(120, LSnapshot.TimestampUtc)];
  LRepo.SaveSnapshot(LSnapshot);
  LSnapshot := TMHSnapshot.Create(2, FAKE_NOW);
  LSnapshot.Metrics := [Power(180, FAKE_NOW)];
  LRepo.SaveSnapshot(LSnapshot);
  LSeries := LRepo.LoadMetricSeries(mkGpuPowerWatts, FAKE_NOW - 1, FAKE_NOW + 1, 1000);
  Assert.AreEqual(2, Integer(Length(LSeries)));
  // Точки ряда — середины интервалов выборки, поэтому длительность чуть отличается от часа.
  Assert.AreEqual(0.15, MHEstimateEnergy(LSeries, 6, 120).KWh, 0.005);
  LIntf := nil;
end;

{ TScannerRefreshTests }

type
  TCachingCollector = class(TInterfacedObject, IMHCollector, IMHCacheInvalidation)
  public
    Invalidations: Integer;
    function GetSourceId: string;
    function GetDisplayName: string;
    function Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
    procedure Invalidate;
  end;

function TCachingCollector.GetSourceId: string;
begin
  Result := 'caching';
end;

function TCachingCollector.GetDisplayName: string;
begin
  Result := 'Кэширующий';
end;

function TCachingCollector.Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
begin
  Result := TMHCollectionResult.Create(TMHSourceStatus.Create('caching', ssSuccess, '', ASnapshot.TimestampUtc));
end;

procedure TCachingCollector.Invalidate;
begin
  Inc(Invalidations);
end;

procedure TScannerRefreshTests.RequestRefresh_InvalidatesCachesOnce;
var
  LCollector: TCachingCollector;
  LCollectorIntf: IMHCollector;
  LScanner: TMHScanner;
  LSnapshot: TMHSnapshot;
begin
  LCollector := TCachingCollector.Create;
  LCollectorIntf := LCollector;
  LScanner := TMHScanner.Create([LCollectorIntf, TFakeCollector.Create('plain', fcmSuccess) as IMHCollector],
    nil, TFakeClock.Create(FAKE_NOW), TRecordingLogger.Create);
  try
    LScanner.ScanOnce;
    Assert.AreEqual(0, LCollector.Invalidations);
    Assert.AreEqual<UInt64>(0, LScanner.LastRefreshSequence);
    LScanner.RequestRefresh;
    LSnapshot := LScanner.ScanOnce;
    Assert.AreEqual(1, LCollector.Invalidations, 'Кэш сброшен перед сбором');
    Assert.AreEqual<UInt64>(LSnapshot.Sequence, LScanner.LastRefreshSequence);
    LScanner.ScanOnce;
    Assert.AreEqual(1, LCollector.Invalidations, 'Только один раз на запрос');
    Assert.AreEqual<UInt64>(LSnapshot.Sequence, LScanner.LastRefreshSequence);
  finally
    LScanner.Free;
  end;
end;

{ TCheckReportTests }

function BaseInput: TMHCheckReportInput;
begin
  Result := Default(TMHCheckReportInput);
  Result.Snapshot := TMHSnapshot.Create(5, FAKE_NOW);
  Result.Snapshot.Metrics := [TMHMetric.Available(mkCpuPercent, 12, FAKE_NOW),
    TMHMetric.Available(mkMemoryLoadPercent, 48, FAKE_NOW)];
  Result.Snapshot.Sources := [TMHSourceStatus.Create('processes', ssSuccess, '', FAKE_NOW)];
  Result.CpuCount := 8;
  Result.ChangesAvailable := True;
  Result.ChangesDays := 7;
  Result.ElectricityPrice := 6;
  Result.IsElevated := True;
  Result.InventoryStartUtc := FAKE_NOW - 3;
end;

procedure TCheckReportTests.Clean_AllSectionsPresent;
var
  LReport: TMHCheckReport;
begin
  LReport := MHBuildCheckReport(BaseInput);
  Assert.AreEqual(Ord(cvClean), Ord(LReport.Verdict));
  Assert.AreEqual('Угроз не обнаружено', LReport.Headline);
  Assert.AreEqual(0, LReport.AlertCount);
  Assert.IsTrue(LReport.Text.Contains('1. ТРЕВОГИ'));
  Assert.IsTrue(LReport.Text.Contains('2. ПОЧЕМУ'));
  Assert.IsTrue(LReport.Text.Contains('3. ЧТО ИЗМЕНИЛОСЬ ЗА 7'));
  Assert.IsTrue(LReport.Text.Contains('4. ЭЛЕКТРОЭНЕРГИЯ'));
  Assert.IsTrue(LReport.Text.Contains('5. ОГРАНИЧЕНИЯ'));
  Assert.IsTrue(LReport.Text.Contains('процессор 12%'), LReport.Text);
  Assert.IsTrue(LReport.Text.Contains('Новых записей автозапуска'));
  Assert.IsTrue(LReport.Text.Contains('Все источники данных работают'));
  Assert.IsFalse(LReport.Text.Contains('от имени администратора'), 'Права уже есть');
  Assert.IsTrue(LReport.Text.Contains('локально'));
  // Детерминированность.
  Assert.AreEqual(LReport.Text, MHBuildCheckReport(BaseInput).Text);
end;

procedure TCheckReportTests.Threat_ExplainedWithEvidence;
var
  LInput: TMHCheckReportInput;
  LFinding, LLow, LReview: TMHFinding;
  LReport: TMHCheckReport;
begin
  LInput := BaseInput;
  LFinding := Default(TMHFinding);
  LFinding.Key := 'a';
  LFinding.Title := 'Скрытый майнинг';
  LFinding.ProcessName := 'AMD.exe';
  LFinding.ImagePath := 'C:\ProgramData\WindowsTask\AMD.exe';
  LFinding.Level := rlHighlySuspicious;
  LFinding.Score := 100;
  LFinding.Evidence := [TMHEvidence.Create('MINER_ARTIFACT', 'Рядом драйвер WinRing0', 40),
    TMHEvidence.Create('HIDDEN_FILE', 'Скрытый системный файл', 20),
    TMHEvidence.Create('SIGNED', 'Подписан доверенным издателем', -30)];
  LFinding.Recommendations := ['Переместите файл в карантин'];
  LLow := Default(TMHFinding);
  LLow.Key := 'low';
  LLow.Title := 'Слабый признак';
  LLow.Level := rlLow;
  LReview := Default(TMHFinding);
  LReview.Key := 'review';
  LReview.Title := 'Проверить';
  LReview.Level := rlNeedsReview;
  LReview.Score := 30;
  LInput.Findings := [LLow, LReview, LFinding];
  LReport := MHBuildCheckReport(LInput);
  Assert.AreEqual(Ord(cvThreat), Ord(LReport.Verdict));
  Assert.AreEqual(2, LReport.AlertCount, 'Слабые признаки не считаются тревогой');
  Assert.IsTrue(LReport.Text.IndexOf('Скрытый майнинг') < LReport.Text.IndexOf('Проверить'),
    'Опасные — первыми');
  Assert.IsTrue(LReport.Text.Contains('+ Рядом драйвер WinRing0'));
  Assert.IsTrue(LReport.Text.Contains('− Подписан доверенным издателем'), 'Оправдывающие признаки видны');
  Assert.IsTrue(LReport.Text.Contains('Что сделать: Переместите файл в карантин'));
  Assert.IsTrue(LReport.Text.Contains('C:\ProgramData\WindowsTask\AMD.exe'));
  Assert.IsFalse(LReport.Text.Contains('Слабый признак'));

  LInput.Findings := [LReview];
  Assert.AreEqual(Ord(cvAttention), Ord(MHBuildCheckReport(LInput).Verdict));
end;

procedure TCheckReportTests.Changes_GroupedAndLimited;
var
  LInput: TMHCheckReportInput;
  LItem: TMHInventoryItem;
  LReport: TMHCheckReport;
  I: Integer;
begin
  LInput := BaseInput;
  for I := 1 to 12 do
  begin
    LItem := Default(TMHInventoryItem);
    LItem.Kind := ikProgram;
    LItem.Name := Format('prog%d.exe', [I]);
    LItem.ImagePath := 'C:\Apps\' + LItem.Name;
    LItem.FirstSeenUtc := FAKE_NOW - I / HoursPerDay;
    LInput.Changes := LInput.Changes + [LItem];
  end;
  LItem := Default(TMHInventoryItem);
  LItem.Kind := ikAutostart;
  LItem.Name := 'SysFilesL';
  LItem.Details := 'Задание планировщика: \';
  LItem.FirstSeenUtc := FAKE_NOW;
  LInput.Changes := LInput.Changes + [LItem];
  LReport := MHBuildCheckReport(LInput);
  Assert.IsTrue(LReport.Text.Contains('Новая запись автозапуска: 1'), LReport.Text);
  Assert.IsTrue(LReport.Text.Contains('SysFilesL'));
  Assert.IsTrue(LReport.Text.Contains('Впервые запущена программа: 12'));
  Assert.IsTrue(LReport.Text.Contains('и ещё 2'), 'Показываются первые 10');
  Assert.IsFalse(LReport.Text.Contains('prog12.exe'));

  LInput.ChangesAvailable := False;
  Assert.IsTrue(MHBuildCheckReport(LInput).Text.Contains('История недоступна'));
end;

procedure TCheckReportTests.Energy_AndLimitations;
var
  LInput: TMHCheckReportInput;
  LText: string;
begin
  LInput := BaseInput;
  LText := MHBuildCheckReport(LInput).Text;
  Assert.IsTrue(LText.Contains('не сообщает мощность'));
  LInput.Snapshot.Metrics := LInput.Snapshot.Metrics + [Power(250, FAKE_NOW)];
  LInput.Energy := MHEstimateEnergy([Power(250, FAKE_NOW - 1 / HoursPerDay), Power(250, FAKE_NOW)], 6, 120);
  LInput.IsElevated := False;
  LInput.Snapshot.Sources := LInput.Snapshot.Sources +
    [TMHSourceStatus.Create('network', ssPartial, 'нужны права администратора', FAKE_NOW)];
  LText := MHBuildCheckReport(LInput).Text;
  Assert.IsTrue(LText.Contains('Сейчас: 250 Вт'), LText);
  Assert.IsTrue(LText.Contains('За последние сутки'), LText);
  Assert.IsTrue(LText.Contains('network'));
  Assert.IsTrue(LText.Contains('нужны права администратора'));
  Assert.IsTrue(LText.Contains('от имени администратора'));
end;

initialization
  TDUnitX.RegisterTestFixture(TEnergyTests);
  TDUnitX.RegisterTestFixture(TInventoryExtractTests);
  TDUnitX.RegisterTestFixture(TInventoryStorageTests);
  TDUnitX.RegisterTestFixture(TScannerRefreshTests);
  TDUnitX.RegisterTestFixture(TCheckReportTests);

end.
