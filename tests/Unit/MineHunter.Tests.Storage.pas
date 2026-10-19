unit MineHunter.Tests.Storage;

{
  Тесты хранилища SQLite. Каждый тест работает во временном каталоге,
  который удаляется в TearDown; история пользователя не затрагивается.
}

interface

uses
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Storage.SQLite,
  MineHunter.Tests.Fakes;

type
  [TestFixture]
  [Category('Storage')]
  TStorageTests = class
  private
    FDir: string;
    FPath: string;
    FClock: TFakeClock;
    FClockIntf: IMHClock;
    FLogger: TRecordingLogger;
    FLoggerIntf: IMHLogger;
    function Open(const AOptions: TMHStorageOptions): TMHSQLiteRepository; overload;
    function Open: TMHSQLiteRepository; overload;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure UnixMs_RoundTrip;
    [Test] procedure Create_NewDatabase_IsEmpty;
    [Test] procedure SaveLoad_RoundTripAllFields;
    [Test] procedure Reopen_PersistsData;
    [Test] procedure LoadHistory_RangeOrderAndLimit;
    [Test] procedure LoadHistory_ZeroMaxCount_IsEmpty;
    [Test] procedure TopProcesses_AreLimitedByLoad;
    [Test] procedure Privacy_PathsAreNotStored;
    [Test] procedure MetricSeries_IsDownsampledByAverage;
    [Test] procedure MetricSeries_NullValues_AreNoData;
    [Test] procedure MetricSeries_FirstBucketNull_IsLocaleIndependent;
    [Test] procedure MetricSeries_EmptyOrInvalidRange;
    [Test] procedure ProcessSeries_SeparatesReusedPid;
    [Test] procedure ProcessSeries_UnsupportedKind_Raises;
    [Test] procedure Retention_RemovesOldSnapshots;
    [Test] procedure SizeLimit_RemovesOldestFirst;
    [Test] procedure AutoMaintenance_RunsAfterNSaves;
    [Test] procedure Clear_RemovesEverything;
    [Test] procedure CorruptFile_IsQuarantinedAndRecreated;
    [Test] procedure NewerSchema_IsNotModified;
    [Test] procedure InvalidLocation_RaisesStorageError;
    [Test] procedure ConcurrentSaveAndRead;
    [Test] procedure Batch_WrittenAfterIntervalNotEachSnapshot;
    [Test] procedure Batch_ReadAndCloseWritePending;
    [Test] procedure Batch_ZeroInterval_WritesEachSnapshot;
    [Test] procedure Batch_FindingsMergedInOneWrite;
    [Test] procedure Batch_ClockBackOrClear;
    [Test] procedure Batch_QueueKeepsCopyOfSnapshot;
  end;

  [TestFixture]
  [Category('Performance')]
  TStoragePerformanceTests = class
  public
    [Test] procedure WeekOfHistory_SeriesQueryIsFast;
  end;

implementation

uses
  System.SysUtils, System.Classes, System.IOUtils, System.DateUtils, System.Diagnostics,
  System.Variants,
  FireDAC.Comp.Client, FireDAC.Stan.Def, FireDAC.Phys.SQLite, FireDAC.Stan.Async,
  FireDAC.DApt, FireDAC.ConsoleUI.Wait,
  MineHunter.Core.Logging;

function NewTempDir: string;
begin
  Result := TPath.Combine(TPath.GetTempPath, 'MineHunterTests\' +
    TGUID.NewGuid.ToString.Replace('{', '').Replace('}', ''));
  ForceDirectories(Result);
end;

function Snap(ASeq: UInt64; ATime: TDateTime; ACpu: Double;
  AProcessCount: Integer = 0): TMHSnapshot;
var
  I: Integer;
  LInfo: TMHProcessInfo;
begin
  Result := TMHSnapshot.Create(ASeq, ATime);
  Result.Metrics := [TMHMetric.Available(mkCpuPercent, ACpu, ATime),
    TMHMetric.Available(mkMemoryLoadPercent, 40, ATime),
    TMHMetric.NoData(mkDiskActivePercent, ATime)];
  SetLength(Result.Processes, AProcessCount);
  for I := 0 to AProcessCount - 1 do
  begin
    LInfo := TMHProcessInfo.Create(TMHProcessId.Create(1000 + I, 5000 + I),
      Format('p%d.exe', [I]), ATime);
    LInfo.ImagePath := Format('C:\Program Files\Vendor\Product %d\p%d.exe', [I, I]);
    LInfo.Cpu := TMHMetric.Available(mkCpuPercent, I, ATime);
    LInfo.WorkingSet := TMHMetric.Available(mkWorkingSetBytes, 1000 * I, ATime);
    LInfo.Access := alFull;
    LInfo.ThreadCount := I + 1;
    LInfo.SourceId := 'processes';
    Result.Processes[I] := LInfo;
  end;
end;

/// Число строк, видимое другим соединением, — то, что действительно записано в файл.
function RawCount(const APath, ATable: string): Int64;
var
  LConnection: TFDConnection;
begin
  LConnection := TFDConnection.Create(nil);
  try
    LConnection.DriverName := 'SQLite';
    LConnection.Params.Database := APath;
    LConnection.LoginPrompt := False;
    Result := LConnection.ExecSQLScalar('SELECT COUNT(*) FROM ' + ATable);
  finally
    LConnection.Free;
  end;
end;

function BatchFinding(const AKey: string; AScore: Integer; ADetected: TDateTime): TMHFinding;
begin
  Result := Default(TMHFinding);
  Result.Id := TGUID.NewGuid;
  Result.Key := AKey;
  Result.Process := TMHProcessId.Create(4321, $1D9A0000);
  Result.ProcessName := 'miner.exe';
  Result.Title := 'Находка ' + AKey;
  Result.Score := AScore;
  Result.DetectedAtUtc := ADetected;
end;

{ TStorageTests }

procedure TStorageTests.Setup;
begin
  FDir := NewTempDir;
  FPath := TPath.Combine(FDir, 'history.db');
  FClock := TFakeClock.Create(FAKE_NOW);
  FClockIntf := FClock;
  FLogger := TRecordingLogger.Create;
  FLoggerIntf := FLogger;
end;

procedure TStorageTests.TearDown;
begin
  FLoggerIntf := nil;
  FClockIntf := nil;
  try
    TDirectory.Delete(FDir, True);
  except
    // Каталог мог остаться заблокированным антивирусом — не влияет на результат.
  end;
end;

function TStorageTests.Open(const AOptions: TMHStorageOptions): TMHSQLiteRepository;
begin
  Result := TMHSQLiteRepository.Create(FPath, AOptions, FClockIntf, FLoggerIntf);
end;

function TStorageTests.Open: TMHSQLiteRepository;
begin
  Result := Open(TMHStorageOptions.Default);
end;

procedure TStorageTests.UnixMs_RoundTrip;
var
  LTime: TDateTime;
begin
  LTime := EncodeDateTime(2026, 10, 16, 12, 34, 56, 789);
  Assert.AreEqual(LTime, MHUnixMsToUtc(MHUtcToUnixMs(LTime)), 0.5 / MSecsPerDay);
  Assert.AreEqual<Int64>(0, MHUtcToUnixMs(UnixDateDelta));
end;

procedure TStorageTests.Create_NewDatabase_IsEmpty;
var
  LRepo: IMHMetricHistory;
  LStats: TMHHistoryStats;
begin
  LRepo := Open;
  LStats := LRepo.GetStats;
  Assert.IsTrue(FileExists(FPath));
  Assert.AreEqual<Int64>(0, LStats.SnapshotCount);
  Assert.AreEqual(0.0, LStats.OldestUtc, 0);
  Assert.IsTrue(LStats.FileSizeBytes > 0);
end;

procedure TStorageTests.SaveLoad_RoundTripAllFields;
var
  LRepo: IMHRepository;
  LSnapshot: TMHSnapshot;
  LStatus: TMHSourceStatus;
  LLoaded: TArray<TMHSnapshot>;
  LInfo: TMHProcessInfo;
begin
  LRepo := Open;
  LSnapshot := Snap(7, FAKE_NOW, 33.5, 2);
  LStatus := TMHSourceStatus.Create('processes', ssPartial, 'Нет доступа к 3', FAKE_NOW);
  LStatus.RequiresElevation := True;
  LStatus.DurationMs := 15;
  LStatus.ItemCount := 300;
  LSnapshot.Sources := [LStatus];
  LRepo.SaveSnapshot(LSnapshot);

  LLoaded := LRepo.LoadHistory(FAKE_NOW - 1, FAKE_NOW + 1, 10);
  Assert.AreEqual(1, Integer(Length(LLoaded)));
  Assert.AreEqual<UInt64>(7, LLoaded[0].Sequence);
  Assert.AreEqual(FAKE_NOW, LLoaded[0].TimestampUtc, 1 / MSecsPerDay);
  Assert.AreEqual(3, Integer(Length(LLoaded[0].Metrics)));
  Assert.IsTrue(LLoaded[0].Metrics[0].HasValue or LLoaded[0].Metrics[1].HasValue);
  Assert.AreEqual(1, Integer(Length(LLoaded[0].Sources)));
  Assert.AreEqual<TMHSourceState>(ssPartial, LLoaded[0].Sources[0].State);
  Assert.AreEqual('Нет доступа к 3', LLoaded[0].Sources[0].Message);
  Assert.IsTrue(LLoaded[0].Sources[0].RequiresElevation);
  Assert.AreEqual(300, LLoaded[0].Sources[0].ItemCount);
  Assert.AreEqual(2, Integer(Length(LLoaded[0].Processes)));
  Assert.IsTrue(LLoaded[0].FindProcess(TMHProcessId.Create(1001, 5001), LInfo));
  Assert.AreEqual('p1.exe', LInfo.Name);
  Assert.AreEqual('C:\Program Files\Vendor\Product 1\p1.exe', LInfo.ImagePath);
  Assert.AreEqual(1.0, LInfo.Cpu.Value, 0.0001);
  Assert.IsFalse(LInfo.PrivateBytes.HasValue, 'NULL возвращается как «нет данных»');
  Assert.AreEqual<TMHAccessLevel>(alFull, LInfo.Access);
  Assert.AreEqual(2, LInfo.ThreadCount);
  Assert.AreEqual('processes', LInfo.SourceId);
end;

procedure TStorageTests.Reopen_PersistsData;
var
  LRepo: IMHRepository;
begin
  LRepo := Open;
  LRepo.SaveSnapshot(Snap(1, FAKE_NOW, 10));
  LRepo := nil;
  LRepo := Open;
  Assert.AreEqual(1, Integer(Length(LRepo.LoadHistory(0, FAKE_NOW + 1, 10))));
end;

procedure TStorageTests.LoadHistory_RangeOrderAndLimit;
var
  LRepo: IMHRepository;
  LLoaded: TArray<TMHSnapshot>;
  I: Integer;
begin
  LRepo := Open;
  // Сохраняем в обратном порядке: выдача должна быть по времени.
  for I := 9 downto 0 do
    LRepo.SaveSnapshot(Snap(I, FAKE_NOW - (9 - I) / MinsPerDay, I));
  LLoaded := LRepo.LoadHistory(FAKE_NOW - 5.5 / MinsPerDay, FAKE_NOW, 100);
  Assert.AreEqual(6, Integer(Length(LLoaded)));
  for I := 1 to High(LLoaded) do
    Assert.IsTrue(LLoaded[I].TimestampUtc > LLoaded[I - 1].TimestampUtc);
  LLoaded := LRepo.LoadHistory(0, FAKE_NOW + 1, 3);
  Assert.AreEqual(3, Integer(Length(LLoaded)));
  Assert.AreEqual<UInt64>(0, LLoaded[0].Sequence, 'Самые ранние снимки первыми');
end;

procedure TStorageTests.LoadHistory_ZeroMaxCount_IsEmpty;
var
  LRepo: IMHRepository;
begin
  LRepo := Open;
  LRepo.SaveSnapshot(Snap(1, FAKE_NOW, 10));
  Assert.AreEqual(0, Integer(Length(LRepo.LoadHistory(0, FAKE_NOW + 1, 0))));
end;

procedure TStorageTests.TopProcesses_AreLimitedByLoad;
var
  LOptions: TMHStorageOptions;
  LRepo: IMHRepository;
  LLoaded: TArray<TMHSnapshot>;
  LInfo: TMHProcessInfo;
begin
  LOptions := TMHStorageOptions.Default;
  LOptions.MaxProcessesPerSnapshot := 5;
  LRepo := Open(LOptions);
  LRepo.SaveSnapshot(Snap(1, FAKE_NOW, 10, 50));
  LLoaded := LRepo.LoadHistory(0, FAKE_NOW + 1, 1);
  Assert.AreEqual(5, Integer(Length(LLoaded[0].Processes)));
  for LInfo in LLoaded[0].Processes do
    Assert.IsTrue(LInfo.Cpu.Value >= 45, 'Сохраняются самые нагруженные процессы');
end;

procedure TStorageTests.Privacy_PathsAreNotStored;
var
  LOptions: TMHStorageOptions;
  LRepo: IMHRepository;
  LLoaded: TArray<TMHSnapshot>;
begin
  LOptions := TMHStorageOptions.Default;
  LOptions.StoreProcessPaths := False;
  LRepo := Open(LOptions);
  LRepo.SaveSnapshot(Snap(1, FAKE_NOW, 10, 3));
  LLoaded := LRepo.LoadHistory(0, FAKE_NOW + 1, 1);
  Assert.AreEqual('', LLoaded[0].Processes[0].ImagePath);
  // После закрытия журнал WAL переносится в основной файл — проверяем его содержимое.
  LRepo := nil;
  Assert.IsFalse(TEncoding.ANSI.GetString(TFile.ReadAllBytes(FPath)).Contains('Program Files'),
    'Путь не должен попадать в файл базы');
end;

procedure TStorageTests.MetricSeries_IsDownsampledByAverage;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHMetricHistory;
  LSeries: TArray<TMHMetric>;
  LStart: TDateTime;
  I: Integer;
begin
  LRepo := Open;
  LIntf := LRepo;
  LStart := FAKE_NOW - 1 / HoursPerDay;
  for I := 0 to 99 do
    LRepo.SaveSnapshot(Snap(I, LStart + I / SecsPerDay, I));
  // 100 с данных, 10 точек -> интервалы по 10 с, среднее 4.5, 14.5, ...
  LSeries := LIntf.LoadMetricSeries(mkCpuPercent, LStart, LStart + 100 / SecsPerDay, 10);
  Assert.AreEqual(10, Integer(Length(LSeries)));
  for I := 0 to 9 do
  begin
    Assert.IsTrue(LSeries[I].HasValue);
    Assert.AreEqual(I * 10 + 4.5, LSeries[I].Value, 0.0001);
    Assert.AreEqual<TMHMetricKind>(mkCpuPercent, LSeries[I].Kind);
  end;
  Assert.IsTrue(LSeries[1].TimestampUtc > LSeries[0].TimestampUtc);
end;

procedure TStorageTests.MetricSeries_NullValues_AreNoData;
var
  LRepo: IMHRepository;
  LSeries: TArray<TMHMetric>;
begin
  LRepo := Open;
  LRepo.SaveSnapshot(Snap(1, FAKE_NOW, 10));
  LSeries := (LRepo as IMHMetricHistory).LoadMetricSeries(mkDiskActivePercent,
    FAKE_NOW - 1 / HoursPerDay, FAKE_NOW + 1 / HoursPerDay, 60);
  Assert.AreEqual(1, Integer(Length(LSeries)));
  Assert.IsFalse(LSeries[0].HasValue, 'Значение NULL — «нет данных», а не 0');
end;

procedure TStorageTests.MetricSeries_FirstBucketNull_IsLocaleIndependent;
var
  LRepo: IMHRepository;
  LSnapshot: TMHSnapshot;
  LSeries: TArray<TMHMetric>;
  LSaved: TFormatSettings;
begin
  // Регрессия: первый интервал без значения (первый замер CPU) делал колонку AVG
  // строковой, и при десятичной запятой загрузка истории падала.
  LRepo := Open;
  LSnapshot := Snap(1, FAKE_NOW - 2 / SecsPerDay, 0);
  LSnapshot.Metrics[0] := TMHMetric.NoData(mkCpuPercent, LSnapshot.TimestampUtc);
  LRepo.SaveSnapshot(LSnapshot);
  LRepo.SaveSnapshot(Snap(2, FAKE_NOW - 1 / SecsPerDay, 75.25));
  LRepo.SaveSnapshot(Snap(3, FAKE_NOW, 25.5));
  LSaved := FormatSettings;
  FormatSettings.DecimalSeparator := ',';
  try
    LSeries := (LRepo as IMHMetricHistory).LoadMetricSeries(mkCpuPercent,
      FAKE_NOW - 3 / SecsPerDay, FAKE_NOW + 1 / SecsPerDay, 4);
  finally
    FormatSettings := LSaved;
  end;
  Assert.AreEqual(3, Integer(Length(LSeries)));
  Assert.IsFalse(LSeries[0].HasValue);
  Assert.AreEqual(75.25, LSeries[1].Value, 0.0001);
  Assert.AreEqual(25.5, LSeries[2].Value, 0.0001);
end;

procedure TStorageTests.MetricSeries_EmptyOrInvalidRange;
var
  LRepo: IMHRepository;
  LHistory: IMHMetricHistory;
begin
  LRepo := Open;
  LHistory := LRepo as IMHMetricHistory;
  LRepo.SaveSnapshot(Snap(1, FAKE_NOW, 10));
  Assert.AreEqual(0, Integer(Length(LHistory.LoadMetricSeries(mkGpuPercent, 0, FAKE_NOW + 1, 10))),
    'Метрика, которой нет в истории');
  Assert.AreEqual(0, Integer(Length(LHistory.LoadMetricSeries(mkCpuPercent, FAKE_NOW, FAKE_NOW - 1, 10))));
  Assert.AreEqual(0, Integer(Length(LHistory.LoadMetricSeries(mkCpuPercent, 0, FAKE_NOW + 1, 0))));
end;

procedure TStorageTests.ProcessSeries_SeparatesReusedPid;
var
  LRepo: IMHRepository;
  LSnapshot: TMHSnapshot;
  LSeries: TArray<TMHMetric>;
begin
  LRepo := Open;
  LSnapshot := Snap(1, FAKE_NOW - 2 / SecsPerDay, 10, 1); // PID 1000, create 5000, CPU 0
  LRepo.SaveSnapshot(LSnapshot);
  LSnapshot := Snap(2, FAKE_NOW - 1 / SecsPerDay, 10, 1);
  LSnapshot.Processes[0].Id := TMHProcessId.Create(1000, 9999); // тот же PID, другой процесс
  LSnapshot.Processes[0].Cpu := TMHMetric.Available(mkCpuPercent, 90, FAKE_NOW);
  LRepo.SaveSnapshot(LSnapshot);

  LSeries := (LRepo as IMHMetricHistory).LoadProcessSeries(TMHProcessId.Create(1000, 5000),
    mkCpuPercent, FAKE_NOW - 1 / HoursPerDay, FAKE_NOW, 100);
  Assert.AreEqual(1, Integer(Length(LSeries)));
  Assert.AreEqual(0.0, LSeries[0].Value, 0.0001);
end;

procedure TStorageTests.ProcessSeries_UnsupportedKind_Raises;
var
  LHistory: IMHMetricHistory;
begin
  LHistory := Open;
  Assert.WillRaise(
    procedure
    begin
      LHistory.LoadProcessSeries(TMHProcessId.Create(1, 1), mkDiskActivePercent, 0, 1, 10);
    end, EArgumentException);
end;

procedure TStorageTests.Retention_RemovesOldSnapshots;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LOptions: TMHStorageOptions;
begin
  LOptions := TMHStorageOptions.Default;
  LOptions.RetentionDays := 7;
  LRepo := Open(LOptions);
  LIntf := LRepo;
  LRepo.SaveSnapshot(Snap(1, FAKE_NOW - 10, 1));
  LRepo.SaveSnapshot(Snap(2, FAKE_NOW - 6, 2));
  LRepo.SaveSnapshot(Snap(3, FAKE_NOW, 3));
  LRepo.RunMaintenance;
  Assert.AreEqual<Int64>(2, LRepo.GetStats.SnapshotCount);
  Assert.AreEqual(0, Integer(Length(LRepo.LoadHistory(0, FAKE_NOW - 7, 10))));
  Assert.IsTrue(FLogger.ContainsText('Ротация'));
end;

procedure TStorageTests.SizeLimit_RemovesOldestFirst;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LOptions: TMHStorageOptions;
  LStats: TMHHistoryStats;
  I: Integer;
begin
  LOptions := TMHStorageOptions.Default;
  LOptions.MaxDatabaseBytes := 4 * 1024 * 1024; // минимально допустимый предел
  LOptions.MaxProcessesPerSnapshot := 60;
  LOptions.MaintenanceEverySaves := 100000;    // только явное обслуживание
  LRepo := Open(LOptions);
  LIntf := LRepo;
  for I := 1 to 700 do
    LRepo.SaveSnapshot(Snap(I, FAKE_NOW - (700 - I) / SecsPerDay, I, 60));
  LRepo.RunMaintenance;
  LStats := LRepo.GetStats;
  Assert.IsTrue(LStats.SnapshotCount < 700, 'Старые снимки должны быть удалены');
  Assert.IsTrue(LStats.SnapshotCount > 0, 'Свежие снимки должны остаться');
  Assert.AreEqual(FAKE_NOW, LStats.NewestUtc, 1 / MSecsPerDay);
  Assert.IsTrue(LStats.FileSizeBytes <= Int64(LOptions.MaxDatabaseBytes) * 2,
    Format('Файл %d байт', [LStats.FileSizeBytes]));
end;

procedure TStorageTests.AutoMaintenance_RunsAfterNSaves;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LOptions: TMHStorageOptions;
  I: Integer;
begin
  LOptions := TMHStorageOptions.Default;
  LOptions.RetentionDays := 1;
  LOptions.MaintenanceEverySaves := 5;
  LRepo := Open(LOptions);
  LIntf := LRepo;
  LRepo.SaveSnapshot(Snap(1, FAKE_NOW - 3, 1)); // устаревший
  for I := 2 to 5 do
    LRepo.SaveSnapshot(Snap(I, FAKE_NOW, I));
  Assert.AreEqual<Int64>(4, LRepo.GetStats.SnapshotCount);
end;

procedure TStorageTests.Batch_WrittenAfterIntervalNotEachSnapshot;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  I: Integer;
begin
  Assert.AreEqual(60, TMHStorageOptions.Default.FlushIntervalSec, 'По умолчанию — раз в минуту');
  LRepo := Open;
  LIntf := LRepo;
  // Снимки каждые 2 с в течение 58 с — на диске ещё ничего нет.
  for I := 1 to 30 do
  begin
    LRepo.SaveSnapshot(Snap(I, FClock.NowUtc, I, 5));
    if I < 30 then
      FClock.AdvanceMs(2000);
  end;
  Assert.AreEqual<Int64>(0, RawCount(FPath, 'snapshots'), 'Каждый снимок не пишется отдельно');
  // Прошла минута с первого снимка в очереди — весь пакет одной транзакцией.
  FClock.AdvanceMs(2000);
  LRepo.SaveSnapshot(Snap(31, FClock.NowUtc, 31, 5));
  Assert.AreEqual<Int64>(31, RawCount(FPath, 'snapshots'));
  Assert.AreEqual<Int64>(31 * 5, RawCount(FPath, 'process_samples'));
  Assert.AreEqual<Int64>(31 * 3, RawCount(FPath, 'metrics'));
  // Новый пакет начинается заново.
  FClock.AdvanceMs(2000);
  LRepo.SaveSnapshot(Snap(32, FClock.NowUtc, 32));
  Assert.AreEqual<Int64>(31, RawCount(FPath, 'snapshots'));
end;

procedure TStorageTests.Batch_ReadAndCloseWritePending;
var
  LRepo: TMHSQLiteRepository;
  LSnapshots: TArray<TMHSnapshot>;
begin
  LRepo := Open;
  try
    LRepo.SaveSnapshot(Snap(1, FAKE_NOW, 10, 2));
    Assert.AreEqual<Int64>(0, RawCount(FPath, 'snapshots'));
    // Чтение видит очередь: она записывается перед запросом.
    LSnapshots := LRepo.LoadHistory(FAKE_NOW - 1, FAKE_NOW + 1, 10);
    Assert.AreEqual(1, Integer(Length(LSnapshots)));
    Assert.AreEqual(2, Integer(Length(LSnapshots[0].Processes)));
    Assert.AreEqual<Int64>(1, RawCount(FPath, 'snapshots'));
    Assert.AreEqual(1, Integer(Length(LRepo.LoadMetricSeries(mkCpuPercent, FAKE_NOW - 1, FAKE_NOW + 1, 10))));
    // Явная запись.
    LRepo.SaveSnapshot(Snap(2, FAKE_NOW + 1 / SecsPerDay, 20));
    LRepo.Flush;
    Assert.AreEqual<Int64>(2, RawCount(FPath, 'snapshots'));
    // Закрытие записывает остаток.
    LRepo.SaveSnapshot(Snap(3, FAKE_NOW + 2 / SecsPerDay, 30));
    LRepo.SaveSnapshot(Snap(4, FAKE_NOW + 3 / SecsPerDay, 40));
  finally
    LRepo.Free;
  end;
  Assert.AreEqual<Int64>(4, RawCount(FPath, 'snapshots'), 'При закрытии очередь не теряется');
end;

procedure TStorageTests.Batch_ZeroInterval_WritesEachSnapshot;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LOptions: TMHStorageOptions;
begin
  LOptions := TMHStorageOptions.Default;
  LOptions.FlushIntervalSec := 0;
  LRepo := Open(LOptions);
  LIntf := LRepo;
  LRepo.SaveSnapshot(Snap(1, FAKE_NOW, 1));
  Assert.AreEqual<Int64>(1, RawCount(FPath, 'snapshots'));
  LRepo.SaveSnapshot(Snap(2, FAKE_NOW, 2));
  Assert.AreEqual<Int64>(2, RawCount(FPath, 'snapshots'));
  // Включение пакетов и обратно: накопленное пишется при переходе на «сразу».
  LOptions.FlushIntervalSec := 60;
  LRepo.Options := LOptions;
  LRepo.SaveSnapshot(Snap(3, FAKE_NOW, 3));
  Assert.AreEqual<Int64>(2, RawCount(FPath, 'snapshots'));
  LOptions.FlushIntervalSec := 0;
  LRepo.Options := LOptions;
  Assert.AreEqual<Int64>(3, RawCount(FPath, 'snapshots'));
  // Границы параметра.
  LOptions.FlushIntervalSec := -5;
  Assert.AreEqual(0, LOptions.Normalized.FlushIntervalSec);
  LOptions.FlushIntervalSec := 100000;
  Assert.AreEqual(3600, LOptions.Normalized.FlushIntervalSec);
end;

procedure TStorageTests.Batch_FindingsMergedInOneWrite;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LStored: TArray<TMHStoredFinding>;
begin
  LRepo := Open;
  LIntf := LRepo;
  LRepo.SaveFindings([BatchFinding('k1', 40, FAKE_NOW - 2 / SecsPerDay)]);
  LRepo.SaveFindings([BatchFinding('k1', 70, FAKE_NOW - 1 / SecsPerDay),
    BatchFinding('k2', 30, FAKE_NOW - 1 / SecsPerDay)]);
  LRepo.SaveFindings([BatchFinding('k1', 50, FAKE_NOW)]);
  Assert.AreEqual<Int64>(0, RawCount(FPath, 'findings'), 'Находки ждут пакета');
  LStored := LRepo.LoadFindings(FAKE_NOW - 1, FAKE_NOW + 1, 10);
  Assert.AreEqual(2, Integer(Length(LStored)));
  Assert.AreEqual('k1', LStored[0].Finding.Key);
  // Повторы объединяются так же, как при записи по одной.
  Assert.AreEqual(3, LStored[0].Occurrences);
  Assert.AreEqual(70, LStored[0].MaxScore);
  Assert.AreEqual(50, LStored[0].Finding.Score, 'Состояние — от последнего наблюдения');
  Assert.AreEqual(FAKE_NOW - 2 / SecsPerDay, LStored[0].FirstSeenUtc, 1 / MSecsPerDay);
  Assert.AreEqual(FAKE_NOW, LStored[0].LastSeenUtc, 1 / MSecsPerDay);
  Assert.AreEqual(1, LStored[1].Occurrences);
end;

procedure TStorageTests.Batch_ClockBackOrClear;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LClock: TFakeClock;
  LClockIntf: IMHClock;
begin
  LClock := TFakeClock.Create(FAKE_NOW + 1 / HoursPerDay);
  LClockIntf := LClock;
  LRepo := TMHSQLiteRepository.Create(FPath, TMHStorageOptions.Default, LClockIntf, FLoggerIntf);
  LIntf := LRepo;
  LRepo.SaveSnapshot(Snap(2, FAKE_NOW + 1 / HoursPerDay, 2));
  Assert.AreEqual<Int64>(0, RawCount(FPath, 'snapshots'));
  // Часы переведены назад: пакет не ждёт минуту от «будущего» времени.
  LClock.SetNow(FAKE_NOW);
  LRepo.SaveSnapshot(Snap(3, FAKE_NOW, 3));
  Assert.AreEqual<Int64>(2, RawCount(FPath, 'snapshots'), 'Часы назад — пакет записан');
  // Очистка истории удаляет и очередь.
  LRepo.SaveSnapshot(Snap(4, FAKE_NOW, 4));
  LRepo.SaveFindings([BatchFinding('k', 50, FAKE_NOW)]);
  LRepo.Clear;
  LRepo.Flush;
  Assert.AreEqual<Int64>(0, RawCount(FPath, 'snapshots'));
  Assert.AreEqual<Int64>(0, RawCount(FPath, 'findings'));
end;

procedure TStorageTests.Batch_QueueKeepsCopyOfSnapshot;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LSnapshot: TMHSnapshot;
  LSeries: TArray<TMHMetric>;
begin
  LRepo := Open;
  LIntf := LRepo;
  LSnapshot := Snap(1, FAKE_NOW, 25, 3);
  LRepo.SaveSnapshot(LSnapshot);
  // Сканер может менять массивы своего снимка после вызова — в очереди копия.
  LSnapshot.Metrics[0] := TMHMetric.Available(mkCpuPercent, 99, FAKE_NOW);
  LSnapshot.Processes[0].Name := 'changed.exe';
  LSeries := LRepo.LoadMetricSeries(mkCpuPercent, FAKE_NOW - 1, FAKE_NOW + 1, 10);
  Assert.AreEqual(1, Integer(Length(LSeries)));
  Assert.AreEqual(25.0, LSeries[0].Value, 0.001);
  Assert.AreEqual(3, Integer(Length(LRepo.LoadHistory(FAKE_NOW - 1, FAKE_NOW + 1, 10)[0].Processes)));
end;

procedure TStorageTests.Clear_RemovesEverything;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
begin
  LRepo := Open;
  LIntf := LRepo;
  LRepo.SaveSnapshot(Snap(1, FAKE_NOW, 1, 3));
  LRepo.Clear;
  Assert.AreEqual<Int64>(0, LRepo.GetStats.SnapshotCount);
  LRepo.SaveSnapshot(Snap(2, FAKE_NOW, 2));
  Assert.AreEqual<Int64>(1, LRepo.GetStats.SnapshotCount, 'После очистки запись продолжается');
end;

procedure TStorageTests.CorruptFile_IsQuarantinedAndRecreated;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LGarbage: TBytes;
  I: Integer;
begin
  SetLength(LGarbage, 64 * 1024);
  for I := 0 to High(LGarbage) do
    LGarbage[I] := Byte(I * 31 + 7);
  TFile.WriteAllBytes(FPath, LGarbage);

  LRepo := Open;
  LIntf := LRepo;
  Assert.IsNotEmpty(LRepo.RecoveredFrom);
  Assert.IsTrue(FileExists(LRepo.RecoveredFrom), 'Повреждённый файл сохранён для анализа');
  Assert.AreEqual(Int64(Length(LGarbage)), TFile.GetSize(LRepo.RecoveredFrom));
  LRepo.SaveSnapshot(Snap(1, FAKE_NOW, 1));
  Assert.AreEqual<Int64>(1, LRepo.GetStats.SnapshotCount);
  Assert.IsTrue(FLogger.ContainsText('повреждена'));
end;

procedure TStorageTests.NewerSchema_IsNotModified;
var
  LConnection: TFDConnection;
begin
  Open.Free;
  LConnection := TFDConnection.Create(nil);
  try
    LConnection.DriverName := 'SQLite';
    LConnection.Params.Database := FPath;
    LConnection.LoginPrompt := False;
    LConnection.ExecSQL('UPDATE schema_version SET version = 99');
  finally
    LConnection.Free;
  end;
  Assert.WillRaise(
    procedure
    begin
      Open.Free;
    end, EMHStorageError);
  Assert.IsTrue(FileExists(FPath), 'База более новой версии не должна удаляться');
end;

procedure TStorageTests.InvalidLocation_RaisesStorageError;
var
  LBlocker: string;
  LClock: IMHClock;
  LLogger: IMHLogger;
begin
  // Каталог базы совпадает с существующим файлом — создать базу невозможно.
  LBlocker := TPath.Combine(FDir, 'blocker');
  TFile.WriteAllText(LBlocker, 'x');
  LClock := FClockIntf;
  LLogger := FLoggerIntf;
  Assert.WillRaise(
    procedure
    begin
      TMHSQLiteRepository.Create(TPath.Combine(LBlocker, 'history.db'),
        TMHStorageOptions.Default, LClock, LLogger).Free;
    end, EMHStorageError);
end;

procedure TStorageTests.ConcurrentSaveAndRead;
const
  COUNT = 150;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LWriter: TThread;
  LError: string;
  LReads: Integer;
begin
  LRepo := Open;
  LIntf := LRepo;
  LError := '';
  LWriter := TThread.CreateAnonymousThread(
    procedure
    var
      I: Integer;
    begin
      try
        for I := 1 to COUNT do
          LIntf.SaveSnapshot(Snap(I, FAKE_NOW - (COUNT - I) / SecsPerDay, I, 5));
      except
        on E: Exception do
          LError := E.Message;
      end;
    end);
  LWriter.FreeOnTerminate := False;
  LWriter.Start;
  LReads := 0;
  try
    while not LWriter.Finished do
    begin
      LRepo.LoadMetricSeries(mkCpuPercent, FAKE_NOW - 1, FAKE_NOW + 1, 50);
      LRepo.LoadHistory(FAKE_NOW - 1, FAKE_NOW + 1, 20);
      Inc(LReads);
    end;
    LWriter.WaitFor;
  finally
    LWriter.Free;
  end;
  Assert.AreEqual('', LError);
  Assert.AreEqual<Int64>(COUNT, LRepo.GetStats.SnapshotCount);
  Assert.IsTrue(LReads > 0);
end;

{ TStoragePerformanceTests }

procedure TStoragePerformanceTests.WeekOfHistory_SeriesQueryIsFast;
const
  SNAPSHOTS = 5000;
  QUERY_LIMIT_MS = 1000;
var
  LDir: string;
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LClock: IMHClock;
  LWatch: TStopwatch;
  LSeries: TArray<TMHMetric>;
  LStep: Double;
  I: Integer;
begin
  LDir := NewTempDir;
  try
    LClock := TFakeClock.Create(FAKE_NOW);
    LRepo := TMHSQLiteRepository.Create(TPath.Combine(LDir, 'perf.db'),
      TMHStorageOptions.Default, LClock, TMHNullLogger.Create);
    LIntf := LRepo;
    // Неделя истории, равномерно распределённая по 5000 снимкам.
    LStep := 7 / SNAPSHOTS;
    for I := 1 to SNAPSHOTS do
      LRepo.SaveSnapshot(Snap(I, FAKE_NOW - 7 + I * LStep, I mod 100, 10));
    LWatch := TStopwatch.StartNew;
    LSeries := LRepo.LoadMetricSeries(mkCpuPercent, FAKE_NOW - 7, FAKE_NOW, 600);
    LWatch.Stop;
    Assert.IsTrue(Length(LSeries) > 500);
    Assert.IsTrue(LWatch.ElapsedMilliseconds < QUERY_LIMIT_MS,
      Format('Запрос недельного ряда занял %d мс', [LWatch.ElapsedMilliseconds]));
  finally
    LIntf := nil; // закрыть базу до удаления каталога, в том числе при ошибке
    try
      TDirectory.Delete(LDir, True);
    except
    end;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TStorageTests);
  TDUnitX.RegisterTestFixture(TStoragePerformanceTests);

end.
