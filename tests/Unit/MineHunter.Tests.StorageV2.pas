unit MineHunter.Tests.StorageV2;

{
  Тесты схемы 2 хранилища SQLite: миграция с версии 1, контекст снимков,
  история находок, журнал действий, профили нормы и прореженная выборка.
  Каждый тест работает во временном каталоге, который удаляется в TearDown.
}

interface

uses
  DUnitX.TestFramework,
  FireDAC.Comp.Client,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Storage.SQLite,
  MineHunter.Tests.Fakes;

type
  [TestFixture]
  [Category('Storage')]
  TStorageV2Tests = class
  private
    FDir: string;
    FPath: string;
    FClock: TFakeClock;
    FClockIntf: IMHClock;
    FLogger: TRecordingLogger;
    FLoggerIntf: IMHLogger;
    function Open(const AOptions: TMHStorageOptions): TMHSQLiteRepository; overload;
    function Open: TMHSQLiteRepository; overload;
    function OpenRaw: TFDConnection;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Migration_V1ToV2_PreservesData;
    [Test] procedure Context_RoundTrip;
    [Test] procedure CountSnapshots_ByContextAndPeriod;
    [Test] procedure Findings_RepeatsAreMerged;
    [Test] procedure Findings_EmptyKey_DerivedFromProcessAndCategory;
    [Test] procedure Findings_NewestFirstRangeAndLimit;
    [Test] procedure Findings_CorruptJson_IsSkipped;
    [Test] procedure Actions_NewestFirstAndCapped;
    [Test] procedure Baselines_SaveReplaceLoad;
    [Test] procedure Baselines_CorruptRow_IsSkippedAndLogged;
    [Test] procedure Sampled_LimitAndContextFilter;
    [Test] procedure Sampled_EvenlySpreadAcrossInterval;
    [Test] procedure Maintenance_RemovesOldFindings;
    [Test] procedure Clear_RemovesFindingsKeepsActions;
    [Test] procedure CacheSize_IsLimited;
  end;

  [TestFixture]
  [Category('Performance')]
  TStorageV2PerformanceTests = class
  public
    [Test] procedure Sampled_100kSnapshots_IsFast;
  end;

implementation

uses
  System.SysUtils, System.IOUtils, System.DateUtils, System.Diagnostics, System.Variants,
  FireDAC.Stan.Def, FireDAC.Phys.SQLite, FireDAC.Stan.Async, FireDAC.DApt,
  FireDAC.ConsoleUI.Wait,
  MineHunter.Core.Logging, MineHunter.Analysis.Baseline;

const
  // Схема версии 1 (копия миграции 1) для проверки обновления на месте.
  V1_DDL =
    'CREATE TABLE schema_version(version INTEGER NOT NULL);' +
    'INSERT INTO schema_version(version) VALUES (1);' +
    'CREATE TABLE snapshots(' +
    '  id INTEGER PRIMARY KEY,' +
    '  seq BIGINT NOT NULL,' +
    '  ts BIGINT NOT NULL);' +
    'CREATE INDEX ix_snapshots_ts ON snapshots(ts);' +
    'CREATE TABLE metrics(' +
    '  snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,' +
    '  kind TEXT NOT NULL,' +
    '  value REAL,' +
    '  PRIMARY KEY(snapshot_id, kind)) WITHOUT ROWID;' +
    'CREATE TABLE sources(' +
    '  snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,' +
    '  source_id TEXT NOT NULL,' +
    '  state TEXT NOT NULL,' +
    '  message TEXT,' +
    '  requires_elevation INTEGER NOT NULL,' +
    '  duration_ms BIGINT NOT NULL,' +
    '  item_count INTEGER NOT NULL,' +
    '  PRIMARY KEY(snapshot_id, source_id)) WITHOUT ROWID;' +
    'CREATE TABLE process_samples(' +
    '  snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,' +
    '  pid BIGINT NOT NULL,' +
    '  create_time BIGINT NOT NULL,' +
    '  parent_pid BIGINT NOT NULL,' +
    '  name TEXT NOT NULL,' +
    '  image_path TEXT,' +
    '  access TEXT NOT NULL,' +
    '  cpu REAL,' +
    '  working_set REAL,' +
    '  private_bytes REAL,' +
    '  thread_count INTEGER NOT NULL,' +
    '  source_id TEXT NOT NULL,' +
    '  PRIMARY KEY(snapshot_id, pid, create_time, source_id)) WITHOUT ROWID;' +
    'CREATE INDEX ix_process_samples_identity ON process_samples(pid, create_time);';

function NewTempDir: string;
begin
  Result := TPath.Combine(TPath.GetTempPath, 'MineHunterTests\' +
    TGUID.NewGuid.ToString.Replace('{', '').Replace('}', ''));
  ForceDirectories(Result);
end;

function RawConnection(const APath: string): TFDConnection;
begin
  Result := TFDConnection.Create(nil);
  try
    Result.DriverName := 'SQLite';
    Result.Params.Database := APath;
    Result.Params.Values['OpenMode'] := 'CreateUTF8';
    Result.Params.Values['StringFormat'] := 'Unicode';
    Result.LoginPrompt := False;
    Result.Connected := True;
  except
    Result.Free;
    raise;
  end;
end;

function Snap(ASeq: UInt64; ATime: TDateTime; ACpu: Double; AContext: TMHWorkContext;
  AHasContext: Boolean = True): TMHSnapshot;
var
  LInfo: TMHProcessInfo;
begin
  Result := TMHSnapshot.Create(ASeq, ATime);
  Result.Metrics := [TMHMetric.Available(mkCpuPercent, ACpu, ATime),
    TMHMetric.Available(mkMemoryLoadPercent, 40, ATime)];
  LInfo := TMHProcessInfo.Create(TMHProcessId.Create(100, 200), 'app.exe', ATime);
  LInfo.ImagePath := 'C:\Apps\app.exe';
  LInfo.Cpu := TMHMetric.Available(mkCpuPercent, ACpu / 2, ATime);
  LInfo.WorkingSet := TMHMetric.Available(mkWorkingSetBytes, 4096, ATime);
  LInfo.SourceId := 'processes';
  Result.Processes := [LInfo];
  Result.Context.Available := AHasContext;
  if AHasContext then
    Result.Context.WorkContext := AContext;
end;

function Finding(const AKey: string; AScore: Integer; ADetected: TDateTime): TMHFinding;
begin
  Result := Default(TMHFinding);
  Result.Id := TGUID.NewGuid;
  Result.Key := AKey;
  Result.Process := TMHProcessId.Create(4321, $1D9A0000);
  Result.ProcessName := 'miner.exe';
  Result.Title := 'Находка ' + AKey;
  Result.Score := AScore;
  Result.Level := TMHRiskThresholds.Default.LevelOf(AScore);
  Result.Category := fcMining;
  Result.DetectedAtUtc := ADetected;
  Result.RulesetVersion := 'test-1';
end;

function Action(const AName: string; ATime: TDateTime; ASuccess: Boolean): TMHActionRecord;
begin
  Result.TimestampUtc := ATime;
  Result.Action := AName;
  Result.Target := 'C:\Apps\app.exe';
  Result.Result := 'готово';
  Result.Success := ASuccess;
end;

function Baseline(AContext: TMHWorkContext; ASamples: Integer): TMHBaseline;
var
  LValues: TArray<Double>;
begin
  Result := TMHBaseline.Empty;
  Result.Context := AContext;
  Result.CreatedUtc := FAKE_NOW - 1;
  Result.UpdatedUtc := FAKE_NOW;
  Result.SampleCount := ASamples;
  Result.PeriodFromUtc := FAKE_NOW - 3;
  Result.PeriodToUtc := FAKE_NOW;
  LValues := [10, 20, 30];
  Result.SystemCpu := TMHStat.FromValues(LValues);
  SetLength(Result.Processes, 1);
  Result.Processes[0].Key := 'c:\apps\app.exe';
  Result.Processes[0].Name := 'app.exe';
  LValues := [1, 2, 3];
  Result.Processes[0].Cpu := TMHStat.FromValues(LValues);
  Result.Processes[0].PresenceRatio := 0.5;
end;

{ TStorageV2Tests }

procedure TStorageV2Tests.Setup;
begin
  FDir := NewTempDir;
  FPath := TPath.Combine(FDir, 'history.db');
  FClock := TFakeClock.Create(FAKE_NOW);
  FClockIntf := FClock;
  FLogger := TRecordingLogger.Create;
  FLoggerIntf := FLogger;
end;

procedure TStorageV2Tests.TearDown;
begin
  FLoggerIntf := nil;
  FClockIntf := nil;
  try
    TDirectory.Delete(FDir, True);
  except
    // Каталог мог остаться заблокированным антивирусом — не влияет на результат.
  end;
end;

function TStorageV2Tests.Open(const AOptions: TMHStorageOptions): TMHSQLiteRepository;
begin
  Result := TMHSQLiteRepository.Create(FPath, AOptions, FClockIntf, FLoggerIntf);
end;

function TStorageV2Tests.Open: TMHSQLiteRepository;
begin
  Result := Open(TMHStorageOptions.Default);
end;

function TStorageV2Tests.OpenRaw: TFDConnection;
begin
  Result := RawConnection(FPath);
end;

procedure TStorageV2Tests.Migration_V1ToV2_PreservesData;
var
  LRaw: TFDConnection;
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LLoaded: TArray<TMHSnapshot>;
  LTs: Int64;
  LMetric: TMHMetric;
begin
  LTs := MHUtcToUnixMs(FAKE_NOW - 1 / HoursPerDay);
  LRaw := OpenRaw;
  try
    LRaw.ExecSQL(V1_DDL);
    LRaw.ExecSQL('INSERT INTO snapshots(id, seq, ts) VALUES (1, 77, :ts)', [LTs]);
    LRaw.ExecSQL('INSERT INTO metrics(snapshot_id, kind, value) VALUES (1, ''cpuPercent'', 12.5)');
    LRaw.ExecSQL('INSERT INTO process_samples(snapshot_id, pid, create_time, parent_pid, name, ' +
      'image_path, access, cpu, working_set, private_bytes, thread_count, source_id) VALUES ' +
      '(1, 500, 600, 4, ''old.exe'', ''C:\old.exe'', ''full'', 3, 1000, NULL, 2, ''processes'')');
  finally
    LRaw.Free;
  end;

  LRepo := Open;
  LIntf := LRepo;
  LLoaded := LRepo.LoadHistory(0, FAKE_NOW + 1, 10);
  Assert.AreEqual(1, Integer(Length(LLoaded)));
  Assert.AreEqual<UInt64>(77, LLoaded[0].Sequence);
  Assert.AreEqual(FAKE_NOW - 1 / HoursPerDay, LLoaded[0].TimestampUtc, 1 / MSecsPerDay);
  Assert.IsTrue(LLoaded[0].FindMetric(mkCpuPercent, LMetric));
  Assert.AreEqual(12.5, LMetric.Value, 0.0001);
  Assert.AreEqual(1, Integer(Length(LLoaded[0].Processes)));
  Assert.AreEqual('old.exe', LLoaded[0].Processes[0].Name);
  Assert.IsFalse(LLoaded[0].Context.Available, 'Старые снимки не имеют контекста');
  Assert.IsTrue(FLogger.ContainsText('версии 2'));

  // После миграции доступны новые возможности.
  LRepo.SaveSnapshot(Snap(78, FAKE_NOW, 5, wcWork));
  LRepo.SaveFindings([Finding('k', 50, FAKE_NOW)]);
  Assert.AreEqual(1, Integer(Length(LRepo.LoadFindings(0, FAKE_NOW + 1, 10))));
  LIntf := nil;

  LRaw := OpenRaw;
  try
    Assert.AreEqual(TMHSQLiteRepository.SchemaVersion, Integer(LRaw.ExecSQLScalar('SELECT MAX(version) FROM schema_version')));
    Assert.AreEqual(2, Integer(LRaw.ExecSQLScalar('SELECT COUNT(*) FROM snapshots')));
  finally
    LRaw.Free;
  end;
end;

procedure TStorageV2Tests.Context_RoundTrip;
var
  LRepo: IMHRepository;
  LLoaded: TArray<TMHSnapshot>;
begin
  LRepo := Open;
  LRepo.SaveSnapshot(Snap(1, FAKE_NOW - 2 / SecsPerDay, 1, wcGaming));
  LRepo.SaveSnapshot(Snap(2, FAKE_NOW - 1 / SecsPerDay, 2, wcIdle));
  LRepo.SaveSnapshot(Snap(3, FAKE_NOW, 3, wcWork, False));
  LLoaded := LRepo.LoadHistory(0, FAKE_NOW + 1, 10);
  Assert.AreEqual(3, Integer(Length(LLoaded)));
  Assert.IsTrue(LLoaded[0].Context.Available);
  Assert.AreEqual<TMHWorkContext>(wcGaming, LLoaded[0].Context.WorkContext);
  Assert.IsTrue(LLoaded[1].Context.Available);
  Assert.AreEqual<TMHWorkContext>(wcIdle, LLoaded[1].Context.WorkContext);
  Assert.IsFalse(LLoaded[2].Context.Available, 'Недоступный контекст хранится как NULL');
  Assert.AreEqual<TMHWorkContext>(wcUnknown, LLoaded[2].Context.WorkContext);
end;

procedure TStorageV2Tests.CountSnapshots_ByContextAndPeriod;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  I: Integer;
begin
  LRepo := Open;
  LIntf := LRepo;
  // Прогресс профиля нормы — сколько снимков режима накоплено сейчас, без пересчёта профиля.
  for I := 1 to 5 do
    LIntf.SaveSnapshot(Snap(I, FAKE_NOW - I / SecsPerDay, 1, wcWork));
  LIntf.SaveSnapshot(Snap(10, FAKE_NOW - 1 / SecsPerDay, 1, wcGaming));
  LIntf.SaveSnapshot(Snap(11, FAKE_NOW - 3, 1, wcWork));
  LIntf.SaveSnapshot(Snap(12, FAKE_NOW - 2 / SecsPerDay, 1, wcWork, False));
  Assert.AreEqual<Int64>(5, LRepo.CountSnapshots(FAKE_NOW - 1, FAKE_NOW, wcWork), 'Только режим и период');
  Assert.AreEqual<Int64>(6, LRepo.CountSnapshots(FAKE_NOW - 5, FAKE_NOW, wcWork));
  Assert.AreEqual<Int64>(1, LRepo.CountSnapshots(FAKE_NOW - 1, FAKE_NOW, wcGaming));
  Assert.AreEqual<Int64>(1, LRepo.CountSnapshots(FAKE_NOW - 1, FAKE_NOW, wcUnknown), 'Без контекста — «неизвестно»');
  Assert.AreEqual<Int64>(0, LRepo.CountSnapshots(FAKE_NOW + 1, FAKE_NOW + 2, wcWork));
end;

procedure TStorageV2Tests.CacheSize_IsLimited;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
begin
  LRepo := Open;
  LIntf := LRepo;
  // Значение FireDAC по умолчанию (10000 страниц) давало рост памяти на десятки МБ.
  Assert.AreEqual(TMHSQLiteRepository.CacheSizePages, LRepo.CacheSizeSetting);
end;

procedure TStorageV2Tests.Findings_RepeatsAreMerged;
var
  LRepo: IMHFindingHistory;
  LLoaded: TArray<TMHStoredFinding>;
begin
  LRepo := Open;
  LRepo.SaveFindings([Finding('k1', 40, FAKE_NOW - 10 / MinsPerDay)]);
  LRepo.SaveFindings([Finding('k1', 70, FAKE_NOW - 5 / MinsPerDay)]);
  LRepo.SaveFindings([Finding('k1', 50, FAKE_NOW)]);
  // Запоздавшее старое наблюдение расширяет интервал, но не заменяет данные.
  LRepo.SaveFindings([Finding('k1', 10, FAKE_NOW - 20 / MinsPerDay)]);

  LLoaded := LRepo.LoadFindings(0, FAKE_NOW + 1, 10);
  Assert.AreEqual(1, Integer(Length(LLoaded)));
  Assert.AreEqual(4, LLoaded[0].Occurrences);
  Assert.AreEqual(70, LLoaded[0].MaxScore);
  Assert.AreEqual(50, LLoaded[0].Finding.Score, 'Данные от самого позднего наблюдения');
  Assert.AreEqual('k1', LLoaded[0].Finding.Key);
  Assert.AreEqual(FAKE_NOW - 20 / MinsPerDay, LLoaded[0].FirstSeenUtc, 1 / MSecsPerDay);
  Assert.AreEqual(FAKE_NOW, LLoaded[0].LastSeenUtc, 1 / MSecsPerDay);
  Assert.AreEqual('Находка k1', LLoaded[0].Finding.Title);
end;

procedure TStorageV2Tests.Findings_EmptyKey_DerivedFromProcessAndCategory;
var
  LRepo: IMHFindingHistory;
  LLoaded: TArray<TMHStoredFinding>;
  LOther: TMHFinding;
  LExpected: string;
begin
  LRepo := Open;
  LOther := Finding('', 30, FAKE_NOW);
  LOther.Category := fcSuspicious;
  LRepo.SaveFindings([Finding('', 40, FAKE_NOW - 1 / MinsPerDay), Finding('', 60, FAKE_NOW),
    LOther]);
  LLoaded := LRepo.LoadFindings(0, FAKE_NOW + 1, 10);
  Assert.AreEqual(2, Integer(Length(LLoaded)), 'Категории не объединяются');
  LExpected := MHDefaultFindingKey(Finding('', 0, 0));
  Assert.AreEqual(TMHProcessId.Create(4321, $1D9A0000).ToString + '|mining', LExpected);
  if LLoaded[0].Finding.Key = LExpected then
    Assert.AreEqual(2, LLoaded[0].Occurrences)
  else
  begin
    Assert.AreEqual(LExpected, LLoaded[1].Finding.Key);
    Assert.AreEqual(2, LLoaded[1].Occurrences);
  end;
end;

procedure TStorageV2Tests.Findings_NewestFirstRangeAndLimit;
var
  LRepo: IMHFindingHistory;
  LLoaded: TArray<TMHStoredFinding>;
begin
  LRepo := Open;
  LRepo.SaveFindings([Finding('a', 20, FAKE_NOW - 3 / HoursPerDay),
    Finding('b', 30, FAKE_NOW - 2 / HoursPerDay), Finding('c', 40, FAKE_NOW - 1 / HoursPerDay)]);
  LLoaded := LRepo.LoadFindings(FAKE_NOW - 2.5 / HoursPerDay, FAKE_NOW, 10);
  Assert.AreEqual(2, Integer(Length(LLoaded)));
  Assert.AreEqual('c', LLoaded[0].Finding.Key, 'Новые первыми');
  Assert.AreEqual('b', LLoaded[1].Finding.Key);
  LLoaded := LRepo.LoadFindings(0, FAKE_NOW + 1, 1);
  Assert.AreEqual(1, Integer(Length(LLoaded)));
  Assert.AreEqual('c', LLoaded[0].Finding.Key);
  Assert.AreEqual(0, Integer(Length(LRepo.LoadFindings(0, FAKE_NOW + 1, 0))));
end;

procedure TStorageV2Tests.Findings_CorruptJson_IsSkipped;
var
  LRepo: IMHFindingHistory;
  LRaw: TFDConnection;
begin
  LRepo := Open;
  LRepo.SaveFindings([Finding('good', 20, FAKE_NOW), Finding('bad', 30, FAKE_NOW)]);
  LRepo := nil;
  LRaw := OpenRaw;
  try
    LRaw.ExecSQL('UPDATE findings SET json = ''{oops'' WHERE key = ''bad''');
  finally
    LRaw.Free;
  end;
  LRepo := Open;
  Assert.AreEqual(1, Integer(Length(LRepo.LoadFindings(0, FAKE_NOW + 1, 10))));
  Assert.IsTrue(FLogger.ContainsText('повреждена'));
end;

procedure TStorageV2Tests.Actions_NewestFirstAndCapped;
var
  LOptions: TMHStorageOptions;
  LRepo: IMHActionLog;
  LLoaded: TArray<TMHActionRecord>;
  I: Integer;
begin
  LOptions := TMHStorageOptions.Default;
  LOptions.MaxActionRecords := 10;
  LRepo := Open(LOptions);
  for I := 1 to 15 do
    LRepo.LogAction(Action(Format('действие %d', [I]), FAKE_NOW - (15 - I) / MinsPerDay,
      Odd(I)));
  LLoaded := LRepo.LoadActions(100);
  Assert.AreEqual(10, Integer(Length(LLoaded)), 'Хранятся только последние записи');
  Assert.AreEqual('действие 15', LLoaded[0].Action);
  Assert.AreEqual('действие 6', LLoaded[9].Action);
  Assert.IsTrue(LLoaded[0].Success);
  Assert.IsFalse(LLoaded[1].Success);
  Assert.AreEqual('C:\Apps\app.exe', LLoaded[0].Target);
  Assert.AreEqual('готово', LLoaded[0].Result);
  Assert.AreEqual(FAKE_NOW, LLoaded[0].TimestampUtc, 1 / MSecsPerDay);
  Assert.AreEqual(3, Integer(Length(LRepo.LoadActions(3))));
end;

procedure TStorageV2Tests.Baselines_SaveReplaceLoad;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHBaselineStore;
  LLoaded: TArray<TMHBaseline>;
  LWork: TMHBaseline;
begin
  LRepo := Open;
  LIntf := LRepo;
  LRepo.SaveBaseline(Baseline(wcWork, 100));
  LRepo.SaveBaseline(Baseline(wcIdle, 50));
  LWork := Baseline(wcWork, 200);
  LRepo.SaveBaseline(LWork);
  LIntf := nil;

  LRepo := Open;
  LIntf := LRepo;
  LLoaded := LRepo.LoadBaselines;
  Assert.AreEqual(2, Integer(Length(LLoaded)), 'Профиль контекста заменяется');
  Assert.AreEqual<TMHWorkContext>(wcIdle, LLoaded[0].Context);
  Assert.AreEqual<TMHWorkContext>(wcWork, LLoaded[1].Context);
  Assert.AreEqual(200, LLoaded[1].SampleCount);
  Assert.AreEqual(20.0, LLoaded[1].SystemCpu.Median, 0.0001);
  Assert.AreEqual(1, Integer(Length(LLoaded[1].Processes)));
  Assert.AreEqual('c:\apps\app.exe', LLoaded[1].Processes[0].Key);
  Assert.AreEqual(0.5, LLoaded[1].Processes[0].PresenceRatio, 0.0001);
end;

procedure TStorageV2Tests.Baselines_CorruptRow_IsSkippedAndLogged;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHBaselineStore;
  LRaw: TFDConnection;
  LLoaded: TArray<TMHBaseline>;
begin
  LRepo := Open;
  LIntf := LRepo;
  LRepo.SaveBaseline(Baseline(wcWork, 100));
  LRepo.SaveBaseline(Baseline(wcIdle, 50));
  LIntf := nil;
  LRaw := OpenRaw;
  try
    LRaw.ExecSQL('UPDATE baselines SET json = ''{"schema": 2, "context": '' WHERE context = ''idle''');
  finally
    LRaw.Free;
  end;
  LRepo := Open;
  LIntf := LRepo;
  LLoaded := LRepo.LoadBaselines;
  Assert.AreEqual(1, Integer(Length(LLoaded)));
  Assert.AreEqual<TMHWorkContext>(wcWork, LLoaded[0].Context);
  Assert.IsTrue(FLogger.ContainsText('повреждён'));
end;

procedure TStorageV2Tests.Sampled_LimitAndContextFilter;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LLoaded: TArray<TMHSnapshot>;
  LSnap: TMHSnapshot;
  LStart: TDateTime;
  I: Integer;
begin
  LRepo := Open;
  LIntf := LRepo;
  LStart := FAKE_NOW - 2 / HoursPerDay;
  // 100 снимков «работа», 30 «простой», 10 без контекста — вперемешку по времени.
  for I := 0 to 99 do
    LRepo.SaveSnapshot(Snap(I, LStart + I / MinsPerDay, I, wcWork));
  for I := 0 to 29 do
    LRepo.SaveSnapshot(Snap(1000 + I, LStart + (I + 0.5) / MinsPerDay, 1, wcIdle));
  for I := 0 to 9 do
    LRepo.SaveSnapshot(Snap(2000 + I, LStart + (I + 0.25) / MinsPerDay, 1, wcWork, False));

  LLoaded := LRepo.LoadSnapshotsSampled(0, FAKE_NOW + 1, 10, wcWork);
  Assert.AreEqual(10, Integer(Length(LLoaded)));
  for LSnap in LLoaded do
  begin
    Assert.IsTrue(LSnap.Context.Available);
    Assert.AreEqual<TMHWorkContext>(wcWork, LSnap.Context.WorkContext);
    Assert.IsTrue(LSnap.Sequence < 100);
    Assert.AreEqual(2, Integer(Length(LSnap.Metrics)));
    Assert.AreEqual(1, Integer(Length(LSnap.Processes)));
    Assert.AreEqual(0, Integer(Length(LSnap.Sources)), 'Статусы источников не загружаются');
  end;
  for I := 1 to High(LLoaded) do
    Assert.IsTrue(LLoaded[I].TimestampUtc > LLoaded[I - 1].TimestampUtc, 'По возрастанию времени');

  Assert.AreEqual(100, Integer(Length(LRepo.LoadSnapshotsSampled(0, FAKE_NOW + 1, 1000, wcWork))));
  Assert.AreEqual(30, Integer(Length(LRepo.LoadSnapshotsSampled(0, FAKE_NOW + 1, 1000, wcIdle))));
  Assert.AreEqual(0, Integer(Length(LRepo.LoadSnapshotsSampled(0, FAKE_NOW + 1, 1000, wcGaming))));
  Assert.AreEqual(10, Integer(Length(LRepo.LoadSnapshotsSampled(0, FAKE_NOW + 1, 1000, wcUnknown))),
    'wcUnknown — снимки без контекста');
  Assert.AreEqual(0, Integer(Length(LRepo.LoadSnapshotsSampled(0, FAKE_NOW + 1, 0, wcWork))));
  // Граница интервала: первые 50 минут — 50 снимков «работа».
  Assert.AreEqual(50, Integer(Length(LRepo.LoadSnapshotsSampled(LStart,
    LStart + 49.9 / MinsPerDay, 1000, wcWork))));
end;

procedure TStorageV2Tests.Sampled_EvenlySpreadAcrossInterval;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LLoaded: TArray<TMHSnapshot>;
  LStart: TDateTime;
  I: Integer;
begin
  LRepo := Open;
  LIntf := LRepo;
  LStart := FAKE_NOW - 2 / HoursPerDay;
  for I := 0 to 99 do
    LRepo.SaveSnapshot(Snap(I, LStart + I / MinsPerDay, I, wcIdle));
  // 100 снимков, не более 30 -> каждый 4-й: 0, 4, ..., 96 (25 снимков).
  LLoaded := LRepo.LoadSnapshotsSampled(0, FAKE_NOW + 1, 30, wcIdle);
  Assert.AreEqual(25, Integer(Length(LLoaded)));
  for I := 0 to High(LLoaded) do
  begin
    Assert.AreEqual<UInt64>(UInt64(I * 4), LLoaded[I].Sequence);
    Assert.AreEqual(LStart + I * 4 / MinsPerDay, LLoaded[I].TimestampUtc, 1 / MSecsPerDay,
      'Время читается без усечения до 32 бит');
  end;
end;

procedure TStorageV2Tests.Maintenance_RemovesOldFindings;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHFindingHistory;
  LLoaded: TArray<TMHStoredFinding>;
begin
  LRepo := Open;
  LIntf := LRepo;
  LRepo.SaveFindings([Finding('old', 50, FAKE_NOW - 10), Finding('fresh', 50, FAKE_NOW - 1)]);
  LRepo.RunMaintenance;
  LLoaded := LRepo.LoadFindings(0, FAKE_NOW + 1, 10);
  Assert.AreEqual(1, Integer(Length(LLoaded)));
  Assert.AreEqual('fresh', LLoaded[0].Finding.Key);
  Assert.IsTrue(FLogger.ContainsText('удалено находок'));
end;

procedure TStorageV2Tests.Clear_RemovesFindingsKeepsActions;
var
  LRepo: TMHSQLiteRepository;
  LIntf: IMHFindingHistory;
begin
  LRepo := Open;
  LIntf := LRepo;
  LRepo.SaveSnapshot(Snap(1, FAKE_NOW, 1, wcWork));
  LRepo.SaveFindings([Finding('k', 50, FAKE_NOW)]);
  LRepo.LogAction(Action('очистка истории', FAKE_NOW, True));
  LRepo.Clear;
  Assert.AreEqual<Int64>(0, LRepo.GetStats.SnapshotCount);
  Assert.AreEqual(0, Integer(Length(LRepo.LoadFindings(0, FAKE_NOW + 1, 10))));
  Assert.AreEqual(1, Integer(Length(LRepo.LoadActions(10))), 'Журнал действий сохраняется');
  LRepo.SaveFindings([Finding('k', 50, FAKE_NOW)]);
  Assert.AreEqual(1, LRepo.LoadFindings(0, FAKE_NOW + 1, 10)[0].Occurrences,
    'После очистки счёт повторов начинается заново');
end;

{ TStorageV2PerformanceTests }

procedure TStorageV2PerformanceTests.Sampled_100kSnapshots_IsFast;
const
  SNAPSHOTS = 100000;
  STEP_MS = 2000;
  QUERY_LIMIT_MS = 3000;
var
  LDir, LPath: string;
  LRepo: TMHSQLiteRepository;
  LIntf: IMHRepository;
  LClock: IMHClock;
  LRaw: TFDConnection;
  LManager: TMHBaselineManager;
  LProvider: IMHBaselineProvider;
  LWatch: TStopwatch;
  LLoaded: TArray<TMHSnapshot>;
  LBase: Int64;
  LQueryMs, LRebuildMs: Int64;
begin
  LDir := NewTempDir;
  try
    LPath := TPath.Combine(LDir, 'perf.db');
    LClock := TFakeClock.Create(FAKE_NOW);
    // Схема создаётся репозиторием, данные заполняются одним пакетом SQL.
    TMHSQLiteRepository.Create(LPath, TMHStorageOptions.Default, LClock,
      TMHNullLogger.Create).Free;
    LBase := MHUtcToUnixMs(FAKE_NOW) - Int64(SNAPSHOTS) * STEP_MS;
    LRaw := RawConnection(LPath);
    try
      LRaw.StartTransaction;
      LRaw.ExecSQL('INSERT INTO snapshots(seq, ts, context) ' +
        'WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c WHERE i < ' +
        IntToStr(SNAPSHOTS) + ') SELECT i, ' + IntToStr(LBase) + ' + i * ' + IntToStr(STEP_MS) +
        ', CASE i % 3 WHEN 0 THEN ''idle'' WHEN 1 THEN ''work'' ELSE ''gaming'' END FROM c');
      LRaw.ExecSQL('INSERT INTO metrics(snapshot_id, kind, value) ' +
        'SELECT id, ''cpuPercent'', seq % 100 FROM snapshots');
      LRaw.ExecSQL('INSERT INTO metrics(snapshot_id, kind, value) ' +
        'SELECT id, ''memoryLoadPercent'', 40 + seq % 20 FROM snapshots');
      LRaw.ExecSQL('INSERT INTO process_samples(snapshot_id, pid, create_time, parent_pid, ' +
        'name, image_path, access, cpu, working_set, private_bytes, thread_count, source_id) ' +
        'SELECT s.id, p.i, 1000 + p.i, 4, ''p'' || p.i || ''.exe'', ''C:\Apps\p'' || p.i || ''.exe'', ' +
        '''full'', (s.seq + p.i) % 50, 1000000 * p.i, NULL, 3, ''processes'' FROM snapshots s ' +
        'CROSS JOIN (WITH RECURSIVE q(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM q WHERE i < 10) ' +
        'SELECT i FROM q) p');
      LRaw.Commit;
    finally
      LRaw.Free;
    end;

    LRepo := TMHSQLiteRepository.Create(LPath, TMHStorageOptions.Default, LClock,
      TMHNullLogger.Create);
    LIntf := LRepo;
    Assert.AreEqual<Int64>(SNAPSHOTS, LRepo.GetStats.SnapshotCount);

    LWatch := TStopwatch.StartNew;
    LLoaded := LRepo.LoadSnapshotsSampled(FAKE_NOW - 3, FAKE_NOW, 5000, wcWork);
    LWatch.Stop;
    LQueryMs := LWatch.ElapsedMilliseconds;
    Assert.IsTrue(Length(LLoaded) <= 5000);
    Assert.IsTrue(Length(LLoaded) > 4000, Format('Загружено %d', [Length(LLoaded)]));
    Assert.AreEqual(10, Integer(Length(LLoaded[0].Processes)));

    LManager := TMHBaselineManager.Create(LRepo, LClock, TMHNullLogger.Create);
    LProvider := LManager;
    LWatch := TStopwatch.StartNew;
    LManager.Rebuild;
    LWatch.Stop;
    LRebuildMs := LWatch.ElapsedMilliseconds;
    Assert.IsTrue(LManager.BaselineFor(wcWork).SampleCount > 4000);
    Assert.AreEqual(10, Integer(Length(LManager.BaselineFor(wcGaming).Processes)));

    System.Writeln(Format('  [perf] LoadSnapshotsSampled 100k -> %d снимков: %d мс; ' +
      'Rebuild (3 контекста x 5000): %d мс', [Length(LLoaded), LQueryMs, LRebuildMs]));
    Assert.IsTrue(LQueryMs < QUERY_LIMIT_MS,
      Format('Прореженная выборка заняла %d мс', [LQueryMs]));
  finally
    LProvider := nil;
    LIntf := nil; // закрыть базу до удаления каталога, в том числе при ошибке
    try
      TDirectory.Delete(LDir, True);
    except
    end;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TStorageV2Tests);
  TDUnitX.RegisterTestFixture(TStorageV2PerformanceTests);

end.
