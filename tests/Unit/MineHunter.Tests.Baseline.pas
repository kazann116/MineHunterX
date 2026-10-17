unit MineHunter.Tests.Baseline;

{
  Тесты профиля нормы: построение профиля на эталонных данных, менеджер
  профилей с тестовым хранилищем (в том числе многопоточность) и сравнение
  текущих значений с нормой.
}

interface

uses
  System.SysUtils, System.Classes, System.SyncObjs, System.Generics.Collections,
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Analysis.Baseline,
  MineHunter.Tests.Fakes;

type
  /// Хранилище профилей в памяти с управляемыми сбоями.
  TFakeBaselineStore = class(TInterfacedObject, IMHBaselineStore)
  private
    FLock: TCriticalSection;
    FSnapshots: array[TMHWorkContext] of TArray<TMHSnapshot>;
    FSaved: TList<TMHBaseline>;
    FStored: TArray<TMHBaseline>;
    FFailSave: Boolean;
    FFailLoadBaselines: Boolean;
    FLoadCalls: Integer;
    FMinFromUtc, FLastToUtc: TDateTime;
    FLastMaxCount: Integer;
    FOnLoad: TProc;
  public
    constructor Create;
    destructor Destroy; override;
    procedure SaveBaseline(const ABaseline: TMHBaseline);
    function LoadBaselines: TArray<TMHBaseline>;
    function LoadSnapshotsSampled(AFromUtc, AToUtc: TDateTime; AMaxCount: Integer;
      AContext: TMHWorkContext): TArray<TMHSnapshot>;
    procedure SetSnapshots(AContext: TMHWorkContext; const ASnapshots: TArray<TMHSnapshot>);
    function SavedCount: Integer;
    property Stored: TArray<TMHBaseline> read FStored write FStored;
    property FailSave: Boolean read FFailSave write FFailSave;
    property FailLoadBaselines: Boolean read FFailLoadBaselines write FFailLoadBaselines;
    property LoadCalls: Integer read FLoadCalls;
    /// Наименьшая начальная граница среди всех запросов выборки.
    property MinFromUtc: TDateTime read FMinFromUtc;
    property LastToUtc: TDateTime read FLastToUtc;
    property LastMaxCount: Integer read FLastMaxCount;
    /// Вызывается внутри LoadSnapshotsSampled (имитация долгого запроса).
    property OnLoad: TProc read FOnLoad write FOnLoad;
  end;

  [TestFixture]
  [Category('Unit')]
  TBaselineBuilderTests = class
  public
    [Test] procedure Build_SystemStats_ReferenceValues;
    [Test] procedure Build_NoData_IsSkipped;
    [Test] procedure Build_Programs_PresenceAndInstanceSum;
    [Test] procedure Build_MaxProcesses_KeepsMostPresent;
    [Test] procedure Build_IsDeterministic;
    [Test] procedure Build_Empty_HasContextAndNoSamples;
    [Test] procedure Accumulator_InPortions_EqualsBuild;
    [Test] procedure Accumulator_Empty_HasContextAndNoSamples;
  end;

  [TestFixture]
  [Category('Unit')]
  TBaselineManagerTests = class
  private
    FStore: TFakeBaselineStore;
    FStoreIntf: IMHBaselineStore;
    FClock: TFakeClock;
    FClockIntf: IMHClock;
    FLogger: TRecordingLogger;
    FLoggerIntf: IMHLogger;
    FManager: TMHBaselineManager;
    FManagerIntf: IMHBaselineProvider;
    FProbeThreads: TObjectList<TThread>;
    FProbeOk: Boolean;
    FProbeRuns: Integer;
    /// Проверяет из другого потока, что BaselineFor не ждёт идущую перестройку.
    procedure ProbeReaderNotBlocked;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure BaselineFor_BeforeRebuild_IsEmptyWithContext;
    [Test] procedure Rebuild_BuildsSavesAndSwaps;
    [Test] procedure Rebuild_ContextWithoutData_KeepsOldProfile;
    [Test] procedure Rebuild_Failure_KeepsOldProfileAndLogs;
    [Test] procedure Rebuild_PreservesCreatedUtc;
    [Test] procedure LoadFromStore_RestoresProfiles;
    [Test] procedure LoadFromStore_Failure_IsLogged;
    [Test] procedure Rebuild_DoesNotBlockReadersWhileQuerying;
    [Test] procedure ConcurrentBaselineForDuringRebuild;
    [Test] procedure Rebuild_InChunks_CoversPeriodWithoutDuplicates;
    [Test] procedure Rebuild_InChunks_RespectsSampleLimit;
  end;

  [TestFixture]
  [Category('Unit')]
  TBaselineComparisonTests = class
  public
    [Test] procedure StatsFromSeries_SkipsNoData;
    [Test] procedure Compare_BoundaryBelowThreshold_IsWithinNorm;
    [Test] procedure Compare_BoundaryAtThreshold_IsAboveNorm;
    [Test] procedure Compare_BelowNorm;
    [Test] procedure Compare_NoBaseline;
    [Test] procedure Compare_LittleData;
    [Test] procedure Compare_SmallAbsoluteDifference_IsWithinNorm;
    [Test] procedure Compare_ZeroBaseline_NoDivisionByZero;
    [Test] procedure ComparePeriods_ReturnsSystemMetrics;
    [Test] procedure CompareProcesses_RisesAndNewPrograms;
  end;

implementation

uses
  System.Math, System.DateUtils, System.Diagnostics,
  MineHunter.Core.Serialization;

function Proc(APid: Cardinal; const AName, APath: string; ACpu: Double;
  ATime: TDateTime): TMHProcessInfo;
begin
  Result := TMHProcessInfo.Create(TMHProcessId.Create(APid, APid * 10), AName, ATime);
  Result.ImagePath := APath;
  Result.Cpu := TMHMetric.Available(mkCpuPercent, ACpu, ATime);
  Result.WorkingSet := TMHMetric.Available(mkWorkingSetBytes, 1000 * APid, ATime);
end;

/// Пять снимков с эталонными значениями CPU 10..50.
function ReferenceSnapshots: TArray<TMHSnapshot>;
const
  CPU: array[0..4] of Double = (30, 10, 50, 20, 40);
var
  I: Integer;
  LTime: TDateTime;
begin
  SetLength(Result, 5);
  for I := 0 to 4 do
  begin
    LTime := FAKE_NOW - (5 - I) / MinsPerDay;
    Result[I] := TMHSnapshot.Create(I, LTime);
    Result[I].Metrics := [TMHMetric.Available(mkCpuPercent, CPU[I], LTime),
      TMHMetric.NoData(mkDiskActivePercent, LTime)];
    if I = 2 then
      Result[I].Metrics := Result[I].Metrics + [TMHMetric.NoData(mkMemoryLoadPercent, LTime)]
    else
      Result[I].Metrics := Result[I].Metrics +
        [TMHMetric.Available(mkMemoryLoadPercent, 40 + I, LTime)];
    // a.exe присутствует всегда (в первом снимке — два экземпляра),
    // b.exe (путь неизвестен) — в двух снимках из пяти.
    Result[I].Processes := [Proc(100, 'a.exe', 'C:\A\a.exe', I + 1, LTime)];
    if I = 0 then
      Result[I].Processes := Result[I].Processes + [Proc(101, 'a.exe', 'C:\A\a.exe', 2, LTime)];
    if I in [1, 3] then
      Result[I].Processes := Result[I].Processes + [Proc(200, 'B.exe', '', 7, LTime)];
  end;
end;

function SnapshotsFor(ACount: Integer; ACpu: Double): TArray<TMHSnapshot>;
var
  I: Integer;
  LTime: TDateTime;
begin
  SetLength(Result, ACount);
  for I := 0 to ACount - 1 do
  begin
    LTime := FAKE_NOW - (ACount - I) / MinsPerDay;
    Result[I] := TMHSnapshot.Create(I, LTime);
    Result[I].Metrics := [TMHMetric.Available(mkCpuPercent, ACpu, LTime)];
    Result[I].Processes := [Proc(100, 'a.exe', 'C:\A\a.exe', ACpu / 2, LTime)];
  end;
end;

function Stat(AMedian, AP95: Double; ACount: Integer): TMHStat;
begin
  Result := Default(TMHStat);
  Result.SampleCount := ACount;
  Result.Mean := AMedian;
  Result.Median := AMedian;
  Result.P95 := AP95;
  Result.Max := AP95;
end;

function ProcBaseline(const AKey: string; AP95: Double): TMHProcessBaseline;
begin
  Result := Default(TMHProcessBaseline);
  Result.Key := AKey;
  Result.Name := AKey;
  Result.Cpu := Stat(AP95 / 2, AP95, 100);
  Result.PresenceRatio := 1;
end;

{ TFakeBaselineStore }

constructor TFakeBaselineStore.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FSaved := TList<TMHBaseline>.Create;
end;

destructor TFakeBaselineStore.Destroy;
begin
  FSaved.Free;
  FLock.Free;
  inherited;
end;

procedure TFakeBaselineStore.SaveBaseline(const ABaseline: TMHBaseline);
begin
  if FFailSave then
    raise EMHError.Create('simulated save failure');
  FLock.Enter;
  try
    FSaved.Add(ABaseline);
  finally
    FLock.Leave;
  end;
end;

function TFakeBaselineStore.LoadBaselines: TArray<TMHBaseline>;
begin
  if FFailLoadBaselines then
    raise EMHError.Create('simulated load failure');
  Result := FStored;
end;

function TFakeBaselineStore.LoadSnapshotsSampled(AFromUtc, AToUtc: TDateTime;
  AMaxCount: Integer; AContext: TMHWorkContext): TArray<TMHSnapshot>;
var
  LSnapshot: TMHSnapshot;
begin
  FLock.Enter;
  try
    Inc(FLoadCalls);
    if (FLoadCalls = 1) or (AFromUtc < FMinFromUtc) then
      FMinFromUtc := AFromUtc;
    FLastToUtc := AToUtc;
    FLastMaxCount := AMaxCount;
    // Как у хранилища: снимки контекста из [AFromUtc; AToUtc], не больше AMaxCount.
    Result := nil;
    for LSnapshot in FSnapshots[AContext] do
      if (LSnapshot.TimestampUtc >= AFromUtc) and (LSnapshot.TimestampUtc <= AToUtc) and
         (Length(Result) < AMaxCount) then
        Result := Result + [LSnapshot];
  finally
    FLock.Leave;
  end;
  if Assigned(FOnLoad) then
    FOnLoad();
end;

procedure TFakeBaselineStore.SetSnapshots(AContext: TMHWorkContext;
  const ASnapshots: TArray<TMHSnapshot>);
begin
  FLock.Enter;
  try
    FSnapshots[AContext] := ASnapshots;
  finally
    FLock.Leave;
  end;
end;

function TFakeBaselineStore.SavedCount: Integer;
begin
  FLock.Enter;
  try
    Result := FSaved.Count;
  finally
    FLock.Leave;
  end;
end;

{ TBaselineBuilderTests }

procedure TBaselineBuilderTests.Build_SystemStats_ReferenceValues;
var
  LBaseline: TMHBaseline;
begin
  LBaseline := TMHBaselineBuilder.Build(wcWork, ReferenceSnapshots, FAKE_NOW);
  Assert.AreEqual<TMHWorkContext>(wcWork, LBaseline.Context);
  Assert.AreEqual(5, LBaseline.SampleCount);
  Assert.AreEqual(5, LBaseline.SystemCpu.SampleCount);
  Assert.AreEqual(30.0, LBaseline.SystemCpu.Mean, 1e-9);
  Assert.AreEqual(30.0, LBaseline.SystemCpu.Median, 1e-9);
  // p95: позиция 0.95 * 4 = 3.8 -> 40 + (50 - 40) * 0.8 = 48.
  Assert.AreEqual(48.0, LBaseline.SystemCpu.P95, 1e-9);
  Assert.AreEqual(50.0, LBaseline.SystemCpu.Max, 1e-9);
  Assert.AreEqual(FAKE_NOW - 5 / MinsPerDay, LBaseline.PeriodFromUtc, 1e-9);
  Assert.AreEqual(FAKE_NOW - 1 / MinsPerDay, LBaseline.PeriodToUtc, 1e-9);
  Assert.AreEqual(FAKE_NOW, LBaseline.CreatedUtc, 0);
  Assert.AreEqual(FAKE_NOW, LBaseline.UpdatedUtc, 0);
end;

procedure TBaselineBuilderTests.Build_NoData_IsSkipped;
var
  LBaseline: TMHBaseline;
begin
  LBaseline := TMHBaselineBuilder.Build(wcWork, ReferenceSnapshots, FAKE_NOW);
  // Память: значения 40, 41, 43, 44 (третий снимок — «нет данных»).
  Assert.AreEqual(4, LBaseline.MemoryLoad.SampleCount);
  Assert.AreEqual(42.0, LBaseline.MemoryLoad.Median, 1e-9);
  Assert.AreEqual(0, LBaseline.DiskActive.SampleCount, 'Только «нет данных» — статистики нет');
  Assert.IsFalse(LBaseline.DiskActive.HasData);
end;

procedure TBaselineBuilderTests.Build_Programs_PresenceAndInstanceSum;
var
  LBaseline: TMHBaseline;
  LA, LB: TMHProcessBaseline;
begin
  LBaseline := TMHBaselineBuilder.Build(wcWork, ReferenceSnapshots, FAKE_NOW);
  Assert.AreEqual(2, Integer(Length(LBaseline.Processes)));
  Assert.AreEqual('b.exe', LBaseline.Processes[0].Key, 'Упорядочено по ключу');
  Assert.AreEqual('c:\a\a.exe', LBaseline.Processes[1].Key);
  Assert.IsTrue(LBaseline.FindProcess('c:\a\a.exe', LA));
  Assert.IsTrue(LBaseline.FindProcess('b.exe', LB));
  Assert.AreEqual(1.0, LA.PresenceRatio, 1e-9);
  Assert.AreEqual(0.4, LB.PresenceRatio, 1e-9);
  // a.exe: снимок 0 — 1 + 2 = 3 (два экземпляра), далее 2, 3, 4, 5.
  Assert.AreEqual(5, LA.Cpu.SampleCount);
  Assert.AreEqual(3.0, LA.Cpu.Median, 1e-9);
  Assert.AreEqual(4.8, LA.Cpu.P95, 1e-9);
  Assert.AreEqual(201000.0, LA.WorkingSet.Max, 1e-9, 'Рабочий набор экземпляров суммируется');
  Assert.AreEqual('B.exe', LB.Name);
  Assert.AreEqual(2, LB.Cpu.SampleCount);
  Assert.AreEqual(7.0, LB.Cpu.Median, 1e-9);
end;

procedure TBaselineBuilderTests.Build_MaxProcesses_KeepsMostPresent;
var
  LBaseline: TMHBaseline;
begin
  LBaseline := TMHBaselineBuilder.Build(wcWork, ReferenceSnapshots, FAKE_NOW, 1);
  Assert.AreEqual(1, Integer(Length(LBaseline.Processes)));
  Assert.AreEqual('c:\a\a.exe', LBaseline.Processes[0].Key);
  LBaseline := TMHBaselineBuilder.Build(wcWork, ReferenceSnapshots, FAKE_NOW, 0);
  Assert.AreEqual(0, Integer(Length(LBaseline.Processes)));
end;

procedure TBaselineBuilderTests.Build_IsDeterministic;
var
  LSnapshots, LReversed: TArray<TMHSnapshot>;
  I, J: Integer;
  LFirst, LSecond: string;
begin
  LSnapshots := ReferenceSnapshots;
  // Тот же набор, но процессы в каждом снимке — в обратном порядке.
  LReversed := ReferenceSnapshots;
  for I := 0 to High(LReversed) do
  begin
    LReversed[I].Processes := nil;
    for J := High(LSnapshots[I].Processes) downto 0 do
      LReversed[I].Processes := LReversed[I].Processes + [LSnapshots[I].Processes[J]];
  end;
  LFirst := TMHJson.BaselineToString(TMHBaselineBuilder.Build(wcIdle, LSnapshots, FAKE_NOW));
  LSecond := TMHJson.BaselineToString(TMHBaselineBuilder.Build(wcIdle, LReversed, FAKE_NOW));
  Assert.AreEqual(LFirst, LSecond);
  Assert.AreEqual(LFirst,
    TMHJson.BaselineToString(TMHBaselineBuilder.Build(wcIdle, LSnapshots, FAKE_NOW)));
end;

procedure TBaselineBuilderTests.Build_Empty_HasContextAndNoSamples;
var
  LBaseline: TMHBaseline;
begin
  LBaseline := TMHBaselineBuilder.Build(wcGaming, nil, FAKE_NOW);
  Assert.AreEqual<TMHWorkContext>(wcGaming, LBaseline.Context);
  Assert.AreEqual(0, LBaseline.SampleCount);
  Assert.IsFalse(LBaseline.SystemCpu.HasData);
  Assert.AreEqual(0, Integer(Length(LBaseline.Processes)));
end;

procedure TBaselineBuilderTests.Accumulator_InPortions_EqualsBuild;
var
  LSnapshots: TArray<TMHSnapshot>;
  LAccumulator: TMHBaselineAccumulator;
  LExpected, LActual: string;
  I: Integer;
begin
  LSnapshots := ReferenceSnapshots;
  LExpected := TMHJson.BaselineToString(TMHBaselineBuilder.Build(wcWork, LSnapshots, FAKE_NOW));
  LAccumulator := TMHBaselineAccumulator.Create(wcWork, FAKE_NOW);
  try
    // Первая порция — один снимок, остальные — по одному через Add(снимок).
    LAccumulator.Add(Copy(LSnapshots, 0, 1));
    for I := 1 to High(LSnapshots) do
      LAccumulator.Add(LSnapshots[I]);
    Assert.AreEqual(Integer(Length(LSnapshots)), LAccumulator.Count);
    LActual := TMHJson.BaselineToString(LAccumulator.Finish);
  finally
    LAccumulator.Free;
  end;
  Assert.AreEqual(LExpected, LActual);
end;

procedure TBaselineBuilderTests.Accumulator_Empty_HasContextAndNoSamples;
var
  LAccumulator: TMHBaselineAccumulator;
  LBaseline: TMHBaseline;
begin
  LAccumulator := TMHBaselineAccumulator.Create(wcIdle, FAKE_NOW);
  try
    LAccumulator.Add(TArray<TMHSnapshot>(nil));
    LBaseline := LAccumulator.Finish;
  finally
    LAccumulator.Free;
  end;
  Assert.AreEqual<TMHWorkContext>(wcIdle, LBaseline.Context);
  Assert.AreEqual(0, LBaseline.SampleCount);
  Assert.IsFalse(LBaseline.SystemCpu.HasData);
  Assert.AreEqual(FAKE_NOW, LBaseline.UpdatedUtc, 0);
end;

/// ACount снимков, равномерно распределённых по последним ADays дням
/// (часть точек попадает точно на границы интервалов перестройки).
function SpreadSnapshots(ACount: Integer; ADays: Double): TArray<TMHSnapshot>;
var
  I: Integer;
  LTime: TDateTime;
begin
  SetLength(Result, ACount);
  for I := 0 to ACount - 1 do
  begin
    LTime := FAKE_NOW - ADays + I * ADays / ACount;
    Result[I] := TMHSnapshot.Create(I, LTime);
    Result[I].Metrics := [TMHMetric.Available(mkCpuPercent, I mod 10, LTime)];
    Result[I].Processes := [Proc(100, 'a.exe', 'C:\A.exe', 1, LTime)];
  end;
end;

{ TBaselineManagerTests }

procedure TBaselineManagerTests.Setup;
begin
  FStore := TFakeBaselineStore.Create;
  FStoreIntf := FStore;
  FClock := TFakeClock.Create(FAKE_NOW);
  FClockIntf := FClock;
  FLogger := TRecordingLogger.Create;
  FLoggerIntf := FLogger;
  FManager := TMHBaselineManager.Create(FStoreIntf, FClockIntf, FLoggerIntf);
  FManagerIntf := FManager;
  FProbeThreads := TObjectList<TThread>.Create(True);
  FProbeOk := True;
  FProbeRuns := 0;
end;

procedure TBaselineManagerTests.TearDown;
var
  LThread: TThread;
begin
  for LThread in FProbeThreads do
    LThread.WaitFor;
  FProbeThreads.Free;
  FManagerIntf := nil;
  FStoreIntf := nil;
  FLoggerIntf := nil;
  FClockIntf := nil;
end;

procedure TBaselineManagerTests.ProbeReaderNotBlocked;
var
  LThread: TThread;
  LWatch: TStopwatch;
  LProvider: IMHBaselineProvider;
begin
  LProvider := FManagerIntf;
  LThread := TThread.CreateAnonymousThread(
    procedure
    begin
      LProvider.BaselineFor(wcWork);
    end);
  LThread.FreeOnTerminate := False;
  FProbeThreads.Add(LThread);
  LThread.Start;
  LWatch := TStopwatch.StartNew;
  while not LThread.Finished and (LWatch.ElapsedMilliseconds < 2000) do
    Sleep(1);
  Inc(FProbeRuns);
  if not LThread.Finished then
    FProbeOk := False;
end;

procedure TBaselineManagerTests.BaselineFor_BeforeRebuild_IsEmptyWithContext;
var
  LContext: TMHWorkContext;
  LBaseline: TMHBaseline;
begin
  for LContext := Low(TMHWorkContext) to High(TMHWorkContext) do
  begin
    LBaseline := FManager.BaselineFor(LContext);
    Assert.AreEqual<TMHWorkContext>(LContext, LBaseline.Context);
    Assert.AreEqual(0, LBaseline.SampleCount);
    Assert.IsFalse(LBaseline.IsEstablished(1));
  end;
  Assert.AreEqual(0.0, FManager.LastRebuildUtc, 0);
end;

procedure TBaselineManagerTests.Rebuild_BuildsSavesAndSwaps;
var
  LWork: TMHBaseline;
begin
  FStore.SetSnapshots(wcWork, SnapshotsFor(20, 30));
  FStore.SetSnapshots(wcIdle, SnapshotsFor(15, 2));
  FManager.Rebuild;
  LWork := FManager.BaselineFor(wcWork);
  Assert.AreEqual(20, LWork.SampleCount);
  Assert.AreEqual(30.0, LWork.SystemCpu.Median, 1e-9);
  Assert.AreEqual(15, FManager.BaselineFor(wcIdle).SampleCount);
  Assert.AreEqual(0, FManager.BaselineFor(wcGaming).SampleCount, 'Нет данных — профиль пуст');
  Assert.AreEqual<TMHWorkContext>(wcGaming, FManager.BaselineFor(wcGaming).Context);
  Assert.AreEqual(2, FStore.SavedCount, 'Сохраняются только построенные профили');
  Assert.AreEqual(3 * TMHBaselineManager.RebuildChunks, FStore.LoadCalls, 'Период читается порциями');
  Assert.AreEqual(FAKE_NOW - 3, FStore.MinFromUtc, 1e-9, 'Период обучения — 3 дня');
  Assert.AreEqual(FAKE_NOW, FStore.LastToUtc, 1e-9);
  Assert.AreEqual(5000, FStore.LastMaxCount, 'Неиспользованная квота переходит к последнему интервалу');
  Assert.AreEqual(FAKE_NOW, FManager.LastRebuildUtc, 0);
end;

procedure TBaselineManagerTests.Rebuild_ContextWithoutData_KeepsOldProfile;
begin
  FStore.SetSnapshots(wcWork, SnapshotsFor(20, 30));
  FManager.Rebuild;
  FStore.SetSnapshots(wcWork, nil);
  FClock.AdvanceMs(60 * 60 * 1000);
  FManager.Rebuild;
  Assert.AreEqual(20, FManager.BaselineFor(wcWork).SampleCount);
  Assert.AreEqual(FClock.NowUtc, FManager.LastRebuildUtc, 0);
end;

procedure TBaselineManagerTests.Rebuild_Failure_KeepsOldProfileAndLogs;
var
  LFirstRebuild: TDateTime;
begin
  FStore.SetSnapshots(wcWork, SnapshotsFor(20, 30));
  FManager.Rebuild;
  LFirstRebuild := FManager.LastRebuildUtc;

  FStore.SetSnapshots(wcWork, SnapshotsFor(40, 80));
  FStore.FailSave := True;
  FClock.AdvanceMs(60 * 60 * 1000);
  FManager.Rebuild;
  Assert.AreEqual(20, FManager.BaselineFor(wcWork).SampleCount, 'Прежний профиль сохранён');
  Assert.AreEqual(30.0, FManager.BaselineFor(wcWork).SystemCpu.Median, 1e-9);
  Assert.IsTrue(FLogger.CountOf(llError) > 0);
  Assert.IsTrue(FLogger.ContainsText('simulated save failure'));
  Assert.AreEqual(LFirstRebuild, FManager.LastRebuildUtc, 0, 'Неудачная перестройка не учитывается');

  FStore.FailSave := False;
  FManager.Rebuild;
  Assert.AreEqual(40, FManager.BaselineFor(wcWork).SampleCount);
end;

procedure TBaselineManagerTests.Rebuild_PreservesCreatedUtc;
var
  LCreated: TDateTime;
begin
  FStore.SetSnapshots(wcWork, SnapshotsFor(20, 30));
  FManager.Rebuild;
  LCreated := FManager.BaselineFor(wcWork).CreatedUtc;
  FClock.AdvanceMs(60 * 60 * 1000);
  FManager.Rebuild;
  Assert.AreEqual(LCreated, FManager.BaselineFor(wcWork).CreatedUtc, 0);
  Assert.AreEqual(FClock.NowUtc, FManager.BaselineFor(wcWork).UpdatedUtc, 0);
end;

procedure TBaselineManagerTests.LoadFromStore_RestoresProfiles;
var
  LStored: TMHBaseline;
begin
  LStored := TMHBaselineBuilder.Build(wcGaming, SnapshotsFor(12, 60), FAKE_NOW - 1);
  FStore.Stored := [LStored];
  FManager.LoadFromStore;
  Assert.AreEqual(12, FManager.BaselineFor(wcGaming).SampleCount);
  Assert.AreEqual(60.0, FManager.BaselineFor(wcGaming).SystemCpu.Median, 1e-9);
  Assert.AreEqual(0, FManager.BaselineFor(wcWork).SampleCount);
end;

procedure TBaselineManagerTests.LoadFromStore_Failure_IsLogged;
begin
  FStore.FailLoadBaselines := True;
  FManager.LoadFromStore;
  Assert.IsTrue(FLogger.ContainsText('simulated load failure'));
  Assert.AreEqual(0, FManager.BaselineFor(wcWork).SampleCount);
end;

procedure TBaselineManagerTests.Rebuild_DoesNotBlockReadersWhileQuerying;
begin
  FStore.SetSnapshots(wcWork, SnapshotsFor(20, 30));
  FStore.OnLoad := ProbeReaderNotBlocked;
  FManager.Rebuild;
  FStore.OnLoad := nil;
  Assert.AreEqual(3 * TMHBaselineManager.RebuildChunks, FProbeRuns);
  Assert.IsTrue(FProbeOk, 'BaselineFor не должен ждать запроса к хранилищу');
end;

procedure TBaselineManagerTests.Rebuild_InChunks_CoversPeriodWithoutDuplicates;
var
  LWork: TMHBaseline;
begin
  FStore.SetSnapshots(wcWork, SpreadSnapshots(100, 3));
  FManager.Rebuild;
  LWork := FManager.BaselineFor(wcWork);
  Assert.AreEqual(100, LWork.SampleCount, 'Каждый снимок учтён ровно один раз');
  Assert.AreEqual(FAKE_NOW - 3, LWork.PeriodFromUtc, 1e-9);
  Assert.AreEqual(1.0, LWork.Processes[0].PresenceRatio, 1e-9);
end;

procedure TBaselineManagerTests.Rebuild_InChunks_RespectsSampleLimit;
var
  LManager: TMHBaselineManager;
  LManagerIntf: IMHBaselineProvider;
  LWork: TMHBaseline;
begin
  FStore.SetSnapshots(wcWork, SpreadSnapshots(1000, 3));
  LManager := TMHBaselineManager.Create(FStoreIntf, FClockIntf, FLoggerIntf, 3, 95);
  LManagerIntf := LManager;
  LManager.Rebuild;
  LWork := LManager.BaselineFor(wcWork);
  Assert.IsTrue(LWork.SampleCount <= 95, Format('Снимков: %d (лимит 95)', [LWork.SampleCount]));
  Assert.IsTrue(LWork.SampleCount >= 90, Format('Лимит должен использоваться: %d', [LWork.SampleCount]));
  Assert.IsTrue(LWork.PeriodFromUtc < FAKE_NOW - 2.9, 'Выборка охватывает начало периода');
  Assert.IsTrue(LWork.PeriodToUtc > FAKE_NOW - 0.3, 'Выборка охватывает конец периода');
end;

procedure TBaselineManagerTests.ConcurrentBaselineForDuringRebuild;
const
  REBUILDS = 30;
var
  LWriter: TThread;
  LError: string;
  LReads, LBadReads: Integer;
  LBaseline: TMHBaseline;
  LManager: IMHBaselineProvider;
  LRaw: TMHBaselineManager;
begin
  FStore.SetSnapshots(wcWork, SnapshotsFor(50, 30));
  FStore.SetSnapshots(wcIdle, SnapshotsFor(25, 3));
  LManager := FManagerIntf;
  LRaw := FManager;
  LError := '';
  LWriter := TThread.CreateAnonymousThread(
    procedure
    var
      I: Integer;
    begin
      try
        for I := 1 to REBUILDS do
          LRaw.Rebuild;
      except
        on E: Exception do
          LError := E.Message;
      end;
    end);
  LWriter.FreeOnTerminate := False;
  LWriter.Start;
  LReads := 0;
  LBadReads := 0;
  try
    while not LWriter.Finished do
    begin
      LBaseline := LManager.BaselineFor(wcWork);
      // Профиль либо ещё пуст, либо целиком построен — промежуточных состояний нет.
      if (LBaseline.Context <> wcWork) or not (LBaseline.SampleCount in [0, 50]) or
         ((LBaseline.SampleCount = 50) and (Length(LBaseline.Processes) <> 1)) then
        Inc(LBadReads);
      Inc(LReads);
    end;
    LWriter.WaitFor;
  finally
    LWriter.Free;
  end;
  Assert.AreEqual('', LError);
  Assert.AreEqual(0, LBadReads);
  Assert.IsTrue(LReads > 0);
  Assert.AreEqual(50, LManager.BaselineFor(wcWork).SampleCount);
  Assert.AreEqual(25, LManager.BaselineFor(wcIdle).SampleCount);
end;

{ TBaselineComparisonTests }

procedure TBaselineComparisonTests.StatsFromSeries_SkipsNoData;
var
  LStat: TMHStat;
begin
  LStat := MHStatsFromSeries([TMHMetric.Available(mkCpuPercent, 1, FAKE_NOW),
    TMHMetric.NoData(mkCpuPercent, FAKE_NOW), TMHMetric.Available(mkCpuPercent, 3, FAKE_NOW)]);
  Assert.AreEqual(2, LStat.SampleCount);
  Assert.AreEqual(2.0, LStat.Median, 1e-9);
  Assert.AreEqual(0, MHStatsFromSeries(nil).SampleCount);
end;

procedure TBaselineComparisonTests.Compare_BoundaryBelowThreshold_IsWithinNorm;
var
  LResult: TMHMetricComparison;
begin
  // 45.96 против 40 — +14.9%.
  LResult := MHCompareStats(mkCpuPercent, Stat(45.96, 50, 100), Stat(40, 50, 100));
  Assert.AreEqual(14.9, LResult.MedianDeltaPercent, 1e-9);
  Assert.AreEqual('в пределах нормы', LResult.Verdict);
  Assert.IsTrue(LResult.HasBaseline);
end;

procedure TBaselineComparisonTests.Compare_BoundaryAtThreshold_IsAboveNorm;
var
  LResult: TMHMetricComparison;
begin
  LResult := MHCompareStats(mkCpuPercent, Stat(46, 60, 100), Stat(40, 50, 100));
  Assert.AreEqual(15.0, LResult.MedianDeltaPercent, 1e-9);
  Assert.AreEqual(20.0, LResult.P95DeltaPercent, 1e-9);
  Assert.AreEqual('выше нормы на 15%', LResult.Verdict);
  LResult := MHCompareStats(mkCpuPercent, Stat(54, 60, 100), Stat(40, 50, 100));
  Assert.AreEqual('выше нормы на 35%', LResult.Verdict);
end;

procedure TBaselineComparisonTests.Compare_BelowNorm;
begin
  Assert.AreEqual('ниже нормы на 15%',
    MHCompareStats(mkMemoryLoadPercent, Stat(34, 40, 50), Stat(40, 50, 50)).Verdict);
  Assert.AreEqual('в пределах нормы',
    MHCompareStats(mkMemoryLoadPercent, Stat(34.04, 40, 50), Stat(40, 50, 50)).Verdict);
end;

procedure TBaselineComparisonTests.Compare_NoBaseline;
var
  LResult: TMHMetricComparison;
begin
  LResult := MHCompareStats(mkCpuPercent, Stat(40, 50, 100), Default(TMHStat));
  Assert.IsFalse(LResult.HasBaseline);
  Assert.AreEqual('нет данных о норме', LResult.Verdict);
end;

procedure TBaselineComparisonTests.Compare_LittleData;
begin
  Assert.AreEqual('мало данных для сравнения',
    MHCompareStats(mkCpuPercent, Stat(90, 90, 9), Stat(40, 50, 100)).Verdict);
  Assert.AreEqual('мало данных для сравнения',
    MHCompareStats(mkCpuPercent, Stat(90, 90, 100), Stat(40, 50, 9)).Verdict);
  Assert.AreEqual('мало данных для сравнения',
    MHCompareStats(mkCpuPercent, Default(TMHStat), Stat(40, 50, 100)).Verdict);
  Assert.AreEqual('выше нормы на 125%',
    MHCompareStats(mkCpuPercent, Stat(90, 90, 10), Stat(40, 50, 10)).Verdict,
    'Ровно 10 значений достаточно');
end;

procedure TBaselineComparisonTests.Compare_SmallAbsoluteDifference_IsWithinNorm;
var
  LResult: TMHMetricComparison;
begin
  // 1% против 1.5% CPU — +50% относительно, но всего 0.5 п.п.
  LResult := MHCompareStats(mkCpuPercent, Stat(1.5, 2, 100), Stat(1, 2, 100));
  Assert.AreEqual(50.0, LResult.MedianDeltaPercent, 1e-9);
  Assert.AreEqual('в пределах нормы', LResult.Verdict);
end;

procedure TBaselineComparisonTests.Compare_ZeroBaseline_NoDivisionByZero;
var
  LResult: TMHMetricComparison;
begin
  LResult := MHCompareStats(mkWorkingSetBytes, Stat(10, 10, 100), Stat(0, 0, 100));
  Assert.AreEqual(1000.0, LResult.MedianDeltaPercent, 1e-9);
  Assert.AreEqual('выше нормы на 1000%', LResult.Verdict);
  LResult := MHCompareStats(mkWorkingSetBytes, Stat(0, 0, 100), Stat(0, 0, 100));
  Assert.AreEqual('в пределах нормы', LResult.Verdict);
end;

procedure TBaselineComparisonTests.ComparePeriods_ReturnsSystemMetrics;
var
  LCurrent, LBase: TMHBaseline;
  LResult: TArray<TMHMetricComparison>;
begin
  LCurrent := TMHBaseline.Empty;
  LCurrent.SystemCpu := Stat(60, 80, 100);
  LCurrent.MemoryLoad := Stat(40, 50, 100);
  LBase := TMHBaseline.Empty;
  LBase.SystemCpu := Stat(20, 30, 100);
  LBase.MemoryLoad := Stat(40, 50, 100);
  LResult := MHComparePeriods(LCurrent, LBase);
  Assert.AreEqual(3, Integer(Length(LResult)));
  Assert.AreEqual<TMHMetricKind>(mkCpuPercent, LResult[0].Kind);
  Assert.AreEqual('выше нормы на 200%', LResult[0].Verdict);
  Assert.AreEqual<TMHMetricKind>(mkMemoryLoadPercent, LResult[1].Kind);
  Assert.AreEqual('в пределах нормы', LResult[1].Verdict);
  Assert.AreEqual<TMHMetricKind>(mkDiskActivePercent, LResult[2].Kind);
  Assert.AreEqual('нет данных о норме', LResult[2].Verdict);
end;

procedure TBaselineComparisonTests.CompareProcesses_RisesAndNewPrograms;
var
  LCurrent, LBase: TMHBaseline;
  LResult: TArray<TMHProcessDeviation>;
begin
  LBase := TMHBaseline.Empty;
  LBase.Processes := [ProcBaseline('c:\a.exe', 10), ProcBaseline('c:\b.exe', 20)];
  LCurrent := TMHBaseline.Empty;
  LCurrent.Processes := [
    ProcBaseline('c:\a.exe', 16),     // +6 п.п. — отклонение
    ProcBaseline('C:\B.EXE', 24),     // +4 п.п. — ниже порога
    ProcBaseline('c:\miner.exe', 30), // новая программа с заметной нагрузкой
    ProcBaseline('c:\tiny.exe', 3)];  // новая, но нагрузка ниже порога
  LResult := MHCompareProcesses(LCurrent, LBase);
  Assert.AreEqual(2, Integer(Length(LResult)));
  Assert.AreEqual('c:\miner.exe', LResult[0].Key, 'Сортировка по влиянию');
  Assert.IsTrue(LResult[0].IsNewProgram);
  Assert.AreEqual(30.0, LResult[0].CurrentCpuP95, 1e-9);
  Assert.AreEqual(0.0, LResult[0].BaselineCpuP95, 1e-9);
  Assert.IsTrue(LResult[0].Description.Contains('новая программа'));
  Assert.AreEqual('c:\a.exe', LResult[1].Key);
  Assert.IsFalse(LResult[1].IsNewProgram);
  Assert.AreEqual(10.0, LResult[1].BaselineCpuP95, 1e-9);
  Assert.IsTrue(LResult[1].Description.Contains('при норме'));

  LResult := MHCompareProcesses(LCurrent, LBase, 3);
  Assert.AreEqual(4, Integer(Length(LResult)), 'Порог задаётся параметром');
end;

initialization
  TDUnitX.RegisterTestFixture(TBaselineBuilderTests);
  TDUnitX.RegisterTestFixture(TBaselineManagerTests);
  TDUnitX.RegisterTestFixture(TBaselineComparisonTests);

end.
