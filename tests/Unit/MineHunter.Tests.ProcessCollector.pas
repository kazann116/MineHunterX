unit MineHunter.Tests.ProcessCollector;

interface

uses
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Collectors.Processes,
  MineHunter.Tests.FakeProcessApi;

type
  [TestFixture]
  [Category('Unit')]
  TProcessCollectorTests = class
  private
    FApi: TFakeProcessApi;
    FApiIntf: IMHProcessApi;
    FCollector: TMHProcessCollector;
    FCollectorIntf: IMHCollector;
    function Collect: TMHCollectionResult;
    function Find(const AResult: TMHCollectionResult; APid: Cardinal;
      out AInfo: TMHProcessInfo): Boolean;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Create_NilArguments_Raise;
    [Test] procedure FirstCollect_FullData_CpuNoData;
    [Test] procedure SecondCollect_CpuFromDelta;
    [Test] procedure ReusedPid_IsNewInstance_CpuRestarts;
    [Test] procedure CpuCounterDecrease_GivesNoData;
    [Test] procedure AccessDenied_IsPartial_WithElevationHint;
    [Test] procedure AccessDenied_WhenElevated_NoElevationHint;
    [Test] procedure MissingMemory_IsLimitedAccess;
    [Test] procedure ProcessGoneDuringQuery_IsSkipped;
    [Test] procedure PidReusedBetweenEnumAndOpen_IsSkipped;
    [Test] procedure EnumerationFailure_IsErrorStatusNotException;
    [Test] procedure IdleProcessWithoutTimes_IsListedWithoutCpu;
    [Test] procedure ExitedProcesses_AreNotTracked;
    [Test] procedure ResultMatchesCollectorContract;
    [Test] procedure Cpu_ScaledToUtilityLikeTaskManager;
    [Test] procedure Cpu_ScaledValueCappedAt100;
    [Test] procedure UtilityFactor_NoMetricsOrLowLoad_IsOne;
    [Test] procedure UtilityFactor_IsBounded;
    [Test] procedure PrivateWorkingSet_FromApiByPid;
    [Test] procedure PrivateWorkingSet_Unavailable_IsNoData;
  end;

  [TestFixture]
  [Category('Performance')]
  TProcessCollectorPerformanceTests = class
  public
    [Test] procedure ThousandsOfProcesses_CollectQuickly;
    [Test] procedure RepeatedCollect_DoesNotGrowHeap;
  end;

implementation

uses
  System.SysUtils, System.Diagnostics,
  MineHunter.Tests.Fakes;

{ TProcessCollectorTests }

procedure TProcessCollectorTests.Setup;
begin
  FApi := TFakeProcessApi.Create(4);
  FApiIntf := FApi;
  FCollector := TMHProcessCollector.Create(FApiIntf, TFakeClock.Create(FAKE_NOW));
  FCollectorIntf := FCollector;
end;

procedure TProcessCollectorTests.TearDown;
begin
  FCollectorIntf := nil;
  FCollector := nil;
  FApiIntf := nil;
  FApi := nil;
end;

function TProcessCollectorTests.Collect: TMHCollectionResult;
begin
  Result := FCollectorIntf.Collect(TMHSnapshot.Create(1, FAKE_NOW));
end;

function TProcessCollectorTests.Find(const AResult: TMHCollectionResult; APid: Cardinal;
  out AInfo: TMHProcessInfo): Boolean;
var
  LInfo: TMHProcessInfo;
begin
  for LInfo in AResult.Processes do
    if LInfo.Id.Pid = APid then
    begin
      AInfo := LInfo;
      Exit(True);
    end;
  AInfo := Default(TMHProcessInfo);
  Result := False;
end;

procedure TProcessCollectorTests.Create_NilArguments_Raise;
var
  LClock: IMHClock;
begin
  LClock := TFakeClock.Create(FAKE_NOW);
  Assert.WillRaise(
    procedure
    begin
      TMHProcessCollector.Create(nil, LClock).Free;
    end, EArgumentNilException);
  Assert.WillRaise(
    procedure
    begin
      TMHProcessCollector.Create(FApiIntf, nil).Free;
    end, EArgumentNilException);
end;

procedure TProcessCollectorTests.FirstCollect_FullData_CpuNoData;
var
  LResult: TMHCollectionResult;
  LInfo: TMHProcessInfo;
begin
  FApi.Add(100, 4, 'game.exe', FAKE_BASE_TIME + 1, 50 * FAKE_SECOND, 2048);
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State);
  Assert.AreEqual(TMHProcessCollector.SourceIdValue, LResult.Status.SourceId);
  Assert.AreEqual(1, LResult.Status.ItemCount);
  Assert.IsTrue(Find(LResult, 100, LInfo));
  Assert.AreEqual<UInt64>(FAKE_BASE_TIME + 1, LInfo.Id.CreateTime);
  Assert.AreEqual<Cardinal>(4, LInfo.ParentPid);
  Assert.AreEqual('game.exe', LInfo.Name);
  Assert.AreEqual('C:\Fake\game.exe', LInfo.ImagePath);
  Assert.AreEqual<TMHAccessLevel>(alFull, LInfo.Access);
  Assert.AreEqual(3, LInfo.ThreadCount);
  Assert.AreEqual(2048.0, LInfo.WorkingSet.Value, 0.1);
  Assert.AreEqual(1024.0, LInfo.PrivateBytes.Value, 0.1);
  Assert.IsFalse(LInfo.Cpu.HasValue, 'Без предыдущего замера CPU неизвестен');
  Assert.AreEqual(TMHProcessCollector.SourceIdValue, LInfo.SourceId);
end;

procedure TProcessCollectorTests.SecondCollect_CpuFromDelta;
var
  LInfo: TMHProcessInfo;
begin
  FApi.Add(100, 4, 'miner-sim.exe', FAKE_BASE_TIME + 1, 10 * FAKE_SECOND);
  Collect;
  // За 1 с реального времени процесс получил 2 с процессорного (2 ядра из 4).
  FApi.AdvanceWall(FAKE_SECOND);
  FApi.SetCpu(100, 12 * FAKE_SECOND);
  Assert.IsTrue(Find(Collect, 100, LInfo));
  Assert.IsTrue(LInfo.Cpu.HasValue);
  Assert.AreEqual(50.0, LInfo.Cpu.Value, 0.001);
end;

procedure TProcessCollectorTests.ReusedPid_IsNewInstance_CpuRestarts;
var
  LInfo: TMHProcessInfo;
begin
  FApi.Add(100, 4, 'old.exe', FAKE_BASE_TIME + 1, 500 * FAKE_SECOND);
  Collect;
  // Процесс завершился, PID 100 достался новому процессу с меньшим временем CPU.
  FApi.AdvanceWall(FAKE_SECOND);
  FApi.Add(100, 4, 'new.exe', FAKE_BASE_TIME + 999, FAKE_SECOND);
  Assert.IsTrue(Find(Collect, 100, LInfo));
  Assert.AreEqual('new.exe', LInfo.Name);
  Assert.AreEqual<UInt64>(FAKE_BASE_TIME + 999, LInfo.Id.CreateTime);
  Assert.IsFalse(LInfo.Cpu.HasValue,
    'Дельта CPU не должна считаться между разными экземплярами с одним PID');

  FApi.AdvanceWall(FAKE_SECOND);
  FApi.SetCpu(100, FAKE_SECOND + 4000000); // +0.4 с CPU за 1 с на 4 ядрах = 10%
  Assert.IsTrue(Find(Collect, 100, LInfo));
  Assert.AreEqual(10.0, LInfo.Cpu.Value, 0.001);
end;

procedure TProcessCollectorTests.CpuCounterDecrease_GivesNoData;
var
  LInfo: TMHProcessInfo;
begin
  FApi.Add(100, 4, 'a.exe', FAKE_BASE_TIME + 1, 10 * FAKE_SECOND);
  Collect;
  FApi.AdvanceWall(FAKE_SECOND);
  FApi.SetCpu(100, 5 * FAKE_SECOND);
  Assert.IsTrue(Find(Collect, 100, LInfo));
  Assert.IsFalse(LInfo.Cpu.HasValue, 'Некорректная дельта — «нет данных», а не 0 или мусор');
end;

procedure TProcessCollectorTests.AccessDenied_IsPartial_WithElevationHint;
var
  LResult: TMHCollectionResult;
  LInfo: TMHProcessInfo;
begin
  FApi.Add(100, 4, 'user.exe', FAKE_BASE_TIME + 1);
  FApi.AddDenied(200, 4, 'protected.exe');
  FApi.Elevated := False;
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.IsTrue(LResult.Status.RequiresElevation);
  Assert.IsNotEmpty(LResult.Status.Message);
  Assert.AreEqual(2, Integer(Length(LResult.Processes)), 'Недоступный процесс не скрывается');
  Assert.IsTrue(Find(LResult, 200, LInfo));
  Assert.AreEqual<TMHAccessLevel>(alDenied, LInfo.Access);
  Assert.AreEqual('protected.exe', LInfo.Name);
  Assert.AreEqual<Cardinal>(4, LInfo.ParentPid);
  Assert.AreEqual(10, LInfo.ThreadCount, 'Число потоков известно из перечня');
  Assert.AreEqual('', LInfo.ImagePath);
  Assert.IsFalse(LInfo.Cpu.HasValue);
  Assert.IsFalse(LInfo.WorkingSet.HasValue);
  Assert.IsFalse(LInfo.Id.HasCreateTime);
end;

procedure TProcessCollectorTests.AccessDenied_WhenElevated_NoElevationHint;
var
  LResult: TMHCollectionResult;
begin
  FApi.AddDenied(200, 4, 'protected.exe');
  FApi.Elevated := True;
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.IsFalse(LResult.Status.RequiresElevation,
    'Повышение прав не поможет — защищённые процессы недоступны и администратору');
end;

procedure TProcessCollectorTests.MissingMemory_IsLimitedAccess;
var
  LDetails: TMHRawProcessDetails;
  LInfo: TMHProcessInfo;
  LResult: TMHCollectionResult;
begin
  FApi.Add(100, 4, 'svc.exe', FAKE_BASE_TIME + 1);
  LDetails := FApi.GetDetails(100);
  LDetails.HasMemory := False;
  FApi.SetDetails(100, LDetails);
  LResult := Collect;
  Assert.IsTrue(Find(LResult, 100, LInfo));
  Assert.AreEqual<TMHAccessLevel>(alLimited, LInfo.Access);
  Assert.IsFalse(LInfo.WorkingSet.HasValue);
  Assert.AreEqual('C:\Fake\svc.exe', LInfo.ImagePath);
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
end;

procedure TProcessCollectorTests.ProcessGoneDuringQuery_IsSkipped;
var
  LResult: TMHCollectionResult;
  LInfo: TMHProcessInfo;
begin
  FApi.Add(100, 4, 'a.exe', FAKE_BASE_TIME + 1);
  FApi.AddGone(300, 'short-lived.exe');
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State,
    'Завершение процесса — штатная ситуация, а не ошибка источника');
  Assert.IsFalse(Find(LResult, 300, LInfo));
  Assert.AreEqual(1, Integer(Length(LResult.Processes)));
  Assert.IsTrue(LResult.Status.Message.Contains('1'));
end;

procedure TProcessCollectorTests.PidReusedBetweenEnumAndOpen_IsSkipped;
var
  LDetails: TMHRawProcessDetails;
  LInfo: TMHProcessInfo;
begin
  FApi.Add(100, 4, 'old.exe', FAKE_BASE_TIME + 1);
  // Перечень говорит «old.exe», а открытый дескриптор указывает на другой образ.
  LDetails := FApi.GetDetails(100);
  LDetails.ImagePath := 'C:\Other\new.exe';
  FApi.SetDetails(100, LDetails);
  Assert.IsFalse(Find(Collect, 100, LInfo),
    'Данные другого процесса не должны приписываться имени из перечня');
end;

procedure TProcessCollectorTests.EnumerationFailure_IsErrorStatusNotException;
var
  LResult: TMHCollectionResult;
begin
  FApi.Add(100, 4, 'a.exe', FAKE_BASE_TIME + 1);
  FApi.EnumerateFails := True;
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssError, LResult.Status.State);
  Assert.IsTrue(LResult.Status.Message.Contains('simulated enumeration failure'));
  Assert.AreEqual(0, Integer(Length(LResult.Processes)));
end;

procedure TProcessCollectorTests.IdleProcessWithoutTimes_IsListedWithoutCpu;
var
  LDetails: TMHRawProcessDetails;
  LInfo: TMHProcessInfo;
begin
  FApi.Add(0, 0, '[System Process]', 0);
  LDetails := Default(TMHRawProcessDetails);
  LDetails.Status := pqOk;
  FApi.SetDetails(0, LDetails);
  Collect;
  FApi.AdvanceWall(FAKE_SECOND);
  Assert.IsTrue(Find(Collect, 0, LInfo));
  Assert.AreEqual<TMHAccessLevel>(alLimited, LInfo.Access);
  Assert.IsFalse(LInfo.Cpu.HasValue);
  Assert.IsFalse(LInfo.Id.HasCreateTime);
  Assert.AreEqual(0, FCollector.TrackedCount, 'Без времени создания экземпляр не отслеживается');
end;

procedure TProcessCollectorTests.ExitedProcesses_AreNotTracked;
begin
  FApi.Add(100, 4, 'a.exe', FAKE_BASE_TIME + 1);
  FApi.Add(101, 4, 'b.exe', FAKE_BASE_TIME + 2);
  Collect;
  Assert.AreEqual(2, FCollector.TrackedCount);
  FApi.Remove(100);
  Collect;
  Assert.AreEqual(1, FCollector.TrackedCount);
  FApi.Remove(101);
  Collect;
  Assert.AreEqual(0, FCollector.TrackedCount);
end;

procedure TProcessCollectorTests.ResultMatchesCollectorContract;
var
  LResult: TMHCollectionResult;
  LInfo: TMHProcessInfo;
begin
  FApi.Add(100, 4, 'a.exe', FAKE_BASE_TIME + 1);
  FApi.AddDenied(200, 4, 'b.exe');
  LResult := Collect;
  Assert.AreEqual(FCollectorIntf.SourceId, LResult.Status.SourceId);
  Assert.IsTrue(LResult.Status.State in [ssSuccess, ssPartial, ssUnavailable, ssError]);
  for LInfo in LResult.Processes do
    Assert.AreEqual(FCollectorIntf.SourceId, LInfo.SourceId);
end;

{ TProcessCollectorPerformanceTests }

procedure TProcessCollectorPerformanceTests.ThousandsOfProcesses_CollectQuickly;
const
  COUNT = 2000;
  LIMIT_MS = 500;
var
  LApi: TFakeProcessApi;
  LApiIntf: IMHProcessApi;
  LCollector: IMHCollector;
  LResult: TMHCollectionResult;
  LWatch: TStopwatch;
  I, LWithCpu: Integer;
begin
  LApi := TFakeProcessApi.Create(16);
  LApiIntf := LApi;
  for I := 1 to COUNT do
    LApi.Add(I * 4, 4, Format('p%d.exe', [I]), FAKE_BASE_TIME + UInt64(I), UInt64(I) * 1000);
  LCollector := TMHProcessCollector.Create(LApiIntf, TFakeClock.Create(FAKE_NOW));
  LCollector.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  for I := 1 to COUNT do
    LApi.SetCpu(I * 4, UInt64(I) * 1000 + 100000);
  LApi.AdvanceWall(FAKE_SECOND);

  LWatch := TStopwatch.StartNew;
  LResult := LCollector.Collect(TMHSnapshot.Create(2, FAKE_NOW));
  LWatch.Stop;

  Assert.AreEqual(COUNT, Integer(Length(LResult.Processes)));
  LWithCpu := 0;
  for I := 0 to High(LResult.Processes) do
    if LResult.Processes[I].Cpu.HasValue then
      Inc(LWithCpu);
  Assert.AreEqual(COUNT, LWithCpu);
  Assert.IsTrue(LWatch.ElapsedMilliseconds < LIMIT_MS,
    Format('Обработка %d процессов заняла %d мс (цель < %d мс)',
      [COUNT, LWatch.ElapsedMilliseconds, LIMIT_MS]));
end;

procedure RunCollectorCycle(ACount: Integer);
var
  LApi: TFakeProcessApi;
  LApiIntf: IMHProcessApi;
  LCollector: IMHCollector;
  I: Integer;
begin
  LApi := TFakeProcessApi.Create(4);
  LApiIntf := LApi;
  for I := 1 to ACount do
    LApi.Add(I, 0, 'x.exe', FAKE_BASE_TIME + UInt64(I));
  LApi.AddDenied(ACount + 1, 0, 'd.exe');
  LApi.AddGone(ACount + 2, 'g.exe');
  LCollector := TMHProcessCollector.Create(LApiIntf, TFakeClock.Create(FAKE_NOW));
  for I := 1 to 3 do
  begin
    LApi.AdvanceWall(FAKE_SECOND);
    LCollector.Collect(TMHSnapshot.Create(I, FAKE_NOW));
  end;
end;

procedure TProcessCollectorPerformanceTests.RepeatedCollect_DoesNotGrowHeap;
const
  ITERATIONS = 100;
  TOLERANCE_BYTES = 16 * 1024;
var
  LBefore, LAfter: Int64;
  I: Integer;
begin
  RunCollectorCycle(50);
  LBefore := MHTestAllocatedBytes;
  for I := 1 to ITERATIONS do
    RunCollectorCycle(50);
  LAfter := MHTestAllocatedBytes;
  Assert.IsTrue(LAfter - LBefore < TOLERANCE_BYTES,
    Format('Рост кучи %d байт за %d циклов — вероятна утечка', [LAfter - LBefore, ITERATIONS]));
end;

function SnapshotWithCpu(AUtility, ATime: Double): TMHSnapshot;
begin
  Result := TMHSnapshot.Create(1, FAKE_NOW);
  Result.Metrics := [TMHMetric.Available(mkCpuPercent, AUtility, FAKE_NOW),
    TMHMetric.Available(mkCpuTimePercent, ATime, FAKE_NOW)];
end;

procedure TProcessCollectorTests.Cpu_ScaledToUtilityLikeTaskManager;
var
  LResult: TMHCollectionResult;
  LInfo: TMHProcessInfo;
begin
  FApi.Add(100, 4, 'render.exe', FAKE_BASE_TIME + 1, 10 * FAKE_SECOND);
  Collect;
  FApi.AdvanceWall(FAKE_SECOND);
  FApi.SetCpu(100, 11 * FAKE_SECOND); // 1 ядро из 4 = 25% времени
  // Система: загруженность 39% при 30% времени (турбочастота, множитель 1,3).
  LResult := FCollectorIntf.Collect(SnapshotWithCpu(39, 30));
  Assert.IsTrue(Find(LResult, 100, LInfo));
  Assert.AreEqual(32.5, LInfo.Cpu.Value, 0.001);
end;

procedure TProcessCollectorTests.Cpu_ScaledValueCappedAt100;
var
  LInfo: TMHProcessInfo;
begin
  FApi.Add(100, 4, 'busy.exe', FAKE_BASE_TIME + 1, 10 * FAKE_SECOND);
  Collect;
  FApi.AdvanceWall(FAKE_SECOND);
  FApi.SetCpu(100, 14 * FAKE_SECOND); // все 4 ядра
  Assert.IsTrue(Find(FCollectorIntf.Collect(SnapshotWithCpu(100, 80)), 100, LInfo));
  Assert.AreEqual(100.0, LInfo.Cpu.Value, 0.001);
end;

procedure TProcessCollectorTests.UtilityFactor_NoMetricsOrLowLoad_IsOne;
begin
  Assert.AreEqual(1.0, MHCpuUtilityFactor(TMHSnapshot.Create(1, FAKE_NOW)), 1e-9);
  Assert.AreEqual(1.0, MHCpuUtilityFactor(SnapshotWithCpu(0.9, 0.5)), 1e-9,
    'При почти нулевой загрузке отношение ненадёжно');
end;

procedure TProcessCollectorTests.UtilityFactor_IsBounded;
begin
  Assert.AreEqual(4.0, MHCpuUtilityFactor(SnapshotWithCpu(100, 2)), 1e-9);
  Assert.AreEqual(0.25, MHCpuUtilityFactor(SnapshotWithCpu(1, 50)), 1e-9);
  Assert.AreEqual(1.25, MHCpuUtilityFactor(SnapshotWithCpu(50, 40)), 1e-9);
end;

procedure TProcessCollectorTests.PrivateWorkingSet_FromApiByPid;
var
  LResult: TMHCollectionResult;
  LInfo: TMHProcessInfo;
  LValue: TMHPidBytes;
begin
  FApi.Add(100, 4, 'app.exe', FAKE_BASE_TIME + 1, 0, 300 * 1048576);
  FApi.AddDenied(200, 4, 'protected.exe');
  LValue.Pid := 100;
  LValue.Bytes := 120 * 1048576;
  FApi.PrivateSets := [LValue];
  LResult := Collect;
  Assert.IsTrue(Find(LResult, 100, LInfo));
  Assert.IsTrue(LInfo.PrivateWorkingSet.HasValue);
  Assert.AreEqual(120.0 * 1048576, LInfo.PrivateWorkingSet.Value, 1);
  Assert.AreEqual(300.0 * 1048576, LInfo.WorkingSet.Value, 1, 'Рабочий набор остаётся отдельной метрикой');
  Assert.IsTrue(Find(LResult, 200, LInfo));
  Assert.IsFalse(LInfo.PrivateWorkingSet.HasValue);
end;

procedure TProcessCollectorTests.PrivateWorkingSet_Unavailable_IsNoData;
var
  LInfo: TMHProcessInfo;
begin
  FApi.Add(100, 4, 'app.exe', FAKE_BASE_TIME + 1);
  Assert.IsTrue(Find(Collect, 100, LInfo));
  Assert.IsFalse(LInfo.PrivateWorkingSet.HasValue);
  Assert.AreEqual<TMHMetricKind>(mkPrivateWorkingSetBytes, LInfo.PrivateWorkingSet.Kind);
end;

initialization
  TDUnitX.RegisterTestFixture(TProcessCollectorTests);
  TDUnitX.RegisterTestFixture(TProcessCollectorPerformanceTests);

end.
