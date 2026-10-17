unit MineHunter.Tests.Collectors;

{
  Contract: все коллекторы стандартной конфигурации соблюдают единый контракт
  статусов. Integration: коллектор самодиагностики работает на реальной Windows.
}

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  [Category('Contract')]
  TCollectorContractTests = class
  public
    [Test] procedure AllDefaultCollectors_HaveUniqueNonEmptyIds;
    [Test] procedure AllDefaultCollectors_ReturnDefinedStatusAndNeverRaise;
    [Test] procedure AllDefaultCollectors_TolerateEmptySnapshot;
  end;

  [TestFixture]
  [Category('Integration')]
  TSelfMonitorTests = class
  public
    [Test] procedure FirstCall_IsPartial_CpuNoData;
    [Test] procedure SecondCall_IsSuccess_WithCpuInRange;
    [Test] procedure ProcessIdentity_MatchesCurrentProcess;
    [Test] procedure NilClock_Raises;
  end;

  [TestFixture]
  [Category('Integration')]
  TProcessCollectorIntegrationTests = class
  public
    [Test] procedure OwnProcess_HasFullData;
    [Test] procedure SecondCollect_OwnCpuAvailable;
    [Test] procedure ChildProcess_SeenWithParent_ThenGone;
    [Test] procedure SystemProcesses_ArePresent;
    [Test] procedure NoHandleLeak_AfterManyCollects;
  end;

  [TestFixture]
  [Category('Integration')]
  TSystemCollectorIntegrationTests = class
  public
    [Test] procedure RealValues_ArePlausible;
    [Test] procedure NoHandleLeak_AfterManyCollects;
  end;

implementation

// Интеграционные тесты работают только на Windows.
{$WARN SYMBOL_PLATFORM OFF}

uses
  System.SysUtils, System.Diagnostics, Winapi.Windows,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Core.Container,
  MineHunter.Core.Logging, MineHunter.Core.Calc, MineHunter.Core.Paths,
  MineHunter.Collectors.SelfMonitor, MineHunter.Collectors.Processes,
  MineHunter.Collectors.Processes.WinApi, MineHunter.Collectors.System,
  MineHunter.Collectors.System.WinApi, MineHunter.App.Bootstrap;

function UtcNow: TDateTime;
var
  LClock: IMHClock;
begin
  LClock := TMHSystemClock.Create;
  Result := LClock.NowUtc;
end;

function DefaultCollectors: TArray<IMHCollector>;
var
  LContainer: TMHContainer;
begin
  LContainer := TMHContainer.Create;
  try
    TMHAppServices.RegisterDefaults(LContainer);
    Result := LContainer.ResolveAll<IMHCollector>;
  finally
    LContainer.Free;
  end;
end;

procedure CheckContract(const ACollector: IMHCollector; const AResult: TMHCollectionResult);
var
  LInfo: TMHProcessInfo;
  LPidZero: Integer;
begin
  LPidZero := 0;
  Assert.AreEqual(ACollector.SourceId, AResult.Status.SourceId,
    'Статус должен содержать идентификатор своего источника');
  Assert.IsTrue(AResult.Status.State in [ssSuccess, ssPartial, ssUnavailable, ssError],
    'Состояние источника должно быть определено');
  if AResult.Status.State <> ssSuccess then
    Assert.IsNotEmpty(AResult.Status.Message,
      'Неполный результат обязан объяснять причину');
  for LInfo in AResult.Processes do
  begin
    Assert.AreEqual(ACollector.SourceId, LInfo.SourceId, 'У процесса должен быть указан источник');
    Assert.IsNotEmpty(LInfo.Name, 'У процесса должно быть имя');
    // PID 0 без времени создания допустим только для System Idle Process.
    if LInfo.Id.IsEmpty then
      Inc(LPidZero);
  end;
  Assert.IsTrue(LPidZero <= 1, 'Без идентичности может быть только один псевдопроцесс PID 0');
end;

{ TCollectorContractTests }

procedure TCollectorContractTests.AllDefaultCollectors_HaveUniqueNonEmptyIds;
var
  LCollectors: TArray<IMHCollector>;
  I, J: Integer;
begin
  LCollectors := DefaultCollectors;
  Assert.IsTrue(Length(LCollectors) > 0);
  for I := 0 to High(LCollectors) do
  begin
    Assert.IsNotEmpty(LCollectors[I].SourceId);
    Assert.IsNotEmpty(LCollectors[I].DisplayName);
    for J := I + 1 to High(LCollectors) do
      Assert.AreNotEqual(LCollectors[I].SourceId, LCollectors[J].SourceId, True);
  end;
end;

procedure TCollectorContractTests.AllDefaultCollectors_ReturnDefinedStatusAndNeverRaise;
var
  LCollector: IMHCollector;
  LSnapshot: TMHSnapshot;
  I: Integer;
begin
  LSnapshot := TMHSnapshot.Create(1, UtcNow);
  for LCollector in DefaultCollectors do
    for I := 1 to 3 do
      CheckContract(LCollector, LCollector.Collect(LSnapshot));
end;

procedure TCollectorContractTests.AllDefaultCollectors_TolerateEmptySnapshot;
var
  LCollector: IMHCollector;
begin
  for LCollector in DefaultCollectors do
    CheckContract(LCollector, LCollector.Collect(Default(TMHSnapshot)));
end;

{ TSelfMonitorTests }

function NewSelfMonitor: IMHCollector;
begin
  Result := TMHSelfMonitorCollector.Create(TMHSystemClock.Create);
end;

function NowSnapshot: TMHSnapshot;
begin
  Result := TMHSnapshot.Create(1, UtcNow);
end;

procedure TSelfMonitorTests.FirstCall_IsPartial_CpuNoData;
var
  LResult: TMHCollectionResult;
begin
  LResult := NewSelfMonitor.Collect(NowSnapshot);
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.AreEqual(1, Integer(Length(LResult.Processes)));
  Assert.IsFalse(LResult.Processes[0].Cpu.HasValue, 'Без второго замера CPU неизвестен');
  Assert.IsTrue(LResult.Processes[0].WorkingSet.HasValue);
  Assert.IsTrue(LResult.Processes[0].WorkingSet.Value > 0);
end;

procedure TSelfMonitorTests.SecondCall_IsSuccess_WithCpuInRange;
var
  LCollector: IMHCollector;
  LResult: TMHCollectionResult;
  LWatch: TStopwatch;
  LDummy: Double;
begin
  LCollector := NewSelfMonitor;
  LCollector.Collect(NowSnapshot);
  // Небольшая безвредная нагрузка, чтобы дельта CPU была ненулевой.
  LWatch := TStopwatch.StartNew;
  LDummy := 0;
  while LWatch.ElapsedMilliseconds < 120 do
    LDummy := LDummy + Sqrt(LWatch.ElapsedTicks);
  LResult := LCollector.Collect(NowSnapshot);
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State, LResult.Status.Message);
  Assert.IsTrue(LResult.Processes[0].Cpu.HasValue);
  Assert.IsTrue((LResult.Processes[0].Cpu.Value >= 0) and (LResult.Processes[0].Cpu.Value <= 100),
    Format('CPU вне диапазона: %g (%g)', [LResult.Processes[0].Cpu.Value, LDummy]));
end;

procedure TSelfMonitorTests.ProcessIdentity_MatchesCurrentProcess;
var
  LInfo: TMHProcessInfo;
begin
  LInfo := NewSelfMonitor.Collect(NowSnapshot).Processes[0];
  Assert.AreEqual<Cardinal>(GetCurrentProcessId, LInfo.Id.Pid);
  Assert.IsTrue(LInfo.Id.HasCreateTime);
  Assert.AreEqual(ParamStr(0), LInfo.ImagePath, True);
  Assert.AreEqual<TMHAccessLevel>(alFull, LInfo.Access);
  // Идентичность стабильна между вызовами.
  Assert.IsTrue(LInfo.Id = NewSelfMonitor.Collect(NowSnapshot).Processes[0].Id);
end;

procedure TSelfMonitorTests.NilClock_Raises;
begin
  Assert.WillRaise(
    procedure
    begin
      TMHSelfMonitorCollector.Create(nil).Free;
    end, EArgumentNilException);
end;

{ TProcessCollectorIntegrationTests }

function NewProcessCollector: IMHCollector;
var
  LApi: IMHProcessApi;
begin
  LApi := TMHWinProcessApi.Create;
  Result := TMHProcessCollector.Create(LApi, TMHSystemClock.Create);
end;

function FindById(const AResult: TMHCollectionResult; const AId: TMHProcessId;
  out AInfo: TMHProcessInfo): Boolean;
var
  LInfo: TMHProcessInfo;
begin
  for LInfo in AResult.Processes do
    if LInfo.Id = AId then
    begin
      AInfo := LInfo;
      Exit(True);
    end;
  AInfo := Default(TMHProcessInfo);
  Result := False;
end;

function FindByPid(const AResult: TMHCollectionResult; APid: Cardinal;
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

function ProcessIdOf(AHandle: THandle; APid: Cardinal): TMHProcessId;
var
  LCreation, LExit, LKernel, LUser: TFileTime;
begin
  Win32Check(GetProcessTimes(AHandle, LCreation, LExit, LKernel, LUser));
  Result := TMHProcessId.Create(APid,
    MHFileTimeToUInt64(LCreation.dwLowDateTime, LCreation.dwHighDateTime));
end;

procedure TProcessCollectorIntegrationTests.OwnProcess_HasFullData;
var
  LResult: TMHCollectionResult;
  LInfo: TMHProcessInfo;
begin
  LResult := NewProcessCollector.Collect(TMHSnapshot.Create(1, UtcNow));
  Assert.IsTrue(LResult.Status.State in [ssSuccess, ssPartial], LResult.Status.Message);
  Assert.IsTrue(Length(LResult.Processes) > 10, 'В системе должно быть больше 10 процессов');
  Assert.IsTrue(FindById(LResult, ProcessIdOf(GetCurrentProcess, GetCurrentProcessId), LInfo),
    'Собственный процесс должен находиться по PID и времени создания');
  Assert.AreEqual<TMHAccessLevel>(alFull, LInfo.Access);
  Assert.IsTrue(MHSamePath(ParamStr(0), LInfo.ImagePath), LInfo.ImagePath);
  Assert.IsTrue(LInfo.ThreadCount > 0);
  Assert.IsTrue(LInfo.WorkingSet.HasValue and (LInfo.WorkingSet.Value > 0));
  Assert.IsTrue(LInfo.PrivateBytes.HasValue and (LInfo.PrivateBytes.Value > 0));
end;

procedure TProcessCollectorIntegrationTests.SecondCollect_OwnCpuAvailable;
var
  LCollector: IMHCollector;
  LInfo: TMHProcessInfo;
  LWatch: TStopwatch;
  LDummy: Double;
begin
  LCollector := NewProcessCollector;
  LCollector.Collect(TMHSnapshot.Create(1, UtcNow));
  LWatch := TStopwatch.StartNew;
  LDummy := 0;
  while LWatch.ElapsedMilliseconds < 120 do
    LDummy := LDummy + Sqrt(LWatch.ElapsedTicks);
  Assert.IsTrue(FindByPid(LCollector.Collect(TMHSnapshot.Create(2, UtcNow)),
    GetCurrentProcessId, LInfo));
  Assert.IsTrue(LInfo.Cpu.HasValue);
  Assert.IsTrue((LInfo.Cpu.Value > 0) and (LInfo.Cpu.Value <= 100),
    Format('CPU = %g (%g)', [LInfo.Cpu.Value, LDummy]));
end;

procedure TProcessCollectorIntegrationTests.ChildProcess_SeenWithParent_ThenGone;
var
  LCollector: IMHCollector;
  LStartup: TStartupInfo;
  LProcInfo: TProcessInformation;
  LCmd: string;
  LSysDir: array[0..MAX_PATH] of Char;
  LChildId: TMHProcessId;
  LInfo: TMHProcessInfo;
begin
  // Безвредный дочерний процесс: cmd.exe создаётся приостановленным и
  // завершается тестом, не выполнив ни одной команды.
  GetSystemDirectory(LSysDir, Length(LSysDir));
  LCmd := Format('"%s\cmd.exe" /c exit 0', [string(LSysDir)]);
  UniqueString(LCmd);
  FillChar(LStartup, SizeOf(LStartup), 0);
  LStartup.cb := SizeOf(LStartup);
  Win32Check(CreateProcess(nil, PChar(LCmd), nil, nil, False,
    CREATE_SUSPENDED or CREATE_NO_WINDOW, nil, nil, LStartup, LProcInfo));
  try
    LChildId := ProcessIdOf(LProcInfo.hProcess, LProcInfo.dwProcessId);
    LCollector := NewProcessCollector;
    Assert.IsTrue(FindById(LCollector.Collect(TMHSnapshot.Create(1, UtcNow)), LChildId, LInfo),
      'Дочерний процесс должен быть найден');
    Assert.AreEqual<Cardinal>(GetCurrentProcessId, LInfo.ParentPid);
    Assert.AreEqual('cmd.exe', LInfo.Name, True);
    Assert.IsTrue(MHSamePath(string(LSysDir) + '\cmd.exe', LInfo.ImagePath), LInfo.ImagePath);

    TerminateProcess(LProcInfo.hProcess, 0);
    WaitForSingleObject(LProcInfo.hProcess, 5000);
    Assert.IsFalse(FindById(LCollector.Collect(TMHSnapshot.Create(2, UtcNow)), LChildId, LInfo),
      'Завершённый процесс не должен оставаться в списке');
  finally
    TerminateProcess(LProcInfo.hProcess, 0);
    CloseHandle(LProcInfo.hThread);
    CloseHandle(LProcInfo.hProcess);
  end;
end;

procedure TProcessCollectorIntegrationTests.SystemProcesses_ArePresent;
var
  LResult: TMHCollectionResult;
  LInfo: TMHProcessInfo;
begin
  LResult := NewProcessCollector.Collect(TMHSnapshot.Create(1, UtcNow));
  Assert.IsTrue(FindByPid(LResult, 0, LInfo), 'System Idle Process');
  Assert.IsTrue(FindByPid(LResult, 4, LInfo), 'System');
  Assert.AreEqual('System', LInfo.Name, True);
  if LResult.Status.State = ssPartial then
    Assert.IsNotEmpty(LResult.Status.Message);
end;

procedure TProcessCollectorIntegrationTests.NoHandleLeak_AfterManyCollects;
var
  LCollector: IMHCollector;
  LBefore, LAfter: DWORD;
  I: Integer;
begin
  LCollector := NewProcessCollector;
  LCollector.Collect(TMHSnapshot.Create(1, UtcNow));
  Win32Check(GetProcessHandleCount(GetCurrentProcess, LBefore));
  for I := 2 to 21 do
    LCollector.Collect(TMHSnapshot.Create(I, UtcNow));
  Win32Check(GetProcessHandleCount(GetCurrentProcess, LAfter));
  Assert.IsTrue(Integer(LAfter) - Integer(LBefore) < 20,
    Format('Число дескрипторов выросло с %d до %d', [LBefore, LAfter]));
end;

{ TSystemCollectorIntegrationTests }

function NewSystemCollector: IMHCollector;
var
  LApi: IMHSystemMetricsApi;
begin
  LApi := TMHWinSystemMetricsApi.Create;
  Result := TMHSystemCollector.Create(LApi, TMHSystemClock.Create);
end;

function MetricOf(const AResult: TMHCollectionResult; AKind: TMHMetricKind): TMHMetric;
var
  LMetric: TMHMetric;
begin
  Result := TMHMetric.NoData(AKind, 0);
  for LMetric in AResult.Metrics do
    if LMetric.Kind = AKind then
      Exit(LMetric);
end;

procedure TSystemCollectorIntegrationTests.RealValues_ArePlausible;
var
  LCollector: IMHCollector;
  LResult: TMHCollectionResult;
  LStatus: TMemoryStatusEx;
  LCpu, LActive: TMHMetric;
begin
  LCollector := NewSystemCollector;
  LCollector.Collect(TMHSnapshot.Create(1, UtcNow));
  Sleep(300);
  LResult := LCollector.Collect(TMHSnapshot.Create(2, UtcNow));
  Assert.IsTrue(LResult.Status.State in [ssSuccess, ssPartial], LResult.Status.Message);

  LCpu := MetricOf(LResult, mkCpuPercent);
  Assert.IsTrue(LCpu.HasValue, 'CPU со второго замера');
  Assert.IsTrue((LCpu.Value >= 0) and (LCpu.Value <= 100), FloatToStr(LCpu.Value));

  FillChar(LStatus, SizeOf(LStatus), 0);
  LStatus.dwLength := SizeOf(LStatus);
  Win32Check(GlobalMemoryStatusEx(LStatus));
  Assert.AreEqual(Double(LStatus.ullTotalPhys), MetricOf(LResult, mkMemoryTotalBytes).Value, 1,
    'Эталон — GlobalMemoryStatusEx');
  Assert.IsTrue(MetricOf(LResult, mkMemoryUsedBytes).Value <= LStatus.ullTotalPhys);

  LActive := MetricOf(LResult, mkDiskActivePercent);
  if LActive.HasValue then
    Assert.IsTrue((LActive.Value >= 0) and (LActive.Value <= 100))
  else
    Assert.IsTrue(LResult.Status.Message.Contains('Диск'),
      'Недоступность диска должна объясняться: ' + LResult.Status.Message);
end;

procedure TSystemCollectorIntegrationTests.NoHandleLeak_AfterManyCollects;
var
  LCollector: IMHCollector;
  LBefore, LAfter: DWORD;
  I: Integer;
begin
  LCollector := NewSystemCollector;
  LCollector.Collect(TMHSnapshot.Create(1, UtcNow));
  Win32Check(GetProcessHandleCount(GetCurrentProcess, LBefore));
  for I := 2 to 31 do
    LCollector.Collect(TMHSnapshot.Create(I, UtcNow));
  Win32Check(GetProcessHandleCount(GetCurrentProcess, LAfter));
  Assert.IsTrue(Integer(LAfter) - Integer(LBefore) < 20,
    Format('Число дескрипторов выросло с %d до %d', [LBefore, LAfter]));
end;

initialization
  TDUnitX.RegisterTestFixture(TCollectorContractTests);
  TDUnitX.RegisterTestFixture(TSelfMonitorTests);
  TDUnitX.RegisterTestFixture(TProcessCollectorIntegrationTests);
  TDUnitX.RegisterTestFixture(TSystemCollectorIntegrationTests);

end.
