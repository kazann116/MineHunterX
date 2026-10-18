unit MineHunter.Tests.ProcessEvents;

{
  События запуска процессов: раскладка структур ETW (x64), сводка коллектора
  на поддельном источнике, правило «часто запускается и сразу завершается» и
  интеграционная проверка настоящего сеанса ETW (с правами и без).
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Collectors.ProcessEvents,
  MineHunter.Tests.Fakes;

type
  TFakeEventSource = class(TInterfacedObject, IMHProcessEventSource)
  public
    StartResult: Boolean;
    StartDenied: Boolean;
    StartCalls: Integer;
    StopCalls: Integer;
    Running: Boolean;
    Pending: TList<TMHProcessEvent>;
    Lost: Integer;
    constructor Create;
    destructor Destroy; override;
    procedure AddStart(APid, AParent: Cardinal; ACreate: UInt64; ATime: TDateTime; const APath: string);
    procedure AddStop(APid: Cardinal; ACreate: UInt64; ATime: TDateTime);
    function Start(out AError: string; out AAccessDenied: Boolean): Boolean;
    procedure Stop;
    function Drain(out ALost: Integer): TArray<TMHProcessEvent>;
    function IsRunning: Boolean;
  end;

  [TestFixture]
  [Category('Unit')]
  TProcessEventTests = class
  public
    [Test] procedure EtwStructures_HaveSdkSizes;
    [Test] procedure AccessDenied_UnavailableWithElevationHint_NoRetry;
    [Test] procedure OtherFailure_RetriedLater;
    [Test] procedure ShortLivedLoop_Summarized;
    [Test] procedure Window_PrunesOldLaunches;
    [Test] procedure UnmatchedAndDuplicateEvents_Ignored;
    [Test] procedure SourceStoppedExternally_Restarted;
    [Test] procedure Destroy_StopsSource;
  end;

  [TestFixture]
  [Category('Unit')]
  TLaunchRuleTests = class
  private
    function Stat(const APath: string; AStarts, AShort: Integer; const AParent: string = 'explorer.exe'): TMHLaunchStat;
    function Analyze(const AStats: array of TMHLaunchStat): TMHFindings;
  public
    [Test] procedure LoopFromTemp_NeedsReviewOrHigher;
    [Test] procedure MinerName_Suspicious;
    [Test] procedure BuildTool_InProgramFiles_NoFinding;
    [Test] procedure BelowThresholds_NoFinding;
    [Test] procedure ScriptHostFromScheduler_Raised;
    [Test] procedure Exclusion_Respected;
  end;

  [TestFixture]
  [Category('Integration')]
  TEtwIntegrationTests = class
  public
    [Test] procedure RealSession_StartsOrExplainsAccess;
  end;

implementation

uses
  System.DateUtils, System.Classes, Winapi.Windows,
  MineHunter.Analysis.Launches, MineHunter.Analysis.Tamper,
  MineHunter.Collectors.ProcessEvents.WinApi, MineHunter.Collectors.Processes.WinApi;

const
  TEMP_EXE = 'C:\Users\u\AppData\Local\Temp\updater.exe';

{ TFakeEventSource }

constructor TFakeEventSource.Create;
begin
  inherited Create;
  StartResult := True;
  Pending := TList<TMHProcessEvent>.Create;
end;

destructor TFakeEventSource.Destroy;
begin
  Pending.Free;
  inherited;
end;

procedure TFakeEventSource.AddStart(APid, AParent: Cardinal; ACreate: UInt64; ATime: TDateTime;
  const APath: string);
var
  LEvent: TMHProcessEvent;
begin
  LEvent := Default(TMHProcessEvent);
  LEvent.Kind := pekStart;
  LEvent.Pid := APid;
  LEvent.ParentPid := AParent;
  LEvent.CreateTime := ACreate;
  LEvent.TimestampUtc := ATime;
  LEvent.ImagePath := APath;
  Pending.Add(LEvent);
end;

procedure TFakeEventSource.AddStop(APid: Cardinal; ACreate: UInt64; ATime: TDateTime);
var
  LEvent: TMHProcessEvent;
begin
  LEvent := Default(TMHProcessEvent);
  LEvent.Kind := pekStop;
  LEvent.Pid := APid;
  LEvent.CreateTime := ACreate;
  LEvent.TimestampUtc := ATime;
  Pending.Add(LEvent);
end;

function TFakeEventSource.Start(out AError: string; out AAccessDenied: Boolean): Boolean;
begin
  Inc(StartCalls);
  AAccessDenied := StartDenied;
  if StartResult then
    AError := ''
  else
    AError := 'нет доступа';
  Running := StartResult;
  Result := StartResult;
end;

procedure TFakeEventSource.Stop;
begin
  Inc(StopCalls);
  Running := False;
end;

function TFakeEventSource.Drain(out ALost: Integer): TArray<TMHProcessEvent>;
begin
  Result := Pending.ToArray;
  Pending.Clear;
  ALost := Lost;
  Lost := 0;
end;

function TFakeEventSource.IsRunning: Boolean;
begin
  Result := Running;
end;

function Snap(ATime: TDateTime): TMHSnapshot;
var
  LInfo: TMHProcessInfo;
begin
  Result := TMHSnapshot.Create(1, ATime);
  LInfo := TMHProcessInfo.Create(TMHProcessId.Create(500, 1), 'svchost.exe', ATime);
  Result.Processes := [LInfo];
end;

{ TProcessEventTests }

procedure TProcessEventTests.EtwStructures_HaveSdkSizes;
begin
  // Размеры для x64 по заголовкам Windows SDK: ошибка в раскладке ломает ETW незаметно.
  Assert.AreEqual(48, SizeOf(TWnodeHeader));
  Assert.AreEqual(120, SizeOf(TEventTraceProperties));
  Assert.AreEqual(48, SizeOf(TEventTraceHeader));
  Assert.AreEqual(88, SizeOf(TEventTrace));
  Assert.AreEqual(280, SizeOf(TTraceLogfileHeader));
  Assert.AreEqual(448, SizeOf(TEventTraceLogfileW));
  Assert.AreEqual(16, SizeOf(TEventDescriptor));
  Assert.AreEqual(80, SizeOf(TEventHeader));
  Assert.AreEqual(112, SizeOf(TEventRecord));
  Assert.AreEqual(16, SizeOf(TPropertyDataDescriptor));
end;

procedure TProcessEventTests.AccessDenied_UnavailableWithElevationHint_NoRetry;
var
  LSource: TFakeEventSource;
  LCollector: TMHProcessEventCollector;
  LIntf: IMHCollector;
  LResult: TMHCollectionResult;
begin
  LSource := TFakeEventSource.Create;
  LSource.StartResult := False;
  LSource.StartDenied := True;
  LCollector := TMHProcessEventCollector.Create(LSource, TFakeClock.Create(FAKE_NOW));
  LIntf := LCollector;
  LResult := LCollector.Collect(Snap(FAKE_NOW));
  // ETW недоступен, но журнал запусков ведётся по опросу списка процессов — частично.
  Assert.AreEqual(Ord(ssPartial), Ord(LResult.Status.State));
  Assert.IsTrue(LResult.Status.RequiresElevation);
  Assert.IsTrue(LResult.Status.Message.Contains('администратора'));
  LCollector.Collect(Snap(IncHour(FAKE_NOW, 2)));
  Assert.AreEqual(1, LSource.StartCalls, 'Без прав повторять бесполезно');
end;

procedure TProcessEventTests.OtherFailure_RetriedLater;
var
  LSource: TFakeEventSource;
  LCollector: TMHProcessEventCollector;
  LIntf: IMHCollector;
begin
  LSource := TFakeEventSource.Create;
  LSource.StartResult := False;
  LCollector := TMHProcessEventCollector.Create(LSource, TFakeClock.Create(FAKE_NOW));
  LIntf := LCollector;
  Assert.IsFalse(LCollector.Collect(Snap(FAKE_NOW)).Status.RequiresElevation);
  LCollector.Collect(Snap(IncMinute(FAKE_NOW, 1)));
  Assert.AreEqual(1, LSource.StartCalls, 'Не чаще RetryMinutes');
  LSource.StartResult := True;
  Assert.AreEqual(Ord(ssSuccess), Ord(LCollector.Collect(Snap(IncMinute(FAKE_NOW, 11))).Status.State));
  Assert.AreEqual(2, LSource.StartCalls);
end;

procedure TProcessEventTests.ShortLivedLoop_Summarized;
var
  LSource: TFakeEventSource;
  LCollector: TMHProcessEventCollector;
  LIntf: IMHCollector;
  LResult: TMHCollectionResult;
  I: Integer;
  LTime: TDateTime;
begin
  LSource := TFakeEventSource.Create;
  LCollector := TMHProcessEventCollector.Create(LSource, TFakeClock.Create(FAKE_NOW));
  LIntf := LCollector;
  LCollector.Collect(Snap(FAKE_NOW));
  for I := 1 to 10 do
  begin
    LTime := IncMinute(FAKE_NOW, I);
    LSource.AddStart(1000 + I, 500, 7000 + I, LTime, TEMP_EXE);
    LSource.AddStop(1000 + I, 7000 + I, IncSecond(LTime, 2));
  end;
  // Работающий долго экземпляр и однократный запуск другой программы.
  LSource.AddStart(2000, 500, 8000, IncMinute(FAKE_NOW, 11), TEMP_EXE);
  LSource.AddStart(3000, 500, 9000, IncMinute(FAKE_NOW, 11), 'C:\Apps\once.exe');
  LResult := LCollector.Collect(Snap(IncMinute(FAKE_NOW, 12)));
  Assert.AreEqual(Ord(ssSuccess), Ord(LResult.Status.State));
  Assert.AreEqual(1, Integer(Length(LResult.Launches)), 'Однократные запуски не передаются');
  Assert.AreEqual(TEMP_EXE, LResult.Launches[0].ImagePath);
  Assert.AreEqual('updater.exe', LResult.Launches[0].Name);
  Assert.AreEqual(11, LResult.Launches[0].Starts);
  Assert.AreEqual(10, LResult.Launches[0].Exited);
  Assert.AreEqual(10, LResult.Launches[0].ShortLived);
  Assert.AreEqual(2.0, LResult.Launches[0].AverageLifetimeSeconds, 0.01);
  Assert.AreEqual('svchost.exe', LResult.Launches[0].LastParentName, 'Имя родителя — из списка процессов');
  Assert.AreEqual(Cardinal(500), LResult.Launches[0].LastParentPid);
  Assert.AreEqual(12, LResult.Status.ItemCount);
end;

procedure TProcessEventTests.Window_PrunesOldLaunches;
var
  LSource: TFakeEventSource;
  LCollector: TMHProcessEventCollector;
  LIntf: IMHCollector;
begin
  LSource := TFakeEventSource.Create;
  LCollector := TMHProcessEventCollector.Create(LSource, TFakeClock.Create(FAKE_NOW), 30, 15);
  LIntf := LCollector;
  LSource.AddStart(1, 0, 1, FAKE_NOW, TEMP_EXE);
  LSource.AddStart(2, 0, 2, IncMinute(FAKE_NOW, 20), TEMP_EXE);
  LCollector.Collect(Snap(IncMinute(FAKE_NOW, 21)));
  Assert.AreEqual(2, LCollector.TrackedCount);
  LCollector.Collect(Snap(IncMinute(FAKE_NOW, 35)));
  Assert.AreEqual(1, LCollector.TrackedCount, 'Старше окна — удалено');
  LCollector.Collect(Snap(IncMinute(FAKE_NOW, 60)));
  Assert.AreEqual(0, LCollector.TrackedCount);
end;

procedure TProcessEventTests.UnmatchedAndDuplicateEvents_Ignored;
var
  LSource: TFakeEventSource;
  LCollector: TMHProcessEventCollector;
  LIntf: IMHCollector;
  LResult: TMHCollectionResult;
begin
  LSource := TFakeEventSource.Create;
  LCollector := TMHProcessEventCollector.Create(LSource, TFakeClock.Create(FAKE_NOW));
  LIntf := LCollector;
  LSource.AddStop(77, 1, FAKE_NOW);                      // запуск был до начала наблюдения
  LSource.AddStart(5, 0, 10, FAKE_NOW, TEMP_EXE);
  LSource.AddStart(5, 0, 10, FAKE_NOW, TEMP_EXE);        // повтор
  LSource.AddStart(6, 0, 11, FAKE_NOW, '');               // без пути
  LSource.AddStart(5, 0, 12, IncSecond(FAKE_NOW, 5), TEMP_EXE); // тот же PID, другой экземпляр
  LSource.AddStop(5, 10, IncSecond(FAKE_NOW, 1));
  LSource.AddStop(5, 10, IncSecond(FAKE_NOW, 50));        // повторное завершение не меняет время
  LResult := LCollector.Collect(Snap(IncMinute(FAKE_NOW, 1)));
  Assert.AreEqual(2, LCollector.TrackedCount);
  Assert.AreEqual(2, LResult.Launches[0].Starts);
  Assert.AreEqual(1, LResult.Launches[0].ShortLived);
  Assert.AreEqual(1.0, LResult.Launches[0].AverageLifetimeSeconds, 0.01);
end;

procedure TProcessEventTests.SourceStoppedExternally_Restarted;
var
  LSource: TFakeEventSource;
  LCollector: TMHProcessEventCollector;
  LIntf: IMHCollector;
begin
  LSource := TFakeEventSource.Create;
  LCollector := TMHProcessEventCollector.Create(LSource, TFakeClock.Create(FAKE_NOW));
  LIntf := LCollector;
  LCollector.Collect(Snap(FAKE_NOW));
  LSource.Running := False;
  Assert.AreEqual(Ord(ssPartial), Ord(LCollector.Collect(Snap(IncSecond(FAKE_NOW, 2))).Status.State));
  Assert.AreEqual(Ord(ssSuccess), Ord(LCollector.Collect(Snap(IncSecond(FAKE_NOW, 4))).Status.State));
  Assert.AreEqual(2, LSource.StartCalls);
  LSource.Lost := 5;
  Assert.AreEqual(Ord(ssPartial), Ord(LCollector.Collect(Snap(IncSecond(FAKE_NOW, 6))).Status.State),
    'Потери событий отражаются в статусе');
end;

procedure TProcessEventTests.Destroy_StopsSource;
var
  LSource: TFakeEventSource;
  LSourceIntf: IMHProcessEventSource;
  LIntf: IMHCollector;
begin
  LSource := TFakeEventSource.Create;
  LSourceIntf := LSource;
  LIntf := TMHProcessEventCollector.Create(LSourceIntf, TFakeClock.Create(FAKE_NOW));
  LIntf.Collect(Snap(FAKE_NOW));
  LIntf := nil;
  Assert.AreEqual(1, LSource.StopCalls);
  Assert.WillRaise(
    procedure
    begin
      TMHProcessEventCollector.Create(nil, TFakeClock.Create(FAKE_NOW)).Free;
    end, EArgumentNilException);
end;

{ TLaunchRuleTests }

function TLaunchRuleTests.Stat(const APath: string; AStarts, AShort: Integer; const AParent: string): TMHLaunchStat;
begin
  Result := Default(TMHLaunchStat);
  Result.ImagePath := APath;
  Result.Name := ExtractFileName(APath);
  Result.Starts := AStarts;
  Result.ShortLived := AShort;
  Result.Exited := AShort;
  Result.AverageLifetimeSeconds := 2;
  Result.LastParentName := AParent;
  Result.LastParentPid := 500;
  Result.WindowMinutes := 30;
  Result.ShortLivedSeconds := 15;
end;

function TLaunchRuleTests.Analyze(const AStats: array of TMHLaunchStat): TMHFindings;
var
  LSnapshot: TMHSnapshot;
  I: Integer;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  SetLength(LSnapshot.Launches, Length(AStats));
  for I := 0 to High(AStats) do
    LSnapshot.Launches[I] := AStats[I];
  Result := MHAnalyzeLaunches(LSnapshot, TMHRiskThresholds.Default, nil, 'test');
end;

procedure TLaunchRuleTests.LoopFromTemp_NeedsReviewOrHigher;
var
  LFindings: TMHFindings;
begin
  LFindings := Analyze([Stat(TEMP_EXE, 20, 18)]);
  Assert.AreEqual(1, Integer(Length(LFindings)));
  Assert.IsTrue(LFindings[0].Level >= rlNeedsReview, MHRiskLevelToString(LFindings[0].Level));
  Assert.AreEqual('launch:' + TEMP_EXE.ToLower, LFindings[0].Key);
  Assert.AreEqual(Ord(fcSuspicious), Ord(LFindings[0].Category));
  Assert.IsTrue(LFindings[0].Summary.Contains('20 запусков'), LFindings[0].Summary);
  Assert.IsTrue(LFindings[0].Summary.Contains('explorer.exe'));
  Assert.IsTrue(Length(LFindings[0].Recommendations) > 0);
end;

procedure TLaunchRuleTests.MinerName_Suspicious;
var
  LFindings: TMHFindings;
begin
  LFindings := Analyze([Stat('C:\Users\u\AppData\Local\Temp\xmrig.exe', 12, 10)]);
  Assert.AreEqual(1, Integer(Length(LFindings)));
  Assert.IsTrue(LFindings[0].Level >= rlSuspicious, MHRiskLevelToString(LFindings[0].Level));
end;

procedure TLaunchRuleTests.BuildTool_InProgramFiles_NoFinding;
begin
  // Компилятор запускается сотни раз за сборку — это нормально.
  Assert.AreEqual(0, Integer(Length(Analyze([Stat(
    'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\bin\cl.exe', 300, 300)]))));
end;

procedure TLaunchRuleTests.BelowThresholds_NoFinding;
begin
  Assert.AreEqual(0, Integer(Length(Analyze([Stat(TEMP_EXE, MH_LAUNCH_MIN_STARTS - 1, 7)]))));
  Assert.AreEqual(0, Integer(Length(Analyze([Stat(TEMP_EXE, 30, MH_LAUNCH_MIN_SHORT - 1)]))),
    'Долгоживущие запуски — не цикл перезапуска');
  Assert.AreEqual(0, Integer(Length(Analyze([Stat('', 30, 30)]))));
end;

procedure TLaunchRuleTests.ScriptHostFromScheduler_Raised;
var
  LByUser, LByScheduler: TMHFindings;
begin
  LByUser := Analyze([Stat('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', 15, 15, 'explorer.exe')]);
  LByScheduler := Analyze([Stat('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', 15, 15, 'svchost.exe')]);
  Assert.AreEqual(1, Integer(Length(LByScheduler)));
  if Length(LByUser) > 0 then
    Assert.IsTrue(LByScheduler[0].Score > LByUser[0].Score)
  else
    Assert.Pass;
end;

procedure TLaunchRuleTests.Exclusion_Respected;
var
  LSnapshot: TMHSnapshot;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Launches := [Stat(TEMP_EXE, 20, 20)];
  Assert.AreEqual(0, Integer(Length(MHAnalyzeLaunches(LSnapshot, TMHRiskThresholds.Default,
    function(const AKey, ASha256: string): Boolean
    begin
      Result := AKey = MHProgramKey(TEMP_EXE, 'updater.exe');
    end, 'test'))));
end;

{ TEtwIntegrationTests }

procedure TEtwIntegrationTests.RealSession_StartsOrExplainsAccess;
var
  LSource: TMHEtwProcessSource;
  LIntf: IMHProcessEventSource;
  LError, LCmd: string;
  LDenied, LFound: Boolean;
  LEvents: TArray<TMHProcessEvent>;
  LEvent: TMHProcessEvent;
  LLost, I: Integer;
  LStartup: TStartupInfo;
  LInfo: TProcessInformation;
begin
  LSource := TMHEtwProcessSource.Create;
  LIntf := LSource;
  if not LIntf.Start(LError, LDenied) then
  begin
    // Без прав администратора сеанс недоступен — это ожидаемо и объясняется пользователю.
    Assert.IsFalse(TMHWinProcessApi.QueryElevation and not LDenied, 'С правами сеанс должен запускаться: ' + LError);
    Assert.IsNotEmpty(LError);
    Exit;
  end;
  try
    // Запускаем короткий процесс и ждём его событий.
    LCmd := 'cmd.exe /c exit 0';
    UniqueString(LCmd);
    LStartup := Default(TStartupInfo);
    LStartup.cb := SizeOf(LStartup);
    LStartup.dwFlags := STARTF_USESHOWWINDOW;
    LStartup.wShowWindow := SW_HIDE;
    Assert.IsTrue(CreateProcess(nil, PChar(LCmd), nil, nil, False, CREATE_NO_WINDOW, nil, nil, LStartup, LInfo));
    WaitForSingleObject(LInfo.hProcess, 10000);
    LFound := False;
    for I := 1 to 50 do
    begin
      Sleep(100);
      LEvents := LEvents + LIntf.Drain(LLost);
      for LEvent in LEvents do
        if (LEvent.Kind = pekStart) and (LEvent.Pid = LInfo.dwProcessId) then
        begin
          LFound := True;
          Assert.IsTrue(LEvent.ImagePath.EndsWith('cmd.exe', True), LEvent.ImagePath);
          Assert.IsTrue(LEvent.ImagePath.Contains(':\'), 'Путь переведён в формат C:\...: ' + LEvent.ImagePath);
          Assert.AreEqual(GetCurrentProcessId, LEvent.ParentPid);
        end;
      if LFound then
        Break;
    end;
    CloseHandle(LInfo.hThread);
    CloseHandle(LInfo.hProcess);
    Assert.IsTrue(LFound, Format('Событие запуска не получено (событий: %d)', [Length(LEvents)]));
  finally
    LIntf.Stop;
    Assert.IsFalse(LIntf.IsRunning);
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TProcessEventTests);
  TDUnitX.RegisterTestFixture(TLaunchRuleTests);
  TDUnitX.RegisterTestFixture(TEtwIntegrationTests);

end.
