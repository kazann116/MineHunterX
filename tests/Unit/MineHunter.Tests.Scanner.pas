unit MineHunter.Tests.Scanner;

interface

uses
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Core.Scanner,
  MineHunter.Tests.Fakes;

type
  [TestFixture]
  [Category('Unit')]
  TScannerTests = class
  private
    FClock: IMHClock;
    FLogger: TRecordingLogger;
    FLoggerIntf: IMHLogger;
    function NewScanner(const ACollectors: TArray<IMHCollector>;
      const AAnalyzer: IMHAnalyzer = nil): TMHScanner;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Create_InvalidArguments_Raise;
    [Test] procedure Options_AreNormalized;
    [Test] procedure ScanOnce_MergesAllCollectors;
    [Test] procedure ScanOnce_SequenceIncrements;
    [Test] procedure DuplicateSystemMetric_FirstSourceWins_LoggedOnce;
    [Test] procedure ScanOnce_PartialStatusIsPreserved;
    [Test] procedure FailingCollector_DoesNotAffectOthers;
    [Test] procedure TransientFailure_BackoffThenRecovery;
    [Test] procedure PermanentFailure_BackoffGrowsAndIsCapped;
    [Test] procedure Analyzer_FindingsAreDelivered;
    [Test] procedure AnalyzerFailure_IsLoggedAndSnapshotDelivered;
    [Test] procedure HandlerException_IsLoggedNotPropagated;
    [Test] procedure Baseline_RoundTrips;
    [Test] procedure Repository_SavesEachSnapshot_AndReportsStatus;
    [Test] procedure RepositoryFailure_DoesNotStopScanning;
  end;

  [TestFixture]
  [Category('Threading')]
  TScannerThreadTests = class
  public
    [Test] procedure WorkerDispatch_DeliversSnapshots;
    [Test] procedure StartStop_AreIdempotent;
    [Test] procedure MainThreadDispatch_DeliveredViaSynchronizeQueue;
    [Test] procedure MainThreadDispatch_PendingEventsCancelledByStop;
    [Test] procedure FreeWhileRunning_StopsCleanly;
  end;

  [TestFixture]
  [Category('Leaks')]
  TScannerLeakTests = class
  public
    [Test] procedure RepeatedCreateScanFree_DoesNotGrowHeap;
  end;

implementation

uses
  System.SysUtils, System.Classes, System.SyncObjs, System.Diagnostics,
  MineHunter.Core.Logging;

function Collectors(const AItems: array of IMHCollector): TArray<IMHCollector>;
var
  I: Integer;
begin
  SetLength(Result, Length(AItems));
  for I := 0 to High(AItems) do
    Result[I] := AItems[I];
end;

{ TScannerTests }

procedure TScannerTests.Setup;
begin
  FClock := TFakeClock.Create(FAKE_NOW);
  FLogger := TRecordingLogger.Create;
  FLoggerIntf := FLogger;
end;

procedure TScannerTests.TearDown;
begin
  FLoggerIntf := nil;
  FLogger := nil;
  FClock := nil;
end;

function TScannerTests.NewScanner(const ACollectors: TArray<IMHCollector>;
  const AAnalyzer: IMHAnalyzer): TMHScanner;
begin
  Result := TMHScanner.Create(ACollectors, AAnalyzer, FClock, FLoggerIntf);
end;

procedure TScannerTests.Create_InvalidArguments_Raise;
var
  LCollector: IMHCollector;
begin
  LCollector := TFakeCollector.Create('a', fcmSuccess);
  Assert.WillRaise(
    procedure
    begin
      TMHScanner.Create(nil, nil, FClock, FLoggerIntf).Free;
    end, EArgumentException);
  Assert.WillRaise(
    procedure
    begin
      TMHScanner.Create(Collectors([LCollector]), nil, nil, FLoggerIntf).Free;
    end, EArgumentNilException);
  Assert.WillRaise(
    procedure
    begin
      TMHScanner.Create(Collectors([LCollector]), nil, FClock, nil).Free;
    end, EArgumentNilException);
  Assert.WillRaise(
    procedure
    begin
      TMHScanner.Create(Collectors([LCollector, nil]), nil, FClock, FLoggerIntf).Free;
    end, EArgumentNilException);
end;

procedure TScannerTests.Options_AreNormalized;
var
  LScanner: TMHScanner;
  LOptions: TMHScannerOptions;
begin
  LScanner := NewScanner(Collectors([TFakeCollector.Create('a', fcmSuccess)]));
  try
    LOptions := TMHScannerOptions.Default;
    LOptions.IntervalMs := 1;
    LOptions.MaxConsecutiveFailures := 0;
    LOptions.MaxBackoffCycles := -5;
    LScanner.Options := LOptions;
    Assert.AreEqual<Cardinal>(TMHScannerOptions.MinIntervalMs, LScanner.Options.IntervalMs);
    Assert.AreEqual(1, LScanner.Options.MaxConsecutiveFailures);
    Assert.AreEqual(1, LScanner.Options.MaxBackoffCycles);

    LOptions.IntervalMs := High(Cardinal);
    LScanner.Options := LOptions;
    Assert.AreEqual<Cardinal>(TMHScannerOptions.MaxIntervalMs, LScanner.Options.IntervalMs);
  finally
    LScanner.Free;
  end;
end;

procedure TScannerTests.ScanOnce_MergesAllCollectors;
var
  LScanner: TMHScanner;
  LSnapshot: TMHSnapshot;
begin
  LScanner := NewScanner(Collectors([TFakeCollector.Create('a', fcmSuccess, 1),
    TFakeCollector.Create('b', fcmSuccess, 2)]));
  try
    LSnapshot := LScanner.ScanOnce;
    Assert.AreEqual<UInt64>(1, LSnapshot.Sequence);
    Assert.AreEqual(FAKE_NOW, LSnapshot.TimestampUtc, 1e-9);
    Assert.AreEqual(2, Integer(Length(LSnapshot.Processes)));
    Assert.AreEqual(1, Integer(Length(LSnapshot.Metrics)),
      'Системная метрика одного вида от двух источников хранится один раз');
    Assert.AreEqual(2, Integer(Length(LSnapshot.Sources)));
    Assert.AreEqual('a', LSnapshot.Sources[0].SourceId);
    Assert.AreEqual('b', LSnapshot.Sources[1].SourceId);
    Assert.AreEqual<TMHSourceState>(ssSuccess, LSnapshot.Sources[1].State);
  finally
    LScanner.Free;
  end;
end;

procedure TScannerTests.DuplicateSystemMetric_FirstSourceWins_LoggedOnce;
var
  LScanner: TMHScanner;
  LSecond: TFakeCollector;
begin
  LSecond := TFakeCollector.Create('b', fcmSuccess, 2);
  LScanner := NewScanner(Collectors([TFakeCollector.Create('a', fcmSuccess, 1), LSecond]));
  try
    Assert.AreEqual(1, Integer(Length(LScanner.ScanOnce.Metrics)));
    LScanner.ScanOnce;
    Assert.AreEqual(1, FLogger.CountOf(llWarning), 'Конфликт источников журналируется один раз');
    LSecond.EmitMetrics := False;
    Assert.AreEqual(1, Integer(Length(LScanner.ScanOnce.Metrics)));
  finally
    LScanner.Free;
  end;
end;

procedure TScannerTests.ScanOnce_SequenceIncrements;
var
  LScanner: TMHScanner;
begin
  LScanner := NewScanner(Collectors([TFakeCollector.Create('a', fcmSuccess)]));
  try
    Assert.AreEqual<UInt64>(1, LScanner.ScanOnce.Sequence);
    Assert.AreEqual<UInt64>(2, LScanner.ScanOnce.Sequence);
    Assert.AreEqual<UInt64>(3, LScanner.ScanOnce.Sequence);
  finally
    LScanner.Free;
  end;
end;

procedure TScannerTests.ScanOnce_PartialStatusIsPreserved;
var
  LScanner: TMHScanner;
  LSnapshot: TMHSnapshot;
begin
  LScanner := NewScanner(Collectors([TFakeCollector.Create('p', fcmPartial)]));
  try
    LSnapshot := LScanner.ScanOnce;
    Assert.AreEqual<TMHSourceState>(ssPartial, LSnapshot.Sources[0].State);
    Assert.AreEqual(1, Integer(Length(LSnapshot.Processes)), 'Частичные данные не должны теряться');
  finally
    LScanner.Free;
  end;
end;

procedure TScannerTests.FailingCollector_DoesNotAffectOthers;
var
  LScanner: TMHScanner;
  LSnapshot: TMHSnapshot;
begin
  LScanner := NewScanner(Collectors([TFakeCollector.Create('bad', fcmRaise, 1),
    TFakeCollector.Create('good', fcmSuccess, 2)]));
  try
    LSnapshot := LScanner.ScanOnce;
    Assert.AreEqual<TMHSourceState>(ssError, LSnapshot.Sources[0].State);
    Assert.IsTrue(LSnapshot.Sources[0].Message.Contains('simulated failure'));
    Assert.AreEqual<TMHSourceState>(ssSuccess, LSnapshot.Sources[1].State);
    Assert.AreEqual(1, Integer(Length(LSnapshot.Processes)));
    Assert.AreEqual<Cardinal>(2, LSnapshot.Processes[0].Id.Pid);
    Assert.AreEqual(1, FLogger.CountOf(llWarning));
  finally
    LScanner.Free;
  end;
end;

procedure TScannerTests.TransientFailure_BackoffThenRecovery;
var
  LCollector: TFakeCollector;
  LIntf: IMHCollector;
  LScanner: TMHScanner;
  LOptions: TMHScannerOptions;
  I: Integer;
  LSnapshot: TMHSnapshot;
begin
  LCollector := TFakeCollector.Create('flaky', fcmRaiseNTimes, 1, 3);
  LIntf := LCollector;
  LScanner := NewScanner(Collectors([LIntf]));
  try
    LOptions := TMHScannerOptions.Default;
    LOptions.MaxConsecutiveFailures := 3;
    LScanner.Options := LOptions;
    for I := 1 to 3 do
      Assert.AreEqual<TMHSourceState>(ssError, LScanner.ScanOnce.Sources[0].State);
    // После 3 ошибок подряд источник пропускает один цикл.
    LSnapshot := LScanner.ScanOnce;
    Assert.AreEqual<TMHSourceState>(ssUnavailable, LSnapshot.Sources[0].State);
    Assert.IsNotEmpty(LSnapshot.Sources[0].Message);
    Assert.AreEqual(3, LCollector.Calls, 'Во время паузы коллектор не вызывается');
    // Затем опрос возобновляется, и источник восстанавливается.
    LSnapshot := LScanner.ScanOnce;
    Assert.AreEqual<TMHSourceState>(ssSuccess, LSnapshot.Sources[0].State);
    Assert.AreEqual(4, LCollector.Calls);
    Assert.AreEqual<TMHSourceState>(ssSuccess, LScanner.ScanOnce.Sources[0].State);
  finally
    LScanner.Free;
  end;
end;

procedure TScannerTests.PermanentFailure_BackoffGrowsAndIsCapped;
var
  LCollector: TFakeCollector;
  LIntf: IMHCollector;
  LScanner: TMHScanner;
  LOptions: TMHScannerOptions;
  I: Integer;
  LStates: string;
begin
  LCollector := TFakeCollector.Create('dead', fcmRaise);
  LIntf := LCollector;
  LScanner := NewScanner(Collectors([LIntf]));
  try
    LOptions := TMHScannerOptions.Default;
    LOptions.MaxConsecutiveFailures := 1;
    LOptions.MaxBackoffCycles := 4;
    LScanner.Options := LOptions;
    LStates := '';
    for I := 1 to 16 do
      case LScanner.ScanOnce.Sources[0].State of
        ssError: LStates := LStates + 'E';
        ssUnavailable: LStates := LStates + 'u';
      else
        LStates := LStates + '?';
      end;
    // Паузы: 1, 2, 4, затем не более MaxBackoffCycles = 4.
    Assert.AreEqual('EuEuuEuuuuEuuuuE', LStates);
    Assert.AreEqual(5, LCollector.Calls);
  finally
    LScanner.Free;
  end;
end;

procedure TScannerTests.Analyzer_FindingsAreDelivered;
var
  LAnalyzer: TFakeAnalyzer;
  LAnalyzerIntf: IMHAnalyzer;
  LScanner: TMHScanner;
  LFindings: Integer;
  LSnapshots: Integer;
begin
  LAnalyzer := TFakeAnalyzer.Create(False);
  LAnalyzerIntf := LAnalyzer;
  LScanner := NewScanner(Collectors([TFakeCollector.Create('a', fcmSuccess)]), LAnalyzerIntf);
  try
    LFindings := 0;
    LSnapshots := 0;
    LScanner.OnSnapshot :=
      procedure(const ASnapshot: TMHSnapshot)
      begin
        Inc(LSnapshots);
      end;
    LScanner.OnFinding :=
      procedure(const AFinding: TMHFinding)
      begin
        Inc(LFindings);
        Assert.AreEqual('test-1', AFinding.RulesetVersion);
        Assert.AreEqual<TMHRiskLevel>(rlNeedsReview, AFinding.Level);
      end;
    LScanner.ScanOnce;
    LScanner.ScanOnce;
    Assert.AreEqual(2, LSnapshots);
    Assert.AreEqual(2, LFindings);
    Assert.AreEqual(2, LAnalyzer.Calls);
    // Сканер перехватывает исключения обработчиков, поэтому провал Assert
    // внутри OnFinding виден только как ошибка в журнале.
    Assert.AreEqual(0, FLogger.CountOf(llError));
  finally
    LScanner.Free;
  end;
end;

procedure TScannerTests.AnalyzerFailure_IsLoggedAndSnapshotDelivered;
var
  LScanner: TMHScanner;
  LSnapshots: Integer;
begin
  LScanner := NewScanner(Collectors([TFakeCollector.Create('a', fcmSuccess)]),
    TFakeAnalyzer.Create(True));
  try
    LSnapshots := 0;
    LScanner.OnSnapshot :=
      procedure(const ASnapshot: TMHSnapshot)
      begin
        Inc(LSnapshots);
      end;
    LScanner.ScanOnce;
    Assert.AreEqual(1, LSnapshots);
    Assert.IsTrue(FLogger.ContainsText('simulated analyzer failure'));
  finally
    LScanner.Free;
  end;
end;

procedure TScannerTests.HandlerException_IsLoggedNotPropagated;
var
  LScanner: TMHScanner;
begin
  LScanner := NewScanner(Collectors([TFakeCollector.Create('a', fcmSuccess)]));
  try
    LScanner.OnSnapshot :=
      procedure(const ASnapshot: TMHSnapshot)
      begin
        raise ETestCollectorFailure.Create('handler boom');
      end;
    LScanner.ScanOnce;
    Assert.IsTrue(FLogger.ContainsText('handler boom'));
    Assert.AreEqual(1, FLogger.CountOf(llError));
  finally
    LScanner.Free;
  end;
end;

procedure TScannerTests.Baseline_RoundTrips;
var
  LScanner: TMHScanner;
  LBaseline: TMHBaseline;
begin
  LScanner := NewScanner(Collectors([TFakeCollector.Create('a', fcmSuccess)]));
  try
    Assert.AreEqual(0, LScanner.Baseline.SampleCount);
    LBaseline := TMHBaseline.Empty;
    LBaseline.Context := wcGaming;
    LBaseline.SampleCount := 10;
    LScanner.Baseline := LBaseline;
    Assert.AreEqual<TMHWorkContext>(wcGaming, LScanner.Baseline.Context);
    Assert.AreEqual(10, LScanner.Baseline.SampleCount);
  finally
    LScanner.Free;
  end;
end;

procedure TScannerTests.Repository_SavesEachSnapshot_AndReportsStatus;
var
  LScanner: TMHScanner;
  LRepo: TFakeRepository;
  LRepoIntf: IMHRepository;
  LStatus: TMHSourceStatus;
begin
  LRepo := TFakeRepository.Create;
  LRepoIntf := LRepo;
  LScanner := NewScanner(Collectors([TFakeCollector.Create('a', fcmSuccess)]));
  try
    Assert.IsTrue(LScanner.Repository = nil);
    Assert.IsFalse(LScanner.ScanOnce.FindSource(TMHScanner.StorageSourceId, LStatus),
      'Без хранилища статус storage не добавляется');
    LScanner.Repository := LRepoIntf;
    Assert.IsTrue(LScanner.ScanOnce.FindSource(TMHScanner.StorageSourceId, LStatus));
    Assert.AreEqual<TMHSourceState>(ssSuccess, LStatus.State);
    LScanner.ScanOnce;
    Assert.AreEqual(2, LRepo.SavedCount);
  finally
    LScanner.Free;
  end;
end;

procedure TScannerTests.RepositoryFailure_DoesNotStopScanning;
var
  LScanner: TMHScanner;
  LRepo: TFakeRepository;
  LRepoIntf: IMHRepository;
  LSnapshot: TMHSnapshot;
  LStatus: TMHSourceStatus;
begin
  LRepo := TFakeRepository.Create;
  LRepoIntf := LRepo;
  LRepo.Fail := True;
  LScanner := NewScanner(Collectors([TFakeCollector.Create('a', fcmSuccess)]));
  try
    LScanner.Repository := LRepoIntf;
    LSnapshot := LScanner.ScanOnce;
    Assert.AreEqual(1, Integer(Length(LSnapshot.Processes)), 'Сбор данных продолжается');
    Assert.IsTrue(LSnapshot.FindSource(TMHScanner.StorageSourceId, LStatus));
    Assert.AreEqual<TMHSourceState>(ssError, LStatus.State);
    Assert.IsTrue(LStatus.Message.Contains('simulated disk full'));
    LScanner.ScanOnce;
    LScanner.ScanOnce;
    Assert.AreEqual(1, FLogger.CountOf(llError), 'Повторяющийся сбой журналируется один раз');

    LRepo.Fail := False;
    Assert.IsTrue(LScanner.ScanOnce.FindSource(TMHScanner.StorageSourceId, LStatus));
    Assert.AreEqual<TMHSourceState>(ssSuccess, LStatus.State);
    Assert.IsTrue(FLogger.ContainsText('восстановлена'));
  finally
    LScanner.Free;
  end;
end;

{ TScannerThreadTests }

function NewThreadedScanner(ADispatch: TMHEventDispatch): TMHScanner;
var
  LOptions: TMHScannerOptions;
begin
  Result := TMHScanner.Create(Collectors([TFakeCollector.Create('a', fcmSuccess)]), nil,
    TMHSystemClock.Create, TMHNullLogger.Create);
  LOptions := TMHScannerOptions.Default;
  LOptions.IntervalMs := TMHScannerOptions.MinIntervalMs;
  LOptions.EventDispatch := ADispatch;
  Result.Options := LOptions;
end;

procedure TScannerThreadTests.WorkerDispatch_DeliversSnapshots;
var
  LScanner: TMHScanner;
  LEvent: TEvent;
  LCount: Integer;
begin
  LEvent := TEvent.Create(nil, True, False, '');
  LScanner := NewThreadedScanner(edWorkerThread);
  try
    LCount := 0;
    LScanner.OnSnapshot :=
      procedure(const ASnapshot: TMHSnapshot)
      begin
        if TInterlocked.Increment(LCount) >= 2 then
          LEvent.SetEvent;
      end;
    LScanner.Start;
    Assert.IsTrue(LScanner.IsRunning);
    Assert.AreEqual(wrSignaled, LEvent.WaitFor(5000), 'Сканер должен выдать минимум 2 снимка');
    LScanner.Stop;
    Assert.IsFalse(LScanner.IsRunning);
  finally
    LScanner.Free;
    LEvent.Free;
  end;
end;

procedure TScannerThreadTests.StartStop_AreIdempotent;
var
  LScanner: TMHScanner;
begin
  LScanner := NewThreadedScanner(edWorkerThread);
  try
    LScanner.Stop;
    LScanner.Start;
    LScanner.Start;
    Assert.IsTrue(LScanner.IsRunning);
    LScanner.Stop;
    LScanner.Stop;
    Assert.IsFalse(LScanner.IsRunning);
    LScanner.Start;
    Assert.IsTrue(LScanner.IsRunning, 'Повторный запуск после остановки должен работать');
  finally
    LScanner.Free;
  end;
end;

procedure TScannerThreadTests.MainThreadDispatch_DeliveredViaSynchronizeQueue;
var
  LScanner: TMHScanner;
  LCount: Integer;
  LMainThread: Boolean;
  LWatch: TStopwatch;
begin
  LScanner := NewThreadedScanner(edMainThread);
  try
    LCount := 0;
    LMainThread := True;
    LScanner.OnSnapshot :=
      procedure(const ASnapshot: TMHSnapshot)
      begin
        Inc(LCount);
        LMainThread := LMainThread and (TThread.Current.ThreadID = MainThreadID);
      end;
    LScanner.Start;
    LWatch := TStopwatch.StartNew;
    while (LCount = 0) and (LWatch.ElapsedMilliseconds < 5000) do
      CheckSynchronize(50);
    LScanner.Stop;
    Assert.IsTrue(LCount > 0, 'Событие должно быть доставлено через очередь главного потока');
    Assert.IsTrue(LMainThread, 'Обработчик должен вызываться в главном потоке');
  finally
    LScanner.Free;
  end;
end;

procedure TScannerThreadTests.MainThreadDispatch_PendingEventsCancelledByStop;
var
  LScanner: TMHScanner;
  LCount: Integer;
begin
  LScanner := NewThreadedScanner(edMainThread);
  try
    LCount := 0;
    LScanner.OnSnapshot :=
      procedure(const ASnapshot: TMHSnapshot)
      begin
        Inc(LCount);
      end;
    LScanner.Start;
    // Главный поток не обрабатывает очередь — события накапливаются.
    Sleep(700);
    LScanner.Stop;
    CheckSynchronize(0);
    Assert.AreEqual(0, LCount, 'После Stop недоставленные события должны быть отменены');
  finally
    LScanner.Free;
  end;
end;

procedure TScannerThreadTests.FreeWhileRunning_StopsCleanly;
var
  LScanner: TMHScanner;
begin
  LScanner := NewThreadedScanner(edMainThread);
  LScanner.Start;
  Sleep(100);
  LScanner.Free;
  CheckSynchronize(0);
  Assert.Pass;
end;

{ TScannerLeakTests }

procedure RunScannerCycle;
var
  LScanner: TMHScanner;
begin
  LScanner := TMHScanner.Create(Collectors([TFakeCollector.Create('a', fcmSuccess),
    TFakeCollector.Create('b', fcmRaise)]), TFakeAnalyzer.Create(False),
    TFakeClock.Create(FAKE_NOW), TMHNullLogger.Create);
  try
    LScanner.OnSnapshot :=
      procedure(const ASnapshot: TMHSnapshot)
      begin
      end;
    LScanner.ScanOnce;
    LScanner.ScanOnce;
  finally
    LScanner.Free;
  end;
end;

procedure TScannerLeakTests.RepeatedCreateScanFree_DoesNotGrowHeap;
const
  ITERATIONS = 200;
  TOLERANCE_BYTES = 16 * 1024;
var
  LBefore, LAfter: Int64;
  I: Integer;
begin
  RunScannerCycle; // прогрев: однократные выделения RTL
  LBefore := MHTestAllocatedBytes;
  for I := 1 to ITERATIONS do
    RunScannerCycle;
  LAfter := MHTestAllocatedBytes;
  Assert.IsTrue(LAfter - LBefore < TOLERANCE_BYTES,
    Format('Рост кучи %d байт за %d циклов — вероятна утечка', [LAfter - LBefore, ITERATIONS]));
end;

initialization
  TDUnitX.RegisterTestFixture(TScannerTests);
  TDUnitX.RegisterTestFixture(TScannerThreadTests);
  TDUnitX.RegisterTestFixture(TScannerLeakTests);

end.
