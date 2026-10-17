unit MineHunter.Tests.Fakes;

{
  Безвредные тестовые двойники для контрактов MineHunter.Core.
  Никакого реального вредоносного поведения: только управляемые ответы.
}

interface

uses
  System.SysUtils, System.SyncObjs, System.Generics.Collections,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

type
  ETestCollectorFailure = class(Exception);

  /// Ручные часы: время меняется только явно.
  TFakeClock = class(TInterfacedObject, IMHClock)
  private
    FNow: TDateTime;
    FTick: UInt64;
  public
    constructor Create(ANowUtc: TDateTime);
    function NowUtc: TDateTime;
    function TickMs: UInt64;
    procedure AdvanceMs(AMs: Cardinal);
  end;

  /// Журнал, сохраняющий записи для проверки в тестах (потокобезопасный).
  TRecordingLogger = class(TInterfacedObject, IMHLogger)
  private
    FLock: TCriticalSection;
    FEntries: TList<TMHLogEntry>;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Log(ALevel: TMHLogLevel; const ASource, AMessage: string);
    function Count: Integer;
    function CountOf(ALevel: TMHLogLevel): Integer;
    function ContainsText(const AText: string): Boolean;
  end;

  TFakeCollectorMode = (fcmSuccess, fcmPartial, fcmRaise, fcmRaiseNTimes);

  /// Коллектор с управляемым поведением. Возвращает один синтетический процесс.
  TFakeCollector = class(TInterfacedObject, IMHCollector)
  private
    FSourceId: string;
    FMode: TFakeCollectorMode;
    FFailuresLeft: Integer;
    FCalls: Integer;
    FPid: Cardinal;
    FEmitMetrics: Boolean;
  public
    constructor Create(const ASourceId: string; AMode: TFakeCollectorMode;
      APid: Cardinal = 1000; AFailures: Integer = 0);
    function GetSourceId: string;
    function GetDisplayName: string;
    function Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
    property Calls: Integer read FCalls;
    property Mode: TFakeCollectorMode read FMode write FMode;
    /// False — коллектор не передаёт системных метрик (только процесс).
    property EmitMetrics: Boolean read FEmitMetrics write FEmitMetrics;
  end;

  TFakeAnalyzer = class(TInterfacedObject, IMHAnalyzer)
  private
    FRaise: Boolean;
    FCalls: Integer;
  public
    constructor Create(ARaise: Boolean);
    function GetRulesetVersion: string;
    function Analyze(const ASnapshot: TMHSnapshot;
      const ABaseline: TMHBaseline): TMHFindings;
    property Calls: Integer read FCalls;
  end;

  /// Хранилище в памяти: считает сохранения, может имитировать сбой записи.
  TFakeRepository = class(TInterfacedObject, IMHRepository)
  private
    FLock: TCriticalSection;
    FSaved: TList<TMHSnapshot>;
    FFail: Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    procedure SaveSnapshot(const ASnapshot: TMHSnapshot);
    function LoadHistory(AFromUtc, AToUtc: TDateTime; AMaxCount: Integer): TArray<TMHSnapshot>;
    function SavedCount: Integer;
    property Fail: Boolean read FFail write FFail;
  end;

const
  FAKE_NOW: TDateTime = 46311.5; // 2026-10-16 12:00 UTC

/// Байты, выделенные менеджером памяти RTL (для тестов на утечки).
function MHTestAllocatedBytes: Int64;

implementation

function MHTestAllocatedBytes: Int64;
var
  LState: TMemoryManagerState;
  I: Integer;
begin
  {$WARN SYMBOL_PLATFORM OFF}
  GetMemoryManagerState(LState);
  {$WARN SYMBOL_PLATFORM ON}
  Result := Int64(LState.TotalAllocatedMediumBlockSize) + Int64(LState.TotalAllocatedLargeBlockSize);
  for I := Low(LState.SmallBlockTypeStates) to High(LState.SmallBlockTypeStates) do
    Inc(Result, Int64(LState.SmallBlockTypeStates[I].AllocatedBlockCount) *
      LState.SmallBlockTypeStates[I].UseableBlockSize);
end;

{ TFakeClock }

constructor TFakeClock.Create(ANowUtc: TDateTime);
begin
  inherited Create;
  FNow := ANowUtc;
  FTick := 1000;
end;

function TFakeClock.NowUtc: TDateTime;
begin
  Result := FNow;
end;

function TFakeClock.TickMs: UInt64;
begin
  Result := FTick;
end;

procedure TFakeClock.AdvanceMs(AMs: Cardinal);
begin
  Inc(FTick, AMs);
  FNow := FNow + AMs / MSecsPerDay;
end;

{ TRecordingLogger }

constructor TRecordingLogger.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FEntries := TList<TMHLogEntry>.Create;
end;

destructor TRecordingLogger.Destroy;
begin
  FEntries.Free;
  FLock.Free;
  inherited;
end;

procedure TRecordingLogger.Log(ALevel: TMHLogLevel; const ASource, AMessage: string);
var
  LEntry: TMHLogEntry;
begin
  LEntry.TimestampUtc := 0;
  LEntry.Level := ALevel;
  LEntry.Source := ASource;
  LEntry.Message := AMessage;
  FLock.Enter;
  try
    FEntries.Add(LEntry);
  finally
    FLock.Leave;
  end;
end;

function TRecordingLogger.Count: Integer;
begin
  FLock.Enter;
  try
    Result := FEntries.Count;
  finally
    FLock.Leave;
  end;
end;

function TRecordingLogger.CountOf(ALevel: TMHLogLevel): Integer;
var
  LEntry: TMHLogEntry;
begin
  Result := 0;
  FLock.Enter;
  try
    for LEntry in FEntries do
      if LEntry.Level = ALevel then
        Inc(Result);
  finally
    FLock.Leave;
  end;
end;

function TRecordingLogger.ContainsText(const AText: string): Boolean;
var
  LEntry: TMHLogEntry;
begin
  FLock.Enter;
  try
    for LEntry in FEntries do
      if LEntry.Message.Contains(AText) then
        Exit(True);
  finally
    FLock.Leave;
  end;
  Result := False;
end;

{ TFakeCollector }

constructor TFakeCollector.Create(const ASourceId: string; AMode: TFakeCollectorMode;
  APid: Cardinal; AFailures: Integer);
begin
  inherited Create;
  FSourceId := ASourceId;
  FMode := AMode;
  FPid := APid;
  FFailuresLeft := AFailures;
  FEmitMetrics := True;
end;

function TFakeCollector.GetSourceId: string;
begin
  Result := FSourceId;
end;

function TFakeCollector.GetDisplayName: string;
begin
  Result := 'Fake ' + FSourceId;
end;

function TFakeCollector.Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
var
  LInfo: TMHProcessInfo;
  LState: TMHSourceState;
begin
  Inc(FCalls);
  case FMode of
    fcmRaise:
      raise ETestCollectorFailure.Create('simulated failure');
    fcmRaiseNTimes:
      if FFailuresLeft > 0 then
      begin
        Dec(FFailuresLeft);
        raise ETestCollectorFailure.Create('simulated transient failure');
      end;
  end;
  if FMode = fcmPartial then
    LState := ssPartial
  else
    LState := ssSuccess;
  LInfo := TMHProcessInfo.Create(TMHProcessId.Create(FPid, 1234567), 'fake.exe',
    ASnapshot.TimestampUtc);
  LInfo.Cpu := TMHMetric.Available(mkCpuPercent, 12.5, ASnapshot.TimestampUtc);
  LInfo.SourceId := FSourceId;
  Result := TMHCollectionResult.Create(
    TMHSourceStatus.Create(FSourceId, LState, '', ASnapshot.TimestampUtc));
  Result.Status.ItemCount := 1;
  Result.Processes := [LInfo];
  if FEmitMetrics then
    Result.Metrics := [TMHMetric.Available(mkCpuPercent, 5, ASnapshot.TimestampUtc)];
end;

{ TFakeRepository }

constructor TFakeRepository.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FSaved := TList<TMHSnapshot>.Create;
end;

destructor TFakeRepository.Destroy;
begin
  FSaved.Free;
  FLock.Free;
  inherited;
end;

procedure TFakeRepository.SaveSnapshot(const ASnapshot: TMHSnapshot);
begin
  if FFail then
    raise EMHError.Create('simulated disk full');
  FLock.Enter;
  try
    FSaved.Add(ASnapshot);
  finally
    FLock.Leave;
  end;
end;

function TFakeRepository.LoadHistory(AFromUtc, AToUtc: TDateTime;
  AMaxCount: Integer): TArray<TMHSnapshot>;
begin
  FLock.Enter;
  try
    Result := FSaved.ToArray;
  finally
    FLock.Leave;
  end;
end;

function TFakeRepository.SavedCount: Integer;
begin
  FLock.Enter;
  try
    Result := FSaved.Count;
  finally
    FLock.Leave;
  end;
end;

{ TFakeAnalyzer }

constructor TFakeAnalyzer.Create(ARaise: Boolean);
begin
  inherited Create;
  FRaise := ARaise;
end;

function TFakeAnalyzer.GetRulesetVersion: string;
begin
  Result := 'test-1';
end;

function TFakeAnalyzer.Analyze(const ASnapshot: TMHSnapshot;
  const ABaseline: TMHBaseline): TMHFindings;
var
  LFinding: TMHFinding;
  LInfo: TMHProcessInfo;
begin
  Inc(FCalls);
  if FRaise then
    raise EMHError.Create('simulated analyzer failure');
  LFinding := Default(TMHFinding);
  LFinding.Title := 'test finding';
  LFinding.Summary := 'Тестовая находка. Это повод для проверки, а не диагноз.';
  LFinding.Key := 'test:finding';
  LFinding.Category := fcSuspicious;
  LFinding.Score := 40;
  LFinding.RawScore := 40;
  LFinding.Level := TMHRiskThresholds.Default.LevelOf(40);
  LFinding.Confidence := 0.9;
  LFinding.RulesetVersion := GetRulesetVersion;
  LFinding.DetectedAtUtc := ASnapshot.TimestampUtc;
  LFinding.Evidence := [TMHEvidence.Create('TEST', 'synthetic', 40)];
  LFinding.Recommendations := ['проверить'];
  // Находка привязывается к процессу chrome.exe, если он есть в снимке.
  for LInfo in ASnapshot.Processes do
    if SameText(LInfo.Name, 'chrome.exe') then
    begin
      LFinding.Process := LInfo.Id;
      LFinding.ProcessName := LInfo.Name;
      LFinding.ImagePath := LInfo.ImagePath;
      LFinding.ParentPid := LInfo.ParentPid;
      Break;
    end;
  Result := [LFinding];
end;

end.
