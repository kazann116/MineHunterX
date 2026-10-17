unit MineHunter.Tests.NetworkContext;

{
  Unit: сетевой коллектор и коллектор контекста на управляемых двойниках API,
  а также чистые функции форматирования адресов, портов и состояний TCP.
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.Interfaces,
  MineHunter.Collectors.Network, MineHunter.Collectors.Context;

type
  /// Управляемый двойник IMHNetworkApi: каждая из четырёх таблиц может
  /// вернуть отказ или исключение.
  TFakeNetworkApi = class(TInterfacedObject, IMHNetworkApi)
  public
    /// Индекс: 0 — TCP IPv4, 1 — TCP IPv6, 2 — UDP IPv4, 3 — UDP IPv6.
    Tables: array[0..3] of TArray<TMHNetConnection>;
    Fail: array[0..3] of Boolean;
    RaiseOn: array[0..3] of Boolean;
    function ReadTcp(AIPv6: Boolean; out AItems: TArray<TMHNetConnection>;
      out AError: string): Boolean;
    function ReadUdp(AIPv6: Boolean; out AItems: TArray<TMHNetConnection>;
      out AError: string): Boolean;
    function Read(AIndex: Integer; out AItems: TArray<TMHNetConnection>;
      out AError: string): Boolean;
  end;

  /// Управляемый двойник IMHContextApi с журналом запросов командных строк.
  TFakeContextApi = class(TInterfacedObject, IMHContextApi)
  private
    FLines: TDictionary<Cardinal, string>;
    FRequests: TList<TArray<Cardinal>>;
  public
    HasIdle: Boolean;
    IdleSeconds: Cardinal;
    HasFullscreen: Boolean;
    Fullscreen: Boolean;
    Foreground: Cardinal;
    Visible: TArray<Cardinal>;
    FailCommandLines: Boolean;
    constructor Create;
    destructor Destroy; override;
    function UserIdleSeconds(out ASeconds: Cardinal): Boolean;
    function ForegroundPid: Cardinal;
    function FullscreenState(out AFullscreen: Boolean): Boolean;
    function VisibleWindowPids: TArray<Cardinal>;
    function ReadCommandLines(const APids: TArray<Cardinal>;
      out ALines: TArray<TMHProcessDetail>; out AError: string): Boolean;
    procedure SetLine(APid: Cardinal; const ALine: string);
    function RequestCount: Integer;
    function LastRequest: TArray<Cardinal>;
  end;

  [TestFixture]
  [Category('Unit')]
  TNetworkFormatTests = class
  public
    [Test] procedure IPv4_NetworkByteOrder;
    [Test] procedure IPv6_Unspecified;
    [Test] procedure IPv6_Loopback;
    [Test] procedure IPv6_LinkLocal;
    [Test] procedure IPv6_FullAddress_NoCompression;
    [Test] procedure IPv6_SingleZeroGroup_NotCompressed;
    [Test] procedure IPv6_LongestRunCompressed;
    [Test] procedure IPv6_EqualRuns_FirstCompressed;
    [Test] procedure IPv6_TrailingZeros;
    [Test] procedure IPv6_LowercaseWithoutLeadingZeros;
    [Test] procedure IPv6_IPv4Mapped;
    [Test] procedure IPv6_WrongLength_Raises;
    [Test] procedure Port_NetworkToHost;
    [Test] procedure TcpStateNames;
  end;

  [TestFixture]
  [Category('Unit')]
  TNetworkCollectorTests = class
  private
    FApi: TFakeNetworkApi;
    FApiIntf: IMHNetworkApi;
    FCollector: IMHCollector;
    procedure CreateWithNilApi;
    procedure CreateWithNilClock;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Create_NilArguments_Raise;
    [Test] procedure AllTablesOk_IsSuccess_WithAllConnections;
    [Test] procedure OneTableFails_IsPartial_OthersReturned;
    [Test] procedure AllTablesFail_IsError_NoException;
    [Test] procedure TableRaises_TreatedAsFailure;
    [Test] procedure ResultMatchesCollectorContract;
  end;

  [TestFixture]
  [Category('Unit')]
  TContextCollectorTests = class
  private
    FApi: TFakeContextApi;
    FApiIntf: IMHContextApi;
    FCollector: TMHContextCollector;
    FCollectorIntf: IMHCollector;
    procedure CreateWithNilApi;
    procedure CreateWithNilClock;
    procedure CreateWithZeroThreshold;
    function Collect(const AProcesses: array of TMHProcessInfo): TMHCollectionResult;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Create_InvalidArguments_Raise;
    [Test] procedure ShortIdle_IsWork;
    [Test] procedure IdleAtThreshold_IsIdle;
    [Test] procedure Fullscreen_IsGaming_EvenWhenIdle;
    [Test] procedure IdleUnavailable_IsUnknown_Partial;
    [Test] procedure FullscreenUnavailable_IsPartial_ClassifiedByIdle;
    [Test] procedure ContextFields_AreCopied;
    [Test] procedure CommandLine_RequestedOnce_CachedByIdentity;
    [Test] procedure ReusedPid_DifferentCreateTime_IsRequeried;
    [Test] procedure CapPerCycle_HighestCpuFirst_RestNextCycle;
    [Test] procedure ExitedProcesses_ArePrunedFromCache;
    [Test] procedure CommandLineFailure_IsPartial_ContextStillReturned_Retried;
    [Test] procedure ThresholdAndIdentity_Filtering;
    [Test] procedure MissingAnswer_CachedWithoutDetail;
    [Test] procedure ResultMatchesCollectorContract;
  end;

implementation

uses
  MineHunter.Tests.Fakes;

function Conn(ATransport: TMHTransport; AIPv6: Boolean; APid: Cardinal): TMHNetConnection;
begin
  Result := Default(TMHNetConnection);
  Result.Transport := ATransport;
  Result.IPv6 := AIPv6;
  Result.OwningPid := APid;
  if AIPv6 then
    Result.LocalAddress := '::1'
  else
    Result.LocalAddress := '127.0.0.1';
  Result.LocalPort := 1000 + APid;
  if ATransport = ntTcp then
    Result.State := 'LISTEN';
end;

function Proc(APid: Cardinal; ACreateTime: UInt64; ACpu: Double;
  AHasCpu: Boolean = True): TMHProcessInfo;
begin
  Result := TMHProcessInfo.Create(TMHProcessId.Create(APid, ACreateTime),
    Format('p%d.exe', [APid]), FAKE_NOW);
  if AHasCpu then
    Result.Cpu := TMHMetric.Available(mkCpuPercent, ACpu, FAKE_NOW);
end;

function ContainsPid(const APids: TArray<Cardinal>; APid: Cardinal): Boolean;
var
  LPid: Cardinal;
begin
  for LPid in APids do
    if LPid = APid then
      Exit(True);
  Result := False;
end;

function FindDetail(const AResult: TMHCollectionResult; const AId: TMHProcessId;
  out ALine: string): Boolean;
var
  LDetail: TMHProcessDetail;
begin
  for LDetail in AResult.ProcessDetails do
    if LDetail.Id = AId then
    begin
      ALine := LDetail.CommandLine;
      // Командная строка не должна приносить случайные метрики GPU (поля не инициализированы).
      Assert.IsFalse(LDetail.Gpu.HasValue or LDetail.GpuCompute.HasValue or LDetail.GpuMemory.HasValue,
        'Сведения о командной строке не содержат метрик GPU');
      Exit(True);
    end;
  ALine := '';
  Result := False;
end;

{ TFakeNetworkApi }

function TFakeNetworkApi.Read(AIndex: Integer; out AItems: TArray<TMHNetConnection>;
  out AError: string): Boolean;
begin
  AItems := nil;
  AError := '';
  if RaiseOn[AIndex] then
    raise EMHError.Create('simulated table exception');
  if Fail[AIndex] then
  begin
    AError := 'simulated failure';
    Exit(False);
  end;
  AItems := Tables[AIndex];
  Result := True;
end;

function TFakeNetworkApi.ReadTcp(AIPv6: Boolean; out AItems: TArray<TMHNetConnection>;
  out AError: string): Boolean;
begin
  Result := Read(Ord(AIPv6), AItems, AError);
end;

function TFakeNetworkApi.ReadUdp(AIPv6: Boolean; out AItems: TArray<TMHNetConnection>;
  out AError: string): Boolean;
begin
  Result := Read(2 + Ord(AIPv6), AItems, AError);
end;

{ TFakeContextApi }

constructor TFakeContextApi.Create;
begin
  inherited Create;
  FLines := TDictionary<Cardinal, string>.Create;
  FRequests := TList<TArray<Cardinal>>.Create;
  HasIdle := True;
  HasFullscreen := True;
end;

destructor TFakeContextApi.Destroy;
begin
  FRequests.Free;
  FLines.Free;
  inherited;
end;

function TFakeContextApi.UserIdleSeconds(out ASeconds: Cardinal): Boolean;
begin
  ASeconds := IdleSeconds;
  Result := HasIdle;
end;

function TFakeContextApi.ForegroundPid: Cardinal;
begin
  Result := Foreground;
end;

function TFakeContextApi.FullscreenState(out AFullscreen: Boolean): Boolean;
begin
  AFullscreen := Fullscreen;
  Result := HasFullscreen;
end;

function TFakeContextApi.VisibleWindowPids: TArray<Cardinal>;
begin
  Result := Visible;
end;

function TFakeContextApi.ReadCommandLines(const APids: TArray<Cardinal>;
  out ALines: TArray<TMHProcessDetail>; out AError: string): Boolean;
var
  LPid: Cardinal;
  LDetail: TMHProcessDetail;
begin
  ALines := nil;
  AError := '';
  FRequests.Add(Copy(APids));
  if FailCommandLines then
  begin
    AError := 'simulated WMI failure';
    Exit(False);
  end;
  for LPid in APids do
    if FLines.ContainsKey(LPid) then
    begin
      // Как и WMI, двойник не знает времени создания процесса.
      LDetail := TMHProcessDetail.Create(TMHProcessId.Create(LPid, 0));
      LDetail.CommandLine := FLines[LPid];
      ALines := ALines + [LDetail];
    end;
  Result := True;
end;

procedure TFakeContextApi.SetLine(APid: Cardinal; const ALine: string);
begin
  FLines.AddOrSetValue(APid, ALine);
end;

function TFakeContextApi.RequestCount: Integer;
begin
  Result := FRequests.Count;
end;

function TFakeContextApi.LastRequest: TArray<Cardinal>;
begin
  if FRequests.Count = 0 then
    Result := nil
  else
    Result := FRequests.Last;
end;

{ TNetworkFormatTests }

procedure TNetworkFormatTests.IPv4_NetworkByteOrder;
begin
  // В DWORD таблиц IP Helper первый октет — младший байт.
  Assert.AreEqual('127.0.0.1', MHFormatIPv4($0100007F));
  Assert.AreEqual('192.168.1.10', MHFormatIPv4($0A01A8C0));
  Assert.AreEqual('0.0.0.0', MHFormatIPv4(0));
  Assert.AreEqual('255.255.255.255', MHFormatIPv4($FFFFFFFF));
end;

procedure TNetworkFormatTests.IPv6_Unspecified;
begin
  Assert.AreEqual('::', MHFormatIPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
end;

procedure TNetworkFormatTests.IPv6_Loopback;
begin
  Assert.AreEqual('::1', MHFormatIPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
end;

procedure TNetworkFormatTests.IPv6_LinkLocal;
begin
  Assert.AreEqual('fe80::1234:5678:9abc:def0', MHFormatIPv6([$FE, $80, 0, 0, 0, 0, 0, 0,
    $12, $34, $56, $78, $9A, $BC, $DE, $F0]));
  Assert.AreEqual('fe80::1', MHFormatIPv6([$FE, $80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
end;

procedure TNetworkFormatTests.IPv6_FullAddress_NoCompression;
begin
  Assert.AreEqual('2001:db8:1:2:3:4:5:6', MHFormatIPv6([$20, $01, $0D, $B8, 0, 1, 0, 2,
    0, 3, 0, 4, 0, 5, 0, 6]));
end;

procedure TNetworkFormatTests.IPv6_SingleZeroGroup_NotCompressed;
begin
  // RFC 5952 4.2.2: одна нулевая группа не заменяется на «::».
  Assert.AreEqual('2001:db8:0:1:1:1:1:1', MHFormatIPv6([$20, $01, $0D, $B8, 0, 0, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 1]));
end;

procedure TNetworkFormatTests.IPv6_LongestRunCompressed;
begin
  Assert.AreEqual('2001:0:0:1::1', MHFormatIPv6([$20, $01, 0, 0, 0, 0, 0, 1,
    0, 0, 0, 0, 0, 0, 0, 1]));
end;

procedure TNetworkFormatTests.IPv6_EqualRuns_FirstCompressed;
begin
  // RFC 5952 4.2.3: при равной длине сокращается первая серия.
  Assert.AreEqual('2001:db8::1:0:0:1', MHFormatIPv6([$20, $01, $0D, $B8, 0, 0, 0, 0,
    0, 1, 0, 0, 0, 0, 0, 1]));
end;

procedure TNetworkFormatTests.IPv6_TrailingZeros;
begin
  Assert.AreEqual('2001:db8::', MHFormatIPv6([$20, $01, $0D, $B8, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0]));
end;

procedure TNetworkFormatTests.IPv6_LowercaseWithoutLeadingZeros;
begin
  Assert.AreEqual('abcd:ef:a:b:c:d:e:f', MHFormatIPv6([$AB, $CD, 0, $EF, 0, $0A, 0, $0B,
    0, $0C, 0, $0D, 0, $0E, 0, $0F]));
end;

procedure TNetworkFormatTests.IPv6_IPv4Mapped;
begin
  Assert.AreEqual('::ffff:192.0.2.1', MHFormatIPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, $FF, $FF,
    192, 0, 2, 1]));
end;

procedure TNetworkFormatTests.IPv6_WrongLength_Raises;
begin
  Assert.WillRaise(
    procedure
    begin
      MHFormatIPv6([1, 2, 3, 4]);
    end, EArgumentException);
end;

procedure TNetworkFormatTests.Port_NetworkToHost;
begin
  Assert.AreEqual<Word>(80, MHNetworkToHostPort($5000));
  Assert.AreEqual<Word>(443, MHNetworkToHostPort($BB01));
  Assert.AreEqual<Word>(65535, MHNetworkToHostPort($FFFF));
  // Старшие 16 бит не используются.
  Assert.AreEqual<Word>(80, MHNetworkToHostPort($ABCD5000));
end;

procedure TNetworkFormatTests.TcpStateNames;
const
  EXPECTED: array[1..12] of string = ('CLOSED', 'LISTEN', 'SYN_SENT', 'SYN_RCVD',
    'ESTABLISHED', 'FIN_WAIT1', 'FIN_WAIT2', 'CLOSE_WAIT', 'CLOSING', 'LAST_ACK',
    'TIME_WAIT', 'DELETE_TCB');
var
  I: Cardinal;
begin
  for I := Low(EXPECTED) to High(EXPECTED) do
    Assert.AreEqual(EXPECTED[I], MHTcpStateName(I));
  Assert.AreEqual('UNKNOWN(0)', MHTcpStateName(0));
  Assert.AreEqual('UNKNOWN(13)', MHTcpStateName(13));
end;

{ TNetworkCollectorTests }

procedure TNetworkCollectorTests.Setup;
begin
  FApi := TFakeNetworkApi.Create;
  FApiIntf := FApi;
  FApi.Tables[0] := [Conn(ntTcp, False, 1), Conn(ntTcp, False, 2)];
  FApi.Tables[1] := [Conn(ntTcp, True, 3)];
  FApi.Tables[2] := [Conn(ntUdp, False, 4), Conn(ntUdp, False, 5), Conn(ntUdp, False, 6)];
  FApi.Tables[3] := [Conn(ntUdp, True, 7)];
  FCollector := TMHNetworkCollector.Create(FApiIntf, TFakeClock.Create(FAKE_NOW));
end;

procedure TNetworkCollectorTests.TearDown;
begin
  FCollector := nil;
  FApiIntf := nil;
  FApi := nil;
end;

procedure TNetworkCollectorTests.CreateWithNilApi;
var
  LClock: IMHClock;
begin
  LClock := TFakeClock.Create(FAKE_NOW);
  TMHNetworkCollector.Create(nil, LClock).Free;
end;

procedure TNetworkCollectorTests.CreateWithNilClock;
begin
  TMHNetworkCollector.Create(FApiIntf, nil).Free;
end;

procedure TNetworkCollectorTests.Create_NilArguments_Raise;
begin
  Assert.WillRaise(CreateWithNilApi, EArgumentNilException);
  Assert.WillRaise(CreateWithNilClock, EArgumentNilException);
end;

procedure TNetworkCollectorTests.AllTablesOk_IsSuccess_WithAllConnections;
var
  LResult: TMHCollectionResult;
  LPid: Cardinal;
  LFound: Boolean;
  LItem: TMHNetConnection;
begin
  LResult := FCollector.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State, LResult.Status.Message);
  Assert.AreEqual('', LResult.Status.Message);
  Assert.AreEqual(7, Integer(Length(LResult.Connections)));
  Assert.AreEqual(7, LResult.Status.ItemCount);
  Assert.AreEqual<TDateTime>(FAKE_NOW, LResult.Status.TimestampUtc);
  for LPid := 1 to 7 do
  begin
    LFound := False;
    for LItem in LResult.Connections do
      if LItem.OwningPid = LPid then
        LFound := True;
    Assert.IsTrue(LFound, Format('Соединение PID %d должно быть в результате', [LPid]));
  end;
  Assert.IsFalse(LResult.HasContext);
  Assert.AreEqual(0, Integer(Length(LResult.Processes)));
end;

procedure TNetworkCollectorTests.OneTableFails_IsPartial_OthersReturned;
var
  LResult: TMHCollectionResult;
begin
  FApi.Fail[1] := True;
  LResult := FCollector.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.Contains(LResult.Status.Message, 'TCP IPv6');
  Assert.Contains(LResult.Status.Message, 'simulated failure');
  Assert.DoesNotContain(LResult.Status.Message, 'UDP');
  Assert.AreEqual(6, Integer(Length(LResult.Connections)));
  Assert.AreEqual(6, LResult.Status.ItemCount);
end;

procedure TNetworkCollectorTests.AllTablesFail_IsError_NoException;
var
  LResult: TMHCollectionResult;
  I: Integer;
begin
  for I := 0 to 3 do
    FApi.Fail[I] := True;
  LResult := FCollector.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual<TMHSourceState>(ssError, LResult.Status.State);
  Assert.Contains(LResult.Status.Message, 'TCP IPv4');
  Assert.Contains(LResult.Status.Message, 'UDP IPv6');
  Assert.AreEqual(0, Integer(Length(LResult.Connections)));
  Assert.AreEqual(0, LResult.Status.ItemCount);
end;

procedure TNetworkCollectorTests.TableRaises_TreatedAsFailure;
var
  LResult: TMHCollectionResult;
begin
  FApi.RaiseOn[2] := True;
  LResult := FCollector.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.Contains(LResult.Status.Message, 'UDP IPv4');
  Assert.Contains(LResult.Status.Message, 'simulated table exception');
  Assert.AreEqual(4, Integer(Length(LResult.Connections)));
end;

procedure TNetworkCollectorTests.ResultMatchesCollectorContract;
var
  LResult: TMHCollectionResult;
begin
  Assert.AreEqual(TMHNetworkCollector.SourceIdValue, FCollector.SourceId);
  Assert.AreEqual('network', FCollector.SourceId);
  Assert.IsNotEmpty(FCollector.DisplayName);
  FApi.Fail[3] := True;
  // Пустой снимок: время берётся из часов.
  LResult := FCollector.Collect(Default(TMHSnapshot));
  Assert.AreEqual(FCollector.SourceId, LResult.Status.SourceId);
  Assert.AreEqual<TDateTime>(FAKE_NOW, LResult.Status.TimestampUtc);
  Assert.IsTrue(LResult.Status.State in [ssSuccess, ssPartial, ssUnavailable, ssError]);
  Assert.IsNotEmpty(LResult.Status.Message);
end;

{ TContextCollectorTests }

procedure TContextCollectorTests.Setup;
begin
  FApi := TFakeContextApi.Create;
  FApiIntf := FApi;
  FApi.IdleSeconds := 10;
  FCollector := TMHContextCollector.Create(FApiIntf, TFakeClock.Create(FAKE_NOW), 300, 3.0, 20);
  FCollectorIntf := FCollector;
end;

procedure TContextCollectorTests.TearDown;
begin
  FCollectorIntf := nil;
  FCollector := nil;
  FApiIntf := nil;
  FApi := nil;
end;

function TContextCollectorTests.Collect(const AProcesses: array of TMHProcessInfo): TMHCollectionResult;
var
  LSnapshot: TMHSnapshot;
  I: Integer;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  SetLength(LSnapshot.Processes, Length(AProcesses));
  for I := 0 to High(AProcesses) do
    LSnapshot.Processes[I] := AProcesses[I];
  Result := FCollectorIntf.Collect(LSnapshot);
end;

procedure TContextCollectorTests.CreateWithNilApi;
var
  LClock: IMHClock;
begin
  LClock := TFakeClock.Create(FAKE_NOW);
  TMHContextCollector.Create(nil, LClock).Free;
end;

procedure TContextCollectorTests.CreateWithNilClock;
begin
  TMHContextCollector.Create(FApiIntf, nil).Free;
end;

procedure TContextCollectorTests.CreateWithZeroThreshold;
var
  LClock: IMHClock;
begin
  LClock := TFakeClock.Create(FAKE_NOW);
  TMHContextCollector.Create(FApiIntf, LClock, 0).Free;
end;

procedure TContextCollectorTests.Create_InvalidArguments_Raise;
begin
  Assert.WillRaise(CreateWithNilApi, EArgumentNilException);
  Assert.WillRaise(CreateWithNilClock, EArgumentNilException);
  Assert.WillRaise(CreateWithZeroThreshold, EArgumentOutOfRangeException);
end;

procedure TContextCollectorTests.ShortIdle_IsWork;
var
  LResult: TMHCollectionResult;
begin
  FApi.IdleSeconds := 299;
  LResult := Collect([]);
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State, LResult.Status.Message);
  Assert.IsTrue(LResult.HasContext);
  Assert.IsTrue(LResult.Context.Available);
  Assert.AreEqual<TMHWorkContext>(wcWork, LResult.Context.WorkContext);
  Assert.AreEqual<Cardinal>(299, LResult.Context.UserIdleSeconds);
end;

procedure TContextCollectorTests.IdleAtThreshold_IsIdle;
begin
  FApi.IdleSeconds := 300;
  Assert.AreEqual<TMHWorkContext>(wcIdle, Collect([]).Context.WorkContext);
  FApi.IdleSeconds := 100000;
  Assert.AreEqual<TMHWorkContext>(wcIdle, Collect([]).Context.WorkContext);
end;

procedure TContextCollectorTests.Fullscreen_IsGaming_EvenWhenIdle;
var
  LResult: TMHCollectionResult;
begin
  FApi.Fullscreen := True;
  FApi.IdleSeconds := 5000;
  LResult := Collect([]);
  Assert.AreEqual<TMHWorkContext>(wcGaming, LResult.Context.WorkContext);
  Assert.IsTrue(LResult.Context.FullscreenActive);
  // Полноэкранный режим определяет контекст и без данных о бездействии.
  FApi.HasIdle := False;
  Assert.AreEqual<TMHWorkContext>(wcGaming, Collect([]).Context.WorkContext);
end;

procedure TContextCollectorTests.IdleUnavailable_IsUnknown_Partial;
var
  LResult: TMHCollectionResult;
begin
  FApi.HasIdle := False;
  LResult := Collect([]);
  Assert.AreEqual<TMHWorkContext>(wcUnknown, LResult.Context.WorkContext);
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.Contains(LResult.Status.Message, 'бездействия');
  Assert.IsTrue(LResult.HasContext);
  Assert.IsTrue(LResult.Context.Available);
end;

procedure TContextCollectorTests.FullscreenUnavailable_IsPartial_ClassifiedByIdle;
var
  LResult: TMHCollectionResult;
begin
  FApi.HasFullscreen := False;
  FApi.Fullscreen := True; // значение не должно использоваться при отказе
  FApi.IdleSeconds := 400;
  LResult := Collect([]);
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.Contains(LResult.Status.Message, 'полноэкранного');
  Assert.IsFalse(LResult.Context.FullscreenActive);
  Assert.AreEqual<TMHWorkContext>(wcIdle, LResult.Context.WorkContext);
end;

procedure TContextCollectorTests.ContextFields_AreCopied;
var
  LResult: TMHCollectionResult;
begin
  FApi.Foreground := 4242;
  FApi.Visible := [4242, 17, 99];
  LResult := Collect([]);
  Assert.AreEqual<Cardinal>(4242, LResult.Context.ForegroundPid);
  Assert.AreEqual(3, Integer(Length(LResult.Context.VisibleWindowPids)));
  Assert.IsTrue(LResult.Context.HasVisibleWindow(17));
  Assert.IsFalse(LResult.Context.HasVisibleWindow(18));
  Assert.AreEqual<TDateTime>(FAKE_NOW, LResult.Status.TimestampUtc);
end;

procedure TContextCollectorTests.CommandLine_RequestedOnce_CachedByIdentity;
var
  LResult: TMHCollectionResult;
  LLine: string;
begin
  FApi.SetLine(100, '"C:\x\miner.exe" --algo test');
  LResult := Collect([Proc(100, 5000, 50)]);
  Assert.AreEqual(1, FApi.RequestCount);
  Assert.AreEqual(1, Integer(Length(FApi.LastRequest)));
  Assert.IsTrue(FindDetail(LResult, TMHProcessId.Create(100, 5000), LLine),
    'Деталь должна содержать полную идентичность из снимка');
  Assert.AreEqual('"C:\x\miner.exe" --algo test', LLine);
  Assert.AreEqual(1, LResult.Status.ItemCount);

  // Второй цикл: запроса нет, данные из кеша.
  FApi.SetLine(100, 'changed');
  LResult := Collect([Proc(100, 5000, 50)]);
  Assert.AreEqual(1, FApi.RequestCount, 'Повторный запрос для того же экземпляра не нужен');
  Assert.IsTrue(FindDetail(LResult, TMHProcessId.Create(100, 5000), LLine));
  Assert.AreEqual('"C:\x\miner.exe" --algo test', LLine);
  // Кешированная строка возвращается и после падения CPU ниже порога.
  Assert.IsTrue(FindDetail(Collect([Proc(100, 5000, 0)]), TMHProcessId.Create(100, 5000), LLine));
  Assert.AreEqual(1, FApi.RequestCount);
end;

procedure TContextCollectorTests.ReusedPid_DifferentCreateTime_IsRequeried;
var
  LResult: TMHCollectionResult;
  LLine: string;
begin
  FApi.SetLine(100, 'old.exe');
  Collect([Proc(100, 5000, 50)]);
  FApi.SetLine(100, 'new.exe --x');
  LResult := Collect([Proc(100, 9000, 50)]);
  Assert.AreEqual(2, FApi.RequestCount, 'Новый экземпляр с тем же PID должен запрашиваться заново');
  Assert.IsTrue(FindDetail(LResult, TMHProcessId.Create(100, 9000), LLine));
  Assert.AreEqual('new.exe --x', LLine);
  Assert.IsFalse(FindDetail(LResult, TMHProcessId.Create(100, 5000), LLine),
    'Строка старого экземпляра не должна возвращаться');
  Assert.AreEqual(1, Integer(Length(LResult.ProcessDetails)));
  Assert.AreEqual(1, FCollector.CachedCount);
end;

procedure TContextCollectorTests.CapPerCycle_HighestCpuFirst_RestNextCycle;
var
  LProcs: TArray<TMHProcessInfo>;
  LRequest: TArray<Cardinal>;
  LResult: TMHCollectionResult;
  I: Integer;
begin
  SetLength(LProcs, 30);
  for I := 0 to 29 do
  begin
    // PID 1..30, CPU растёт с PID: самые нагруженные — 11..30.
    LProcs[I] := Proc(I + 1, 777, 10 + I);
    FApi.SetLine(I + 1, Format('cmd%d', [I + 1]));
  end;
  LResult := Collect(LProcs);
  LRequest := FApi.LastRequest;
  Assert.AreEqual(20, Integer(Length(LRequest)));
  for I := 11 to 30 do
    Assert.IsTrue(ContainsPid(LRequest, I), Format('PID %d с высоким CPU должен быть запрошен', [I]));
  Assert.AreEqual(20, Integer(Length(LResult.ProcessDetails)));

  LResult := Collect(LProcs);
  Assert.AreEqual(2, FApi.RequestCount);
  Assert.AreEqual(10, Integer(Length(FApi.LastRequest)));
  for I := 1 to 10 do
    Assert.IsTrue(ContainsPid(FApi.LastRequest, I));
  Assert.AreEqual(30, Integer(Length(LResult.ProcessDetails)));

  Collect(LProcs);
  Assert.AreEqual(2, FApi.RequestCount, 'Все экземпляры уже в кеше');
end;

procedure TContextCollectorTests.ExitedProcesses_ArePrunedFromCache;
var
  LResult: TMHCollectionResult;
  LLine: string;
begin
  FApi.SetLine(1, 'a');
  FApi.SetLine(2, 'b');
  Collect([Proc(1, 10, 50), Proc(2, 20, 50)]);
  Assert.AreEqual(2, FCollector.CachedCount);
  LResult := Collect([Proc(2, 20, 50)]);
  Assert.AreEqual(1, FCollector.CachedCount);
  Assert.IsTrue(FindDetail(LResult, TMHProcessId.Create(2, 20), LLine));
  Assert.AreEqual(1, Integer(Length(LResult.ProcessDetails)));
  Collect([]);
  Assert.AreEqual(0, FCollector.CachedCount);
end;

procedure TContextCollectorTests.CommandLineFailure_IsPartial_ContextStillReturned_Retried;
var
  LResult: TMHCollectionResult;
  LLine: string;
begin
  FApi.SetLine(100, 'x.exe');
  FApi.FailCommandLines := True;
  FApi.Fullscreen := True;
  LResult := Collect([Proc(100, 5000, 50)]);
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.Contains(LResult.Status.Message, 'командные строки');
  Assert.Contains(LResult.Status.Message, 'simulated WMI failure');
  Assert.IsTrue(LResult.HasContext);
  Assert.IsTrue(LResult.Context.Available);
  Assert.AreEqual<TMHWorkContext>(wcGaming, LResult.Context.WorkContext);
  Assert.AreEqual(0, Integer(Length(LResult.ProcessDetails)));
  Assert.AreEqual(0, FCollector.CachedCount, 'Неудачный запрос не кешируется');

  FApi.FailCommandLines := False;
  LResult := Collect([Proc(100, 5000, 50)]);
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State, LResult.Status.Message);
  Assert.AreEqual(2, FApi.RequestCount, 'После сбоя запрос повторяется');
  Assert.IsTrue(FindDetail(LResult, TMHProcessId.Create(100, 5000), LLine));
  Assert.AreEqual('x.exe', LLine);
end;

procedure TContextCollectorTests.ThresholdAndIdentity_Filtering;
var
  LRequest: TArray<Cardinal>;
begin
  Collect([
    Proc(1, 10, 2.99),            // ниже порога
    Proc(2, 20, 0, False),        // CPU неизвестен
    Proc(3, 0, 90),               // нет времени создания
    Proc(0, 0, 90),               // System Idle Process
    Proc(4, 40, 3.0),             // ровно порог
    Proc(5, 50, 75)]);
  Assert.AreEqual(1, FApi.RequestCount);
  LRequest := FApi.LastRequest;
  Assert.AreEqual(2, Integer(Length(LRequest)));
  Assert.AreEqual<Cardinal>(5, LRequest[0], 'Сначала самый нагруженный');
  Assert.AreEqual<Cardinal>(4, LRequest[1]);

  // Нет кандидатов — нет запроса.
  Collect([Proc(1, 10, 1)]);
  Assert.AreEqual(1, FApi.RequestCount);
end;

procedure TContextCollectorTests.MissingAnswer_CachedWithoutDetail;
var
  LResult: TMHCollectionResult;
begin
  // Процесс другого пользователя: WMI не вернул командной строки.
  LResult := Collect([Proc(200, 1, 40)]);
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State, LResult.Status.Message);
  Assert.AreEqual(0, Integer(Length(LResult.ProcessDetails)));
  Assert.AreEqual(1, FCollector.CachedCount);
  Collect([Proc(200, 1, 40)]);
  Assert.AreEqual(1, FApi.RequestCount, 'Безответный экземпляр не запрашивается каждый цикл');
end;

procedure TContextCollectorTests.ResultMatchesCollectorContract;
var
  LResult: TMHCollectionResult;
begin
  Assert.AreEqual(TMHContextCollector.SourceIdValue, FCollectorIntf.SourceId);
  Assert.AreEqual('context', FCollectorIntf.SourceId);
  Assert.IsNotEmpty(FCollectorIntf.DisplayName);
  LResult := FCollectorIntf.Collect(Default(TMHSnapshot));
  Assert.AreEqual(FCollectorIntf.SourceId, LResult.Status.SourceId);
  Assert.AreEqual<TDateTime>(FAKE_NOW, LResult.Status.TimestampUtc);
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State);
  Assert.AreEqual(0, Integer(Length(LResult.Processes)), 'Контекст не добавляет процессы');
  FApi.HasIdle := False;
  LResult := FCollectorIntf.Collect(Default(TMHSnapshot));
  Assert.IsNotEmpty(LResult.Status.Message);
end;

initialization
  TDUnitX.RegisterTestFixture(TNetworkFormatTests);
  TDUnitX.RegisterTestFixture(TNetworkCollectorTests);
  TDUnitX.RegisterTestFixture(TContextCollectorTests);

end.
