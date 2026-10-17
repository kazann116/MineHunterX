unit MineHunter.Tests.NetworkContextIntegration;

{
  Integration: сетевой коллектор и коллектор контекста на реальных API Windows.
  Тесты создают только собственные сокеты на петлевом интерфейсе и читают
  сведения о собственном процессе — внешних соединений не устанавливают.
}

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  [Category('Integration')]
  TNetworkIntegrationTests = class
  public
    [Test] procedure TcpTable_IsNotEmpty;
    [Test] procedure OwnListeningSocket_IPv4_HasPidAndListenState;
    [Test] procedure OwnListeningSocket_IPv6_Loopback;
    [Test] procedure OwnUdpSocket_HasPid;
    [Test] procedure Collector_ReturnsConnections;
    [Test] procedure NoHandleLeak_AfterManyCollects;
  end;

  [TestFixture]
  [Category('Integration')]
  TContextIntegrationTests = class
  public
    [Test] procedure Context_IsAvailable_WithWorkContext;
    [Test] procedure OwnCommandLine_ContainsExeName;
    [Test] procedure Collector_ReturnsOwnCommandLine_WithIdentity;
    [Test] procedure NoHandleLeak_AfterManyCollects;
  end;

implementation

// Интеграционные тесты работают только на Windows.
{$WARN SYMBOL_PLATFORM OFF}

uses
  System.SysUtils, Winapi.Windows, Winapi.Winsock2,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Core.Logging,
  MineHunter.Core.Calc,
  MineHunter.Collectors.Network, MineHunter.Collectors.Network.WinApi,
  MineHunter.Collectors.Context, MineHunter.Collectors.Context.WinApi;

type
  // ws2ipdef.h — в Winapi.Winsock2 Delphi 12 не объявлена.
  TSockAddrIn6 = record
    sin6_family: Word;
    sin6_port: Word;
    sin6_flowinfo: Cardinal;
    sin6_addr: array[0..15] of Byte;
    sin6_scope_id: Cardinal;
  end;

  /// Собственный сокет на петлевом интерфейсе; закрывается в Free.
  TLoopbackSocket = class
  private
    FSocket: TSocket;
    FPort: Word;
    FStarted: Boolean;
  public
    /// False — семейство адресов недоступно (только для IPv6).
    function Open(AIPv6: Boolean; AType, AProtocol: Integer): Boolean;
    destructor Destroy; override;
    property Port: Word read FPort;
  end;

function TLoopbackSocket.Open(AIPv6: Boolean; AType, AProtocol: Integer): Boolean;
var
  LData: TWSAData;
  LAddr4: TSockAddrIn;
  LAddr6: TSockAddrIn6;
  LLen: Integer;
begin
  Assert.AreEqual(0, WSAStartup($0202, LData), 'WSAStartup');
  FStarted := True;
  if AIPv6 then
    FSocket := socket(AF_INET6, AType, AProtocol)
  else
    FSocket := socket(AF_INET, AType, AProtocol);
  if FSocket = INVALID_SOCKET then
  begin
    if AIPv6 then
      Exit(False);
    Assert.Fail('socket: ' + SysErrorMessage(WSAGetLastError));
  end;

  if AIPv6 then
  begin
    FillChar(LAddr6, SizeOf(LAddr6), 0);
    LAddr6.sin6_family := AF_INET6;
    LAddr6.sin6_addr[15] := 1; // ::1, порт 0 — выбирает система
    if bind(FSocket, PSockAddr(@LAddr6)^, SizeOf(LAddr6)) <> 0 then
      Exit(False);
    LLen := SizeOf(LAddr6);
    Assert.AreEqual(0, getsockname(FSocket, PSockAddr(@LAddr6)^, LLen), 'getsockname');
    FPort := ntohs(LAddr6.sin6_port);
  end
  else
  begin
    FillChar(LAddr4, SizeOf(LAddr4), 0);
    LAddr4.sin_family := AF_INET;
    LAddr4.sin_addr.S_addr := inet_addr('127.0.0.1');
    Assert.AreEqual(0, bind(FSocket, PSockAddr(@LAddr4)^, SizeOf(LAddr4)),
      'bind: ' + SysErrorMessage(WSAGetLastError));
    LLen := SizeOf(LAddr4);
    Assert.AreEqual(0, getsockname(FSocket, PSockAddr(@LAddr4)^, LLen), 'getsockname');
    FPort := ntohs(LAddr4.sin_port);
  end;
  if AType = SOCK_STREAM then
    Assert.AreEqual(0, listen(FSocket, 1), 'listen: ' + SysErrorMessage(WSAGetLastError));
  Assert.IsTrue(FPort <> 0, 'Система должна назначить порт');
  Result := True;
end;

destructor TLoopbackSocket.Destroy;
begin
  if (FSocket <> 0) and (FSocket <> INVALID_SOCKET) then
    closesocket(FSocket);
  if FStarted then
    WSACleanup;
  inherited;
end;

function UtcNow: TDateTime;
var
  LClock: IMHClock;
begin
  LClock := TMHSystemClock.Create;
  Result := LClock.NowUtc;
end;

function NewNetworkApi: IMHNetworkApi;
begin
  Result := TMHWinNetworkApi.Create;
end;

function NewNetworkCollector: IMHCollector;
var
  LApi: IMHNetworkApi;
  LClock: IMHClock;
begin
  LApi := TMHWinNetworkApi.Create;
  LClock := TMHSystemClock.Create;
  Result := TMHNetworkCollector.Create(LApi, LClock);
end;

function NewContextCollector: IMHCollector;
var
  LApi: IMHContextApi;
  LClock: IMHClock;
begin
  LApi := TMHWinContextApi.Create;
  LClock := TMHSystemClock.Create;
  Result := TMHContextCollector.Create(LApi, LClock);
end;

function FindOwn(const AItems: TArray<TMHNetConnection>; ATransport: TMHTransport;
  const AAddress: string; APort: Word; out AItem: TMHNetConnection): Boolean;
var
  LItem: TMHNetConnection;
begin
  for LItem in AItems do
    if (LItem.Transport = ATransport) and (LItem.LocalPort = APort) and
       (LItem.LocalAddress = AAddress) and (LItem.OwningPid = GetCurrentProcessId) then
    begin
      AItem := LItem;
      Exit(True);
    end;
  AItem := Default(TMHNetConnection);
  Result := False;
end;

function OwnProcessId: TMHProcessId;
var
  LCreation, LExit, LKernel, LUser: TFileTime;
begin
  Win32Check(GetProcessTimes(GetCurrentProcess, LCreation, LExit, LKernel, LUser));
  Result := TMHProcessId.Create(GetCurrentProcessId,
    MHFileTimeToUInt64(LCreation.dwLowDateTime, LCreation.dwHighDateTime));
end;

function SnapshotWithOwnProcess(ASequence: UInt64; ACreateTime: UInt64): TMHSnapshot;
var
  LInfo: TMHProcessInfo;
begin
  Result := TMHSnapshot.Create(ASequence, UtcNow);
  LInfo := TMHProcessInfo.Create(TMHProcessId.Create(GetCurrentProcessId, ACreateTime),
    ExtractFileName(ParamStr(0)), Result.TimestampUtc);
  LInfo.Cpu := TMHMetric.Available(mkCpuPercent, 50, Result.TimestampUtc);
  Result.Processes := [LInfo];
end;

{ TNetworkIntegrationTests }

procedure TNetworkIntegrationTests.TcpTable_IsNotEmpty;
var
  LItems: TArray<TMHNetConnection>;
  LError: string;
  LSocket: TLoopbackSocket;
begin
  // Даже на изолированной машине есть прослушиваемые порты служб Windows
  // (RPC 135 и др.); на всякий случай добавляем собственный.
  LSocket := TLoopbackSocket.Create;
  try
    LSocket.Open(False, SOCK_STREAM, IPPROTO_TCP);
    Assert.IsTrue(NewNetworkApi.ReadTcp(False, LItems, LError), LError);
    Assert.IsTrue(Length(LItems) > 0, 'Таблица TCP IPv4 не может быть пустой при открытом сокете');
  finally
    LSocket.Free;
  end;
end;

procedure TNetworkIntegrationTests.OwnListeningSocket_IPv4_HasPidAndListenState;
var
  LItems: TArray<TMHNetConnection>;
  LError: string;
  LSocket: TLoopbackSocket;
  LItem: TMHNetConnection;
  LPort: Word;
begin
  LSocket := TLoopbackSocket.Create;
  try
    LSocket.Open(False, SOCK_STREAM, IPPROTO_TCP);
    LPort := LSocket.Port;
    Assert.IsTrue(NewNetworkApi.ReadTcp(False, LItems, LError), LError);
    Assert.IsTrue(FindOwn(LItems, ntTcp, '127.0.0.1', LPort, LItem),
      Format('Собственный сокет 127.0.0.1:%d должен быть в таблице', [LPort]));
    Assert.AreEqual('LISTEN', LItem.State);
    Assert.IsFalse(LItem.IPv6);
    Assert.AreEqual('', LItem.RemoteAddress);
    Assert.AreEqual<Word>(0, LItem.RemotePort);
  finally
    LSocket.Free;
  end;
  // После закрытия сокет исчезает из таблицы.
  Assert.IsTrue(NewNetworkApi.ReadTcp(False, LItems, LError), LError);
  Assert.IsFalse(FindOwn(LItems, ntTcp, '127.0.0.1', LPort, LItem),
    'Закрытый сокет не должен оставаться в таблице');
end;

procedure TNetworkIntegrationTests.OwnListeningSocket_IPv6_Loopback;
var
  LItems: TArray<TMHNetConnection>;
  LError: string;
  LSocket: TLoopbackSocket;
  LItem: TMHNetConnection;
begin
  LSocket := TLoopbackSocket.Create;
  try
    if not LSocket.Open(True, SOCK_STREAM, IPPROTO_TCP) then
    begin
      Assert.Pass('IPv6 на этой системе недоступен');
      Exit;
    end;
    Assert.IsTrue(NewNetworkApi.ReadTcp(True, LItems, LError), LError);
    Assert.IsTrue(FindOwn(LItems, ntTcp, '::1', LSocket.Port, LItem),
      Format('Собственный сокет [::1]:%d должен быть в таблице IPv6', [LSocket.Port]));
    Assert.AreEqual('LISTEN', LItem.State);
    Assert.IsTrue(LItem.IPv6);
  finally
    LSocket.Free;
  end;
end;

procedure TNetworkIntegrationTests.OwnUdpSocket_HasPid;
var
  LItems: TArray<TMHNetConnection>;
  LError: string;
  LSocket: TLoopbackSocket;
  LItem: TMHNetConnection;
begin
  LSocket := TLoopbackSocket.Create;
  try
    LSocket.Open(False, SOCK_DGRAM, IPPROTO_UDP);
    Assert.IsTrue(NewNetworkApi.ReadUdp(False, LItems, LError), LError);
    Assert.IsTrue(FindOwn(LItems, ntUdp, '127.0.0.1', LSocket.Port, LItem),
      Format('Собственный UDP-сокет 127.0.0.1:%d должен быть в таблице', [LSocket.Port]));
    Assert.AreEqual('', LItem.State);
    Assert.AreEqual('', LItem.RemoteAddress);
  finally
    LSocket.Free;
  end;
end;

procedure TNetworkIntegrationTests.Collector_ReturnsConnections;
var
  LResult: TMHCollectionResult;
  LSocket: TLoopbackSocket;
  LItem: TMHNetConnection;
begin
  LSocket := TLoopbackSocket.Create;
  try
    LSocket.Open(False, SOCK_STREAM, IPPROTO_TCP);
    LResult := NewNetworkCollector.Collect(TMHSnapshot.Create(1, UtcNow));
    Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State, LResult.Status.Message);
    Assert.AreEqual(Integer(Length(LResult.Connections)), LResult.Status.ItemCount);
    Assert.IsTrue(FindOwn(LResult.Connections, ntTcp, '127.0.0.1', LSocket.Port, LItem));
  finally
    LSocket.Free;
  end;
end;

procedure TNetworkIntegrationTests.NoHandleLeak_AfterManyCollects;
var
  LCollector: IMHCollector;
  LBefore, LAfter: DWORD;
  I: Integer;
begin
  LCollector := NewNetworkCollector;
  LCollector.Collect(TMHSnapshot.Create(1, UtcNow));
  Win32Check(GetProcessHandleCount(GetCurrentProcess, LBefore));
  for I := 2 to 21 do
    LCollector.Collect(TMHSnapshot.Create(I, UtcNow));
  Win32Check(GetProcessHandleCount(GetCurrentProcess, LAfter));
  Assert.IsTrue(Integer(LAfter) - Integer(LBefore) < 20,
    Format('Число дескрипторов выросло с %d до %d', [LBefore, LAfter]));
end;

{ TContextIntegrationTests }

procedure TContextIntegrationTests.Context_IsAvailable_WithWorkContext;
var
  LResult: TMHCollectionResult;
begin
  LResult := NewContextCollector.Collect(TMHSnapshot.Create(1, UtcNow));
  Assert.AreEqual(TMHContextCollector.SourceIdValue, LResult.Status.SourceId);
  Assert.IsTrue(LResult.HasContext);
  Assert.IsTrue(LResult.Context.Available);
  if LResult.Context.WorkContext = wcUnknown then
    // Допустимо только с объяснением (например, сеанс без интерактивного ввода).
    Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State,
      'Неизвестный контекст должен объясняться')
  else
    Assert.IsTrue(LResult.Context.WorkContext in [wcIdle, wcWork, wcGaming]);
  if LResult.Status.State <> ssSuccess then
    Assert.IsNotEmpty(LResult.Status.Message);
end;

procedure TContextIntegrationTests.OwnCommandLine_ContainsExeName;
var
  LApi: IMHContextApi;
  LLines: TArray<TMHProcessDetail>;
  LError: string;
begin
  LApi := TMHWinContextApi.Create;
  Assert.IsTrue(LApi.ReadCommandLines([GetCurrentProcessId], LLines, LError), LError);
  Assert.AreEqual(1, Integer(Length(LLines)));
  Assert.AreEqual<Cardinal>(GetCurrentProcessId, LLines[0].Id.Pid);
  Assert.IsTrue(LLines[0].CommandLine.ToLower.Contains(ExtractFileName(ParamStr(0)).ToLower),
    'Командная строка: ' + LLines[0].CommandLine);
  // Повторный вызов в том же потоке: COM корректно освобождён и инициализируется снова.
  Assert.IsTrue(LApi.ReadCommandLines([GetCurrentProcessId], LLines, LError), LError);
  Assert.AreEqual(1, Integer(Length(LLines)));
end;

procedure TContextIntegrationTests.Collector_ReturnsOwnCommandLine_WithIdentity;
var
  LResult: TMHCollectionResult;
  LId: TMHProcessId;
begin
  LId := OwnProcessId;
  LResult := NewContextCollector.Collect(SnapshotWithOwnProcess(1, LId.CreateTime));
  Assert.IsFalse(LResult.Status.Message.Contains('командные строки'), LResult.Status.Message);
  Assert.AreEqual(1, Integer(Length(LResult.ProcessDetails)));
  Assert.IsTrue(LResult.ProcessDetails[0].Id = LId, 'Идентичность берётся из снимка');
  Assert.IsTrue(LResult.ProcessDetails[0].CommandLine.ToLower.Contains(
    ExtractFileName(ParamStr(0)).ToLower), LResult.ProcessDetails[0].CommandLine);
end;

procedure TContextIntegrationTests.NoHandleLeak_AfterManyCollects;
var
  LCollector: IMHCollector;
  LBefore, LAfter: DWORD;
  I: Integer;
  LResult: TMHCollectionResult;
begin
  LCollector := NewContextCollector;
  // Каждый цикл — «новый экземпляр» (другое время создания), поэтому
  // командная строка запрашивается через WMI в каждом цикле.
  LCollector.Collect(SnapshotWithOwnProcess(1, 1));
  Win32Check(GetProcessHandleCount(GetCurrentProcess, LBefore));
  for I := 2 to 21 do
  begin
    LResult := LCollector.Collect(SnapshotWithOwnProcess(I, I));
    Assert.AreEqual(1, Integer(Length(LResult.ProcessDetails)), LResult.Status.Message);
  end;
  Win32Check(GetProcessHandleCount(GetCurrentProcess, LAfter));
  Assert.IsTrue(Integer(LAfter) - Integer(LBefore) < 20,
    Format('Число дескрипторов выросло с %d до %d', [LBefore, LAfter]));
end;

initialization
  TDUnitX.RegisterTestFixture(TNetworkIntegrationTests);
  TDUnitX.RegisterTestFixture(TContextIntegrationTests);

end.
