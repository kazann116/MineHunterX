unit MineHunter.Collectors.Network.WinApi;

{
  Реализация IMHNetworkApi на документированных функциях IP Helper:
    - GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL) — соединения и
      прослушиваемые порты TCP с PID владельца;
    - GetExtendedUdpTable(UDP_TABLE_OWNER_PID) — открытые порты UDP с PID.
  Обе функции работают без прав администратора.

  Размер таблицы может вырасти между запросом размера и чтением, поэтому
  чтение повторяется, пока функция возвращает ERROR_INSUFFICIENT_BUFFER
  (ограниченное число попыток, буфер берётся с запасом).

  Функции и структуры отсутствуют в Winapi.IpHlpApi / Winapi.IpRtrMib Delphi 12
  и объявлены здесь по Windows SDK (iphlpapi.h, tcpmib.h, udpmib.h).
}

interface

uses
  MineHunter.Core.Types, MineHunter.Collectors.Network;

type
  TMHWinNetworkApi = class(TInterfacedObject, IMHNetworkApi)
  public
    function ReadTcp(AIPv6: Boolean; out AItems: TArray<TMHNetConnection>;
      out AError: string): Boolean;
    function ReadUdp(AIPv6: Boolean; out AItems: TArray<TMHNetConnection>;
      out AError: string): Boolean;
  end;

implementation

uses
  Winapi.Windows, System.SysUtils,
  MineHunter.Core.Lang;

const
  // ws2def.h
  AF_INET = 2;
  AF_INET6 = 23;
  // iprtrmib.h: TCP_TABLE_CLASS / UDP_TABLE_CLASS
  TCP_TABLE_OWNER_PID_ALL = 5;
  UDP_TABLE_OWNER_PID = 1;
  // tcpmib.h: MIB_TCP_STATE_LISTEN
  MIB_TCP_STATE_LISTEN = 2;

  /// Число попыток чтения таблицы, если она растёт между вызовами.
  MAX_READ_ATTEMPTS = 5;
  /// Запас буфера в байтах на случай роста таблицы.
  BUFFER_SLACK = 4096;

type
  // tcpmib.h
  MIB_TCPROW_OWNER_PID = record
    dwState: DWORD;
    dwLocalAddr: DWORD;
    dwLocalPort: DWORD;
    dwRemoteAddr: DWORD;
    dwRemotePort: DWORD;
    dwOwningPid: DWORD;
  end;
  PMIB_TCPROW_OWNER_PID = ^MIB_TCPROW_OWNER_PID;

  // tcpmib.h
  MIB_TCP6ROW_OWNER_PID = record
    ucLocalAddr: array[0..15] of Byte;
    dwLocalScopeId: DWORD;
    dwLocalPort: DWORD;
    ucRemoteAddr: array[0..15] of Byte;
    dwRemoteScopeId: DWORD;
    dwRemotePort: DWORD;
    dwState: DWORD;
    dwOwningPid: DWORD;
  end;
  PMIB_TCP6ROW_OWNER_PID = ^MIB_TCP6ROW_OWNER_PID;

  // udpmib.h
  MIB_UDPROW_OWNER_PID = record
    dwLocalAddr: DWORD;
    dwLocalPort: DWORD;
    dwOwningPid: DWORD;
  end;
  PMIB_UDPROW_OWNER_PID = ^MIB_UDPROW_OWNER_PID;

  // udpmib.h
  MIB_UDP6ROW_OWNER_PID = record
    ucLocalAddr: array[0..15] of Byte;
    dwLocalScopeId: DWORD;
    dwLocalPort: DWORD;
    dwOwningPid: DWORD;
  end;
  PMIB_UDP6ROW_OWNER_PID = ^MIB_UDP6ROW_OWNER_PID;

  // Таблицы MIB_*TABLE_OWNER_PID: DWORD dwNumEntries, затем массив строк.
  // Все строки выровнены по 4 байтам, поэтому массив начинается со смещения 4.

  TReadTableFunc = reference to function(ABuffer: Pointer; var ASize: DWORD): DWORD;

// iphlpapi.h
function GetExtendedTcpTable(pTcpTable: Pointer; var pdwSize: DWORD; bOrder: BOOL;
  ulAf: ULONG; TableClass: DWORD; Reserved: ULONG): DWORD; stdcall;
  external 'iphlpapi.dll' name 'GetExtendedTcpTable';

// iphlpapi.h
function GetExtendedUdpTable(pUdpTable: Pointer; var pdwSize: DWORD; bOrder: BOOL;
  ulAf: ULONG; TableClass: DWORD; Reserved: ULONG): DWORD; stdcall;
  external 'iphlpapi.dll' name 'GetExtendedUdpTable';

/// Читает таблицу в буфер с повтором при росте таблицы.
/// ARowCount — число строк, проверенное на соответствие размеру буфера.
function ReadTable(const ARead: TReadTableFunc; ARowSize: Integer; out ABuffer: TBytes;
  out ARowCount: Integer; out AError: string): Boolean;
var
  LSize: DWORD;
  LCode: DWORD;
  LAttempt: Integer;
  LCount: Cardinal;
begin
  ABuffer := nil;
  ARowCount := 0;
  AError := '';
  LSize := 0;
  LCode := ARead(nil, LSize);
  for LAttempt := 1 to MAX_READ_ATTEMPTS do
  begin
    if LCode = NO_ERROR then
      Break;
    if LCode <> ERROR_INSUFFICIENT_BUFFER then
    begin
      AError := Format(MHL('%s (код %d)', '%s (code %d)'), [SysErrorMessage(LCode), LCode]);
      Exit(False);
    end;
    SetLength(ABuffer, Int64(LSize) + BUFFER_SLACK);
    LSize := Length(ABuffer);
    LCode := ARead(@ABuffer[0], LSize);
  end;
  if LCode <> NO_ERROR then
  begin
    AError := Format(MHL('%s (код %d)', '%s (code %d)'), [SysErrorMessage(LCode), LCode]);
    Exit(False);
  end;
  // Таблица могла оказаться пустой уже при первом вызове с nil-буфером.
  if Length(ABuffer) < SizeOf(DWORD) then
    Exit(True);

  LCount := PDWORD(@ABuffer[0])^;
  if Int64(SizeOf(DWORD)) + Int64(LCount) * ARowSize > Length(ABuffer) then
  begin
    AError := Format(MHL('некорректный размер таблицы: %u строк', 'invalid table size: %u rows'), [LCount]);
    Exit(False);
  end;
  ARowCount := Integer(LCount);
  Result := True;
end;

function RowPtr(const ABuffer: TBytes; ARowSize, AIndex: Integer): Pointer;
begin
  Result := @ABuffer[SizeOf(DWORD) + AIndex * ARowSize];
end;

{ TMHWinNetworkApi }

function TMHWinNetworkApi.ReadTcp(AIPv6: Boolean; out AItems: TArray<TMHNetConnection>;
  out AError: string): Boolean;
var
  LBuffer: TBytes;
  LCount, LRowSize, I: Integer;
  LFamily: ULONG;
  LRow4: PMIB_TCPROW_OWNER_PID;
  LRow6: PMIB_TCP6ROW_OWNER_PID;
  LItem: TMHNetConnection;
  LState: DWORD;
begin
  AItems := nil;
  if AIPv6 then
  begin
    LFamily := AF_INET6;
    LRowSize := SizeOf(MIB_TCP6ROW_OWNER_PID);
  end
  else
  begin
    LFamily := AF_INET;
    LRowSize := SizeOf(MIB_TCPROW_OWNER_PID);
  end;

  Result := ReadTable(
    function(ABuffer: Pointer; var ASize: DWORD): DWORD
    begin
      Result := GetExtendedTcpTable(ABuffer, ASize, False, LFamily, TCP_TABLE_OWNER_PID_ALL, 0);
    end, LRowSize, LBuffer, LCount, AError);
  if not Result then
    Exit;

  SetLength(AItems, LCount);
  for I := 0 to LCount - 1 do
  begin
    LItem := Default(TMHNetConnection);
    LItem.Transport := ntTcp;
    LItem.IPv6 := AIPv6;
    if AIPv6 then
    begin
      LRow6 := RowPtr(LBuffer, LRowSize, I);
      LState := LRow6.dwState;
      LItem.LocalAddress := MHFormatIPv6(LRow6.ucLocalAddr);
      LItem.LocalPort := MHNetworkToHostPort(LRow6.dwLocalPort);
      LItem.RemoteAddress := MHFormatIPv6(LRow6.ucRemoteAddr);
      LItem.RemotePort := MHNetworkToHostPort(LRow6.dwRemotePort);
      LItem.OwningPid := LRow6.dwOwningPid;
    end
    else
    begin
      LRow4 := RowPtr(LBuffer, LRowSize, I);
      LState := LRow4.dwState;
      LItem.LocalAddress := MHFormatIPv4(LRow4.dwLocalAddr);
      LItem.LocalPort := MHNetworkToHostPort(LRow4.dwLocalPort);
      LItem.RemoteAddress := MHFormatIPv4(LRow4.dwRemoteAddr);
      LItem.RemotePort := MHNetworkToHostPort(LRow4.dwRemotePort);
      LItem.OwningPid := LRow4.dwOwningPid;
    end;
    LItem.State := MHTcpStateName(LState);
    // У прослушиваемого порта удалённой стороны нет (модель: '' и 0).
    if LState = MIB_TCP_STATE_LISTEN then
    begin
      LItem.RemoteAddress := '';
      LItem.RemotePort := 0;
    end;
    AItems[I] := LItem;
  end;
end;

function TMHWinNetworkApi.ReadUdp(AIPv6: Boolean; out AItems: TArray<TMHNetConnection>;
  out AError: string): Boolean;
var
  LBuffer: TBytes;
  LCount, LRowSize, I: Integer;
  LFamily: ULONG;
  LRow4: PMIB_UDPROW_OWNER_PID;
  LRow6: PMIB_UDP6ROW_OWNER_PID;
  LItem: TMHNetConnection;
begin
  AItems := nil;
  if AIPv6 then
  begin
    LFamily := AF_INET6;
    LRowSize := SizeOf(MIB_UDP6ROW_OWNER_PID);
  end
  else
  begin
    LFamily := AF_INET;
    LRowSize := SizeOf(MIB_UDPROW_OWNER_PID);
  end;

  Result := ReadTable(
    function(ABuffer: Pointer; var ASize: DWORD): DWORD
    begin
      Result := GetExtendedUdpTable(ABuffer, ASize, False, LFamily, UDP_TABLE_OWNER_PID, 0);
    end, LRowSize, LBuffer, LCount, AError);
  if not Result then
    Exit;

  SetLength(AItems, LCount);
  for I := 0 to LCount - 1 do
  begin
    LItem := Default(TMHNetConnection);
    LItem.Transport := ntUdp;
    LItem.IPv6 := AIPv6;
    if AIPv6 then
    begin
      LRow6 := RowPtr(LBuffer, LRowSize, I);
      LItem.LocalAddress := MHFormatIPv6(LRow6.ucLocalAddr);
      LItem.LocalPort := MHNetworkToHostPort(LRow6.dwLocalPort);
      LItem.OwningPid := LRow6.dwOwningPid;
    end
    else
    begin
      LRow4 := RowPtr(LBuffer, LRowSize, I);
      LItem.LocalAddress := MHFormatIPv4(LRow4.dwLocalAddr);
      LItem.LocalPort := MHNetworkToHostPort(LRow4.dwLocalPort);
      LItem.OwningPid := LRow4.dwOwningPid;
    end;
    AItems[I] := LItem;
  end;
end;

end.
