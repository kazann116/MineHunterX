unit MineHunter.Collectors.NetAdapters.WinApi;

{
  IMHNetAdapterApi на GetIfTable2 (iphlpapi.dll, Windows Vista+): одна таблица
  с именем, типом, состоянием, скоростью канала и счётчиками байтов каждого
  интерфейса. MIB_IF_ROW2 объявлена по netioapi.h; размер для x64 (1352 байта)
  проверяется тестом.
}

interface

uses
  System.SysUtils, MineHunter.Collectors.NetAdapters;

type
  TMibIfRow2 = record
    InterfaceLuid: UInt64;
    InterfaceIndex: Cardinal;
    InterfaceGuid: TGUID;
    Alias: array[0..256] of WideChar;
    Description: array[0..256] of WideChar;
    PhysicalAddressLength: Cardinal;
    PhysicalAddress: array[0..31] of Byte;
    PermanentPhysicalAddress: array[0..31] of Byte;
    Mtu: Cardinal;
    IfType: Cardinal;
    TunnelType: Cardinal;
    MediaType: Cardinal;
    PhysicalMediumType: Cardinal;
    AccessType: Cardinal;
    DirectionType: Cardinal;
    /// Битовые флаги: 0 — HardwareInterface, 1 — FilterInterface, 2 — ConnectorPresent…
    InterfaceAndOperStatusFlags: Byte;
    OperStatus: Cardinal;
    AdminStatus: Cardinal;
    MediaConnectState: Cardinal;
    NetworkGuid: TGUID;
    ConnectionType: Cardinal;
    TransmitLinkSpeed: UInt64;
    ReceiveLinkSpeed: UInt64;
    InOctets: UInt64;
    InUcastPkts: UInt64;
    InNUcastPkts: UInt64;
    InDiscards: UInt64;
    InErrors: UInt64;
    InUnknownProtos: UInt64;
    InUcastOctets: UInt64;
    InMulticastOctets: UInt64;
    InBroadcastOctets: UInt64;
    OutOctets: UInt64;
    OutUcastPkts: UInt64;
    OutNUcastPkts: UInt64;
    OutDiscards: UInt64;
    OutErrors: UInt64;
    OutUcastOctets: UInt64;
    OutMulticastOctets: UInt64;
    OutBroadcastOctets: UInt64;
    OutQLen: UInt64;
  end;
  PMibIfRow2 = ^TMibIfRow2;

  TMHWinNetAdapterApi = class(TInterfacedObject, IMHNetAdapterApi)
  public
    function ReadAdapters(out AAdapters: TArray<TMHRawNetAdapter>; out AError: string): Boolean;
  end;

implementation

uses
  Winapi.Windows;

type
  PMibIfTable2 = ^TMibIfTable2;
  TMibIfTable2 = record
    NumEntries: Cardinal;
    // Table начинается со смещения 8 (выравнивание MIB_IF_ROW2 по 8 байт).
  end;

function GetIfTable2(out ATable: PMibIfTable2): Cardinal; stdcall; external 'iphlpapi.dll' name 'GetIfTable2';
procedure FreeMibTable(AMemory: Pointer); stdcall; external 'iphlpapi.dll' name 'FreeMibTable';

function TMHWinNetAdapterApi.ReadAdapters(out AAdapters: TArray<TMHRawNetAdapter>; out AError: string): Boolean;
var
  LTable: PMibIfTable2;
  LStatus: Cardinal;
  LRow: PMibIfRow2;
  I: Integer;
  LItem: TMHRawNetAdapter;
begin
  AAdapters := nil;
  AError := '';
  LTable := nil;
  LStatus := GetIfTable2(LTable);
  if (LStatus <> NO_ERROR) or (LTable = nil) then
  begin
    AError := SysErrorMessage(LStatus);
    Exit(False);
  end;
  try
    SetLength(AAdapters, LTable.NumEntries);
    LRow := PMibIfRow2(PByte(LTable) + 8);
    for I := 0 to Integer(LTable.NumEntries) - 1 do
    begin
      LItem := Default(TMHRawNetAdapter);
      LItem.Index := LRow.InterfaceIndex;
      LItem.Alias := string(PWideChar(@LRow.Alias[0]));
      LItem.Description := string(PWideChar(@LRow.Description[0]));
      LItem.IfType := LRow.IfType;
      LItem.Hardware := (LRow.InterfaceAndOperStatusFlags and $01) <> 0;
      LItem.FilterInterface := (LRow.InterfaceAndOperStatusFlags and $02) <> 0;
      LItem.OperStatus := LRow.OperStatus;
      LItem.LinkSpeedBps := LRow.ReceiveLinkSpeed;
      if LItem.LinkSpeedBps = UInt64(-1) then
        LItem.LinkSpeedBps := 0;
      LItem.InOctets := LRow.InOctets;
      LItem.OutOctets := LRow.OutOctets;
      AAdapters[I] := LItem;
      Inc(LRow);
    end;
    Result := True;
  finally
    FreeMibTable(LTable);
  end;
end;

end.
