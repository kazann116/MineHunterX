unit MineHunter.Collectors.NetAdapters;

{
  Сетевые адаптеры по отдельности: тип (Ethernet, Wi-Fi, мобильная сеть,
  виртуальный), подключение, скорость канала и скорость приёма и передачи.
  Скорость считается по разнице счётчиков байтов между опросами (появляется
  со второго опроса). Служебные экземпляры (фильтры, loopback) отбрасываются;
  виртуальные адаптеры показываются, только если подключены и через них
  уже шли данные.
}

interface

uses
  System.SysUtils, System.Generics.Collections,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

type
  TMHRawNetAdapter = record
    Index: Cardinal;
    Alias: string;
    Description: string;
    /// IANA ifType: 6 — Ethernet, 71 — Wi-Fi (IEEE 802.11), 243/244 — мобильная сеть, 24 — loopback.
    IfType: Cardinal;
    Hardware: Boolean;
    FilterInterface: Boolean;
    /// IF_OPER_STATUS: 1 — работает.
    OperStatus: Cardinal;
    LinkSpeedBps: UInt64;
    InOctets: UInt64;
    OutOctets: UInt64;
  end;

  IMHNetAdapterApi = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1D40}']
    function ReadAdapters(out AAdapters: TArray<TMHRawNetAdapter>; out AError: string): Boolean;
  end;

  TMHNetAdapterCollector = class(TInterfacedObject, IMHCollector)
  public const
    SourceIdValue = 'netadapters';
  private type
    TSample = record
      InOctets: UInt64;
      OutOctets: UInt64;
      Tick: UInt64;
    end;
  private
    FApi: IMHNetAdapterApi;
    FClock: IMHClock;
    FPrevious: TDictionary<Cardinal, TSample>;
  public
    constructor Create(const AApi: IMHNetAdapterApi; const AClock: IMHClock);
    destructor Destroy; override;
    function GetSourceId: string;
    function GetDisplayName: string;
    function Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
  end;

function MHNetAdapterKindOf(AIfType: Cardinal; AHardware: Boolean): TMHNetAdapterKind;
function MHNetAdapterKindToString(AKind: TMHNetAdapterKind): string;
/// «1 Гбит/с», «100 Мбит/с».
function MHFormatLinkSpeed(ABitsPerSec: UInt64): string;
/// Скорость сети в битах в секунду (десятичные приставки), как в диспетчере задач
/// и как скорость канала: «8,0 кбит/с», «152 кбит/с», «1,2 Мбит/с».
function MHFormatBitRate(ABytesPerSec: Double): string;

implementation

uses
  System.Math, System.Generics.Defaults, MineHunter.Core.Lang;

const
  IF_TYPE_ETHERNET_CSMACD = 6;
  IF_TYPE_SOFTWARE_LOOPBACK = 24;
  IF_TYPE_IEEE80211 = 71;
  IF_TYPE_WWANPP = 243;
  IF_TYPE_WWANPP2 = 244;
  IF_OPER_STATUS_UP = 1;

function MHNetAdapterKindOf(AIfType: Cardinal; AHardware: Boolean): TMHNetAdapterKind;
begin
  if not AHardware then
    Exit(nkVirtual);
  case AIfType of
    IF_TYPE_ETHERNET_CSMACD: Result := nkEthernet;
    IF_TYPE_IEEE80211: Result := nkWifi;
    IF_TYPE_WWANPP, IF_TYPE_WWANPP2: Result := nkMobile;
  else
    Result := nkOther;
  end;
end;

function MHNetAdapterKindToString(AKind: TMHNetAdapterKind): string;
begin
  case AKind of
    nkEthernet: Result := MHL('проводная (Ethernet)', 'wired (Ethernet)');
    nkWifi: Result := 'Wi-Fi';
    nkMobile: Result := MHL('мобильная сеть', 'mobile broadband');
    nkVirtual: Result := MHL('виртуальный', 'virtual');
  else
    Result := MHL('другой', 'other');
  end;
end;

function MHFormatLinkSpeed(ABitsPerSec: UInt64): string;
begin
  if ABitsPerSec = 0 then
    Result := ''
  else if ABitsPerSec >= 1000000000 then
    Result := FormatFloat('0.#', ABitsPerSec / 1000000000) + MHL(' Гбит/с', ' Gbit/s')
  else
    Result := FormatFloat('0', ABitsPerSec / 1000000) + MHL(' Мбит/с', ' Mbit/s');
end;

function MHFormatBitRate(ABytesPerSec: Double): string;
var
  LBits: Double;
begin
  LBits := Max(0.0, ABytesPerSec) * 8;
  if LBits = 0 then
    Result := MHL('0 кбит/с', '0 Kbps')
  else if LBits >= 1E9 then
    Result := FormatFloat('0.00', LBits / 1E9) + MHL(' Гбит/с', ' Gbps')
  else if LBits >= 1E6 then
    Result := FormatFloat('0.0', LBits / 1E6) + MHL(' Мбит/с', ' Mbps')
  else if LBits >= 1E4 then
    Result := FormatFloat('0', LBits / 1E3) + MHL(' кбит/с', ' Kbps')
  else
    Result := FormatFloat('0.0', LBits / 1E3) + MHL(' кбит/с', ' Kbps');
end;

{ TMHNetAdapterCollector }

constructor TMHNetAdapterCollector.Create(const AApi: IMHNetAdapterApi; const AClock: IMHClock);
begin
  inherited Create;
  if AApi = nil then
    raise EArgumentNilException.Create('AApi');
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  FApi := AApi;
  FClock := AClock;
  FPrevious := TDictionary<Cardinal, TSample>.Create;
end;

destructor TMHNetAdapterCollector.Destroy;
begin
  FPrevious.Free;
  inherited;
end;

function TMHNetAdapterCollector.GetSourceId: string;
begin
  Result := SourceIdValue;
end;

function TMHNetAdapterCollector.GetDisplayName: string;
begin
  Result := MHL('Сетевые адаптеры', 'Network adapters');
end;

function TMHNetAdapterCollector.Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
var
  LNow: TDateTime;
  LRaw: TArray<TMHRawNetAdapter>;
  LItem: TMHRawNetAdapter;
  LError: string;
  LList: TList<TMHNetAdapterInfo>;
  LInfo: TMHNetAdapterInfo;
  LCurrent: TDictionary<Cardinal, TSample>;
  LSample, LPrev: TSample;
  LTick: UInt64;
  LSeconds: Double;
begin
  LNow := ASnapshot.TimestampUtc;
  if LNow = 0 then
    LNow := FClock.NowUtc;
  if not FApi.ReadAdapters(LRaw, LError) then
    Exit(TMHCollectionResult.Create(TMHSourceStatus.Create(SourceIdValue, ssError,
      MHL('Не удалось прочитать сетевые адаптеры: ', 'Could not read network adapters: ') + LError, LNow)));
  LTick := FClock.TickMs;
  LList := TList<TMHNetAdapterInfo>.Create;
  LCurrent := TDictionary<Cardinal, TSample>.Create;
  try
    for LItem in LRaw do
    begin
      // Фильтры и loopback — служебные копии одного адаптера.
      if LItem.FilterInterface or (LItem.IfType = IF_TYPE_SOFTWARE_LOOPBACK) then
        Continue;
      // Виртуальные (VPN, Hyper-V, туннели) — только подключённые и хоть раз
      // передававшие данные (WAN Miniport, расширения коммутатора Hyper-V — шум).
      if not LItem.Hardware and ((LItem.OperStatus <> IF_OPER_STATUS_UP) or
         (LItem.InOctets + LItem.OutOctets = 0)) then
        Continue;
      LInfo := Default(TMHNetAdapterInfo);
      LInfo.Index := LItem.Index;
      LInfo.Name := LItem.Alias;
      LInfo.Description := LItem.Description;
      LInfo.Kind := MHNetAdapterKindOf(LItem.IfType, LItem.Hardware);
      LInfo.Physical := LItem.Hardware;
      LInfo.Connected := LItem.OperStatus = IF_OPER_STATUS_UP;
      if LInfo.Connected then
        LInfo.LinkSpeedBps := LItem.LinkSpeedBps;
      LSample.InOctets := LItem.InOctets;
      LSample.OutOctets := LItem.OutOctets;
      LSample.Tick := LTick;
      LCurrent.AddOrSetValue(LItem.Index, LSample);
      if FPrevious.TryGetValue(LItem.Index, LPrev) and (LTick > LPrev.Tick) and
         (LItem.InOctets >= LPrev.InOctets) and (LItem.OutOctets >= LPrev.OutOctets) then
      begin
        LSeconds := (LTick - LPrev.Tick) / 1000;
        LInfo.HasRate := True;
        LInfo.ReceiveBytesPerSec := (LItem.InOctets - LPrev.InOctets) / LSeconds;
        LInfo.SendBytesPerSec := (LItem.OutOctets - LPrev.OutOctets) / LSeconds;
      end;
      LList.Add(LInfo);
    end;
    FPrevious.Free;
    FPrevious := LCurrent;
    LCurrent := nil;
    // Сначала подключённые физические, затем остальные.
    LList.Sort(TComparer<TMHNetAdapterInfo>.Construct(
      function(const A, B: TMHNetAdapterInfo): Integer
      begin
        Result := CompareValue(Ord(B.Connected), Ord(A.Connected));
        if Result = 0 then
          Result := CompareValue(Ord(B.Physical), Ord(A.Physical));
        if Result = 0 then
          Result := CompareText(A.Name, B.Name);
      end));
    Result := TMHCollectionResult.Create(TMHSourceStatus.Create(SourceIdValue, ssSuccess, '', LNow));
    Result.Status.ItemCount := LList.Count;
    Result.NetAdapters := LList.ToArray;
  finally
    LCurrent.Free;
    LList.Free;
  end;
end;

end.
