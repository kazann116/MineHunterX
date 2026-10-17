unit MineHunter.Collectors.Network;

{
  Коллектор сетевых соединений (MH-05).

  Собирает таблицы TCP и UDP (IPv4 и IPv6) с привязкой к PID процесса-владельца.
  Коллектор только поставляет данные и не делает выводов о подозрительности.

  Логика отделена от Windows API интерфейсом IMHNetworkApi; реальная
  реализация — MineHunter.Collectors.Network.WinApi. Каждая из четырёх таблиц
  читается независимо: отказ одной даёт ssPartial с пояснением, отказ всех —
  ssError. Штатные отказы не приводят к исключениям.

  Здесь же — чистые функции форматирования адресов, портов и состояний TCP,
  которые проверяются unit-тестами без обращения к системе.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

type
  /// Абстракция системных вызовов для сетевого коллектора.
  IMHNetworkApi = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C71}']
    /// Таблица TCP (соединения и прослушиваемые порты) для IPv4 или IPv6.
    /// False и AError — если таблицу получить не удалось.
    function ReadTcp(AIPv6: Boolean; out AItems: TArray<TMHNetConnection>;
      out AError: string): Boolean;
    /// Таблица UDP (открытые порты) для IPv4 или IPv6.
    function ReadUdp(AIPv6: Boolean; out AItems: TArray<TMHNetConnection>;
      out AError: string): Boolean;
  end;

  TMHNetworkCollector = class(TInterfacedObject, IMHCollector)
  public const
    SourceIdValue = 'network';
  private
    FApi: IMHNetworkApi;
    FClock: IMHClock;
  public
    constructor Create(const AApi: IMHNetworkApi; const AClock: IMHClock);
    function GetSourceId: string;
    function GetDisplayName: string;
    function Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
  end;

/// IPv4-адрес в точечной записи. ANetworkOrderAddr — значение DWORD из таблиц
/// IP Helper: байты в сетевом порядке, первый октет — младший байт.
function MHFormatIPv4(ANetworkOrderAddr: Cardinal): string;
/// IPv6-адрес (16 байт в сетевом порядке) в каноническом виде RFC 5952:
/// шестнадцатеричные группы в нижнем регистре без ведущих нулей, самая длинная
/// серия из двух и более нулевых групп (первая при равенстве) заменяется на «::»;
/// IPv4-отображённые адреса — в виде ::ffff:a.b.c.d.
/// Raises EArgumentException, если длина не равна 16.
function MHFormatIPv6(const ABytes: array of Byte): string;
/// Имя состояния TCP по значению MIB_TCP_STATE ('LISTEN', 'ESTABLISHED', ...).
/// Для неизвестного значения — 'UNKNOWN(<n>)'.
function MHTcpStateName(AState: Cardinal): string;
/// Порт из поля DWORD таблиц IP Helper: сетевой порядок байт в младших 16 битах.
function MHNetworkToHostPort(AValue: Cardinal): Word;

implementation

uses
  MineHunter.Core.Lang;

const
  /// Значения MIB_TCP_STATE (tcpmib.h) 1..12.
  TCP_STATE_NAMES: array[1..12] of string = ('CLOSED', 'LISTEN', 'SYN_SENT', 'SYN_RCVD',
    'ESTABLISHED', 'FIN_WAIT1', 'FIN_WAIT2', 'CLOSE_WAIT', 'CLOSING', 'LAST_ACK',
    'TIME_WAIT', 'DELETE_TCB');

function MHFormatIPv4(ANetworkOrderAddr: Cardinal): string;
begin
  Result := Format('%d.%d.%d.%d', [ANetworkOrderAddr and $FF,
    (ANetworkOrderAddr shr 8) and $FF, (ANetworkOrderAddr shr 16) and $FF,
    (ANetworkOrderAddr shr 24) and $FF]);
end;

function MHFormatIPv6(const ABytes: array of Byte): string;
var
  LGroups: array[0..7] of Word;
  I, LBestStart, LBestLen, LRunStart, LRunLen: Integer;
  LMapped: Boolean;
begin
  if Length(ABytes) <> 16 then
    raise EArgumentException.CreateFmt(MHL('IPv6-адрес должен состоять из 16 байт, получено %d',
      'An IPv6 address must consist of 16 bytes, got %d'), [Length(ABytes)]);
  for I := 0 to 7 do
    LGroups[I] := (Word(ABytes[I * 2]) shl 8) or ABytes[I * 2 + 1];

  // IPv4-отображённый адрес ::ffff:a.b.c.d (RFC 5952, раздел 5).
  LMapped := (LGroups[5] = $FFFF);
  for I := 0 to 4 do
    if LGroups[I] <> 0 then
      LMapped := False;
  if LMapped then
    Exit(Format('::ffff:%d.%d.%d.%d', [ABytes[12], ABytes[13], ABytes[14], ABytes[15]]));

  // Поиск самой длинной серии нулевых групп (минимум две).
  LBestStart := -1;
  LBestLen := 0;
  LRunStart := -1;
  LRunLen := 0;
  for I := 0 to 7 do
    if LGroups[I] = 0 then
    begin
      if LRunStart < 0 then
      begin
        LRunStart := I;
        LRunLen := 0;
      end;
      Inc(LRunLen);
      if LRunLen > LBestLen then
      begin
        LBestStart := LRunStart;
        LBestLen := LRunLen;
      end;
    end
    else
      LRunStart := -1;
  if LBestLen < 2 then
    LBestStart := -1;

  Result := '';
  I := 0;
  while I <= 7 do
  begin
    if I = LBestStart then
    begin
      Result := Result + '::';
      Inc(I, LBestLen);
      Continue;
    end;
    if (Result <> '') and not Result.EndsWith(':') then
      Result := Result + ':';
    Result := Result + IntToHex(Integer(LGroups[I]), 1).ToLower;
    Inc(I);
  end;
end;

function MHTcpStateName(AState: Cardinal): string;
begin
  if (AState >= Low(TCP_STATE_NAMES)) and (AState <= High(TCP_STATE_NAMES)) then
    Result := TCP_STATE_NAMES[AState]
  else
    Result := Format('UNKNOWN(%u)', [AState]);
end;

function MHNetworkToHostPort(AValue: Cardinal): Word;
begin
  Result := Word(((AValue and $FF) shl 8) or ((AValue shr 8) and $FF));
end;

{ TMHNetworkCollector }

constructor TMHNetworkCollector.Create(const AApi: IMHNetworkApi; const AClock: IMHClock);
begin
  inherited Create;
  if AApi = nil then
    raise EArgumentNilException.Create('AApi');
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  FApi := AApi;
  FClock := AClock;
end;

function TMHNetworkCollector.GetSourceId: string;
begin
  Result := SourceIdValue;
end;

function TMHNetworkCollector.GetDisplayName: string;
begin
  Result := MHL('Сетевые соединения', 'Network connections');
end;

function TMHNetworkCollector.Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
const
  TABLE_NAMES: array[0..3] of string = ('TCP IPv4', 'TCP IPv6', 'UDP IPv4', 'UDP IPv6');
var
  LNow: TDateTime;
  LAll, LItems: TArray<TMHNetConnection>;
  LErrors: TArray<string>;
  LError: string;
  LOk: Boolean;
  LFailed, I: Integer;
  LState: TMHSourceState;
  LMessage: string;
begin
  LNow := ASnapshot.TimestampUtc;
  if LNow = 0 then
    LNow := FClock.NowUtc;

  LAll := nil;
  LErrors := nil;
  LFailed := 0;
  for I := 0 to High(TABLE_NAMES) do
  begin
    LItems := nil;
    LError := '';
    try
      if I < 2 then
        LOk := FApi.ReadTcp(I = 1, LItems, LError)
      else
        LOk := FApi.ReadUdp(I = 3, LItems, LError);
    except
      // Сбой одной таблицы не должен лишать данных остальных.
      on E: Exception do
      begin
        LOk := False;
        LError := E.Message;
      end;
    end;
    if LOk then
      LAll := LAll + LItems
    else
    begin
      Inc(LFailed);
      if LError = '' then
        LError := MHL('причина неизвестна', 'unknown reason');
      LErrors := LErrors + [Format(MHL('таблица %s: %s', 'table %s: %s'), [TABLE_NAMES[I], LError])];
    end;
  end;

  if LFailed = 0 then
  begin
    LState := ssSuccess;
    LMessage := '';
  end
  else if LFailed = Length(TABLE_NAMES) then
  begin
    LState := ssError;
    LMessage := MHL('Не удалось получить сетевые таблицы: ', 'Failed to get network tables: ') + string.Join('; ', LErrors) + '.';
  end
  else
  begin
    LState := ssPartial;
    LMessage := MHL('Часть сетевых таблиц недоступна: ', 'Some network tables are unavailable: ') + string.Join('; ', LErrors) + '.';
  end;

  Result := TMHCollectionResult.Create(TMHSourceStatus.Create(SourceIdValue, LState,
    LMessage, LNow));
  Result.Status.ItemCount := Length(LAll);
  Result.Connections := LAll;
end;

end.
