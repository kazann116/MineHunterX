unit MineHunter.Collectors.Pdh;

{
  MineHunter X — общий доступ к счётчикам производительности Windows (PDH).

  Объявления pdh.dll отсутствуют в RTL Delphi 12; значения — из pdh.h и
  pdhmsg.h Windows SDK. Счётчики добавляются через PdhAddEnglishCounterW,
  поэтому имена не зависят от языка Windows. Счётчики с маской экземпляров
  «(*)» читаются массивом (MHPdhReadArray); новые экземпляры (процессы,
  движки GPU) появляются в массиве без пересоздания запроса.

  Права администратора не требуются. Запрос не потокобезопасен: его
  использует только поток сканера.
}

interface

uses
  Winapi.Windows;

type
  PDH_STATUS = Longint;

  TMHPdhItem = record
    Name: string;
    Value: Double;
  end;

  /// Запрос PDH с независимыми счётчиками: ошибка добавления одного счётчика
  /// не мешает остальным.
  TMHPdhQuery = class
  private
    FQuery: THandle;
    FError: string;
    FCollects: Integer;
  public
    constructor Create;
    destructor Destroy; override;
    /// 0 — счётчик недоступен (причина в LastError).
    function AddCounter(const APath: string): THandle;
    /// Снимает значения всех счётчиков; скорости доступны со второго вызова.
    function Collect: Boolean;
    /// Значение счётчика; False — нет данных (первый замер, нет экземпляра и т.п.).
    function Read(ACounter: THandle; out AValue: Double; ANoCap100: Boolean = True): Boolean;
    /// Значения всех экземпляров счётчика с маской «(*)».
    function ReadArray(ACounter: THandle; out AItems: TArray<TMHPdhItem>): Boolean;
    function IsOpen: Boolean;
    /// Сколько раз выполнен Collect (скорости требуют двух замеров).
    property Collects: Integer read FCollects;
    property LastError: string read FError;
  end;

function MHPdhErrorText(AStatus: PDH_STATUS): string;

implementation

uses
  System.SysUtils,
  MineHunter.Core.Lang;

type
  TPdhFmtCounterValue = record
    CStatus: DWORD;
    case Integer of
      0: (longValue: Longint);
      1: (doubleValue: Double);
      2: (largeValue: Int64);
  end;
  TPdhFmtCounterValueItemW = record
    szName: PWideChar;
    FmtValue: TPdhFmtCounterValue;
  end;
  PPdhFmtCounterValueItemW = ^TPdhFmtCounterValueItemW;

const
  PDH_LIB = 'pdh.dll';
  ERROR_SUCCESS_PDH = 0;
  PDH_MORE_DATA = PDH_STATUS($800007D2);
  PDH_FMT_DOUBLE = $00000200;
  PDH_FMT_NOCAP100 = $00008000;
  PDH_CSTATUS_VALID_DATA = $00000000;
  PDH_CSTATUS_NEW_DATA = $00000001;
  /// Защита от неограниченного буфера (тысячи экземпляров — норма, сотни МБ — нет).
  MAX_ARRAY_BUFFER = 16 * 1024 * 1024;

function PdhOpenQueryW(szDataSource: PWideChar; dwUserData: NativeUInt;
  out phQuery: THandle): PDH_STATUS; stdcall; external PDH_LIB name 'PdhOpenQueryW';
function PdhAddEnglishCounterW(hQuery: THandle; szFullCounterPath: PWideChar;
  dwUserData: NativeUInt; out phCounter: THandle): PDH_STATUS; stdcall;
  external PDH_LIB name 'PdhAddEnglishCounterW';
function PdhCollectQueryData(hQuery: THandle): PDH_STATUS; stdcall;
  external PDH_LIB name 'PdhCollectQueryData';
function PdhGetFormattedCounterValue(hCounter: THandle; dwFormat: DWORD;
  lpdwType: PDWORD; out pValue: TPdhFmtCounterValue): PDH_STATUS; stdcall;
  external PDH_LIB name 'PdhGetFormattedCounterValue';
function PdhGetFormattedCounterArrayW(hCounter: THandle; dwFormat: DWORD;
  var lpdwBufferSize: DWORD; var lpdwItemCount: DWORD;
  ItemBuffer: PPdhFmtCounterValueItemW): PDH_STATUS; stdcall;
  external PDH_LIB name 'PdhGetFormattedCounterArrayW';
function PdhCloseQuery(hQuery: THandle): PDH_STATUS; stdcall;
  external PDH_LIB name 'PdhCloseQuery';

function MHPdhErrorText(AStatus: PDH_STATUS): string;
begin
  Result := Format(MHL('счётчики производительности недоступны (код 0x%.8x)',
    'performance counters are unavailable (code 0x%.8x)'), [Cardinal(AStatus)]);
end;

function IsValidStatus(AStatus: DWORD): Boolean;
begin
  Result := (AStatus = PDH_CSTATUS_VALID_DATA) or (AStatus = PDH_CSTATUS_NEW_DATA);
end;

{ TMHPdhQuery }

constructor TMHPdhQuery.Create;
var
  LStatus: PDH_STATUS;
begin
  inherited Create;
  LStatus := PdhOpenQueryW(nil, 0, FQuery);
  if LStatus <> ERROR_SUCCESS_PDH then
  begin
    FQuery := 0;
    FError := MHPdhErrorText(LStatus);
  end;
end;

destructor TMHPdhQuery.Destroy;
begin
  if FQuery <> 0 then
    PdhCloseQuery(FQuery); // закрывает и все счётчики запроса
  inherited;
end;

function TMHPdhQuery.IsOpen: Boolean;
begin
  Result := FQuery <> 0;
end;

function TMHPdhQuery.AddCounter(const APath: string): THandle;
var
  LStatus: PDH_STATUS;
begin
  Result := 0;
  if FQuery = 0 then
    Exit;
  LStatus := PdhAddEnglishCounterW(FQuery, PWideChar(APath), 0, Result);
  if LStatus <> ERROR_SUCCESS_PDH then
  begin
    Result := 0;
    FError := MHPdhErrorText(LStatus);
  end;
end;

function TMHPdhQuery.Collect: Boolean;
var
  LStatus: PDH_STATUS;
begin
  if FQuery = 0 then
    Exit(False);
  LStatus := PdhCollectQueryData(FQuery);
  Result := LStatus = ERROR_SUCCESS_PDH;
  if Result then
    Inc(FCollects)
  else
    FError := MHPdhErrorText(LStatus);
end;

function TMHPdhQuery.Read(ACounter: THandle; out AValue: Double; ANoCap100: Boolean): Boolean;
var
  LValue: TPdhFmtCounterValue;
  LFormat: DWORD;
begin
  AValue := 0;
  if ACounter = 0 then
    Exit(False);
  LFormat := PDH_FMT_DOUBLE;
  if ANoCap100 then
    LFormat := LFormat or PDH_FMT_NOCAP100;
  Result := (PdhGetFormattedCounterValue(ACounter, LFormat, nil, LValue) = ERROR_SUCCESS_PDH) and
    IsValidStatus(LValue.CStatus);
  if Result then
    AValue := LValue.doubleValue;
end;

function TMHPdhQuery.ReadArray(ACounter: THandle; out AItems: TArray<TMHPdhItem>): Boolean;
var
  LSize, LCount: DWORD;
  LBuffer: TBytes;
  LStatus: PDH_STATUS;
  LItem: PPdhFmtCounterValueItemW;
  LList: TArray<TMHPdhItem>;
  I, N: Integer;
begin
  AItems := nil;
  if ACounter = 0 then
    Exit(False);
  LSize := 0;
  LCount := 0;
  LStatus := PdhGetFormattedCounterArrayW(ACounter, PDH_FMT_DOUBLE or PDH_FMT_NOCAP100,
    LSize, LCount, nil);
  if LStatus = ERROR_SUCCESS_PDH then
    Exit(True); // экземпляров нет
  if (LStatus <> PDH_MORE_DATA) or (LSize = 0) or (LSize > MAX_ARRAY_BUFFER) then
    Exit(False);
  SetLength(LBuffer, LSize);
  LStatus := PdhGetFormattedCounterArrayW(ACounter, PDH_FMT_DOUBLE or PDH_FMT_NOCAP100,
    LSize, LCount, PPdhFmtCounterValueItemW(@LBuffer[0]));
  if LStatus <> ERROR_SUCCESS_PDH then
    Exit(False);
  SetLength(LList, LCount);
  N := 0;
  LItem := PPdhFmtCounterValueItemW(@LBuffer[0]);
  for I := 0 to Integer(LCount) - 1 do
  begin
    // Экземпляры без корректного значения (только что появились) пропускаются.
    if IsValidStatus(LItem.FmtValue.CStatus) and (LItem.szName <> nil) then
    begin
      LList[N].Name := string(LItem.szName);
      LList[N].Value := LItem.FmtValue.doubleValue;
      Inc(N);
    end;
    Inc(LItem);
  end;
  SetLength(LList, N);
  AItems := LList;
  Result := True;
end;

end.
