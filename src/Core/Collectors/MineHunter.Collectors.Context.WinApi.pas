unit MineHunter.Collectors.Context.WinApi;

{
  Реализация IMHContextApi на документированных функциях Windows:
    - GetLastInputInfo + GetTickCount — время бездействия (с учётом
      переполнения 32-битного счётчика: вычитание по модулю 2^32);
    - GetForegroundWindow + GetWindowThreadProcessId — активный процесс;
    - SHQueryUserNotificationState (shell32) — полноэкранный режим:
      QUNS_BUSY, QUNS_RUNNING_D3D_FULL_SCREEN, QUNS_PRESENTATION_MODE;
    - EnumWindows — процессы с видимыми, не скрытыми DWM, не
      инструментальными окнами верхнего уровня без владельца и с заголовком;
    - WMI (WbemScripting.SWbemLocator, Win32_Process) — командные строки.
  Права администратора не требуются: для процессов других пользователей WMI
  возвращает пустую командную строку.

  ReadCommandLines вызывается из фонового потока сканера, поэтому COM
  инициализируется (MTA) и освобождается в пределах одного вызова; объекты
  WMI не переживают вызов и не передаются между потоками.
}

interface

uses
  MineHunter.Core.Types, MineHunter.Collectors.Context;

type
  TMHWinContextApi = class(TInterfacedObject, IMHContextApi)
  private
    class procedure QueryCommandLines(const APids: TArray<Cardinal>;
      out ALines: TArray<TMHProcessDetail>); static;
  public
    function UserIdleSeconds(out ASeconds: Cardinal): Boolean;
    function ForegroundPid: Cardinal;
    function FullscreenState(out AFullscreen: Boolean): Boolean;
    function VisibleWindowPids: TArray<Cardinal>;
    function ReadCommandLines(const APids: TArray<Cardinal>;
      out ALines: TArray<TMHProcessDetail>; out AError: string): Boolean;
  end;

implementation

uses
  Winapi.Windows, Winapi.ActiveX, Winapi.ShellAPI, Winapi.DwmApi,
  System.SysUtils, System.Variants, System.Win.ComObj, System.Generics.Collections,
  MineHunter.Core.Lang;

const
  // WbemScripting: WbemFlagEnum.wbemFlagForwardOnly
  wbemFlagForwardOnly = $20;

type
  TPidCollector = class
  private
    FSeen: TDictionary<Cardinal, Boolean>;
    FPids: TList<Cardinal>;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Add(APid: Cardinal);
    function ToArray: TArray<Cardinal>;
  end;

constructor TPidCollector.Create;
begin
  inherited Create;
  FSeen := TDictionary<Cardinal, Boolean>.Create;
  FPids := TList<Cardinal>.Create;
end;

destructor TPidCollector.Destroy;
begin
  FPids.Free;
  FSeen.Free;
  inherited;
end;

procedure TPidCollector.Add(APid: Cardinal);
begin
  if (APid <> 0) and not FSeen.ContainsKey(APid) then
  begin
    FSeen.Add(APid, True);
    FPids.Add(APid);
  end;
end;

function TPidCollector.ToArray: TArray<Cardinal>;
begin
  Result := FPids.ToArray;
end;

function IsCloaked(AWnd: HWND): Boolean;
var
  LCloaked: DWORD;
begin
  // Окна UWP-приложений в фоне «видимы», но скрыты DWM (cloaked).
  LCloaked := 0;
  Result := Succeeded(DwmGetWindowAttribute(AWnd, DWMWA_CLOAKED, @LCloaked, SizeOf(LCloaked))) and
    (LCloaked <> 0);
end;

function EnumVisibleWindow(AWnd: HWND; AParam: LPARAM): BOOL; stdcall;
var
  LPid: DWORD;
begin
  Result := True;
  if not IsWindowVisible(AWnd) then
    Exit;
  if GetWindow(AWnd, GW_OWNER) <> 0 then
    Exit;
  if (GetWindowLongPtr(AWnd, GWL_EXSTYLE) and WS_EX_TOOLWINDOW) <> 0 then
    Exit;
  if GetWindowTextLength(AWnd) <= 0 then
    Exit;
  if IsCloaked(AWnd) then
    Exit;
  LPid := 0;
  if GetWindowThreadProcessId(AWnd, LPid) <> 0 then
    TPidCollector(AParam).Add(LPid);
end;

{ TMHWinContextApi }

function TMHWinContextApi.UserIdleSeconds(out ASeconds: Cardinal): Boolean;
var
  LInfo: TLastInputInfo;
begin
  ASeconds := 0;
  LInfo.cbSize := SizeOf(LInfo);
  LInfo.dwTime := 0;
  Result := GetLastInputInfo(LInfo);
  if Result then
    // Разность по модулю 2^32 корректна и после переполнения GetTickCount (49,7 сут.).
    ASeconds := Cardinal(GetTickCount - LInfo.dwTime) div 1000;
end;

function TMHWinContextApi.ForegroundPid: Cardinal;
var
  LWnd: HWND;
  LPid: DWORD;
begin
  Result := 0;
  LWnd := GetForegroundWindow;
  if LWnd = 0 then
    Exit;
  LPid := 0;
  if GetWindowThreadProcessId(LWnd, LPid) <> 0 then
    Result := LPid;
end;

function TMHWinContextApi.FullscreenState(out AFullscreen: Boolean): Boolean;
var
  LState: QUERY_USER_NOTIFICATION_STATE;
begin
  AFullscreen := False;
  LState := 0;
  Result := SHQueryUserNotificationState(LState) = S_OK;
  if Result then
    AFullscreen := LState in [QUNS_BUSY, QUNS_RUNNING_D3D_FULL_SCREEN, QUNS_PRESENTATION_MODE];
end;

function TMHWinContextApi.VisibleWindowPids: TArray<Cardinal>;
var
  LCollector: TPidCollector;
begin
  LCollector := TPidCollector.Create;
  try
    EnumWindows(@EnumVisibleWindow, LPARAM(LCollector));
    Result := LCollector.ToArray;
  finally
    LCollector.Free;
  end;
end;

class procedure TMHWinContextApi.QueryCommandLines(const APids: TArray<Cardinal>;
  out ALines: TArray<TMHProcessDetail>);
var
  LLocator, LService, LObjects, LItem, LValue: OleVariant;
  LEnum: IEnumVARIANT;
  LFetched: LongWord;
  LQuery: TStringBuilder;
  LList: TList<TMHProcessDetail>;
  LDetail: TMHProcessDetail;
  LSeen: TDictionary<Cardinal, Boolean>;
  LPid: Cardinal;
begin
  // Все COM-ссылки (включая временные значения компилятора) живут только
  // внутри этой процедуры и освобождаются до CoUninitialize в вызывающем коде.
  ALines := nil;
  LQuery := TStringBuilder.Create('SELECT ProcessId, CommandLine FROM Win32_Process WHERE ');
  LSeen := TDictionary<Cardinal, Boolean>.Create;
  LList := TList<TMHProcessDetail>.Create;
  try
    for LPid in APids do
      if not LSeen.ContainsKey(LPid) then
      begin
        if LSeen.Count > 0 then
          LQuery.Append(' OR ');
        LQuery.Append('ProcessId=').Append(LPid);
        LSeen.Add(LPid, True);
      end;

    LLocator := CreateOleObject('WbemScripting.SWbemLocator');
    LService := LLocator.ConnectServer('.', 'root\CIMV2');
    LObjects := LService.ExecQuery(LQuery.ToString, 'WQL', wbemFlagForwardOnly);
    LEnum := IUnknown(LObjects._NewEnum) as IEnumVARIANT;
    while LEnum.Next(1, LItem, LFetched) = S_OK do
    begin
      LDetail := Default(TMHProcessDetail);
      LValue := LItem.ProcessId;
      LDetail.Id := TMHProcessId.Create(Cardinal(Int64(LValue)), 0);
      LValue := LItem.CommandLine;
      if not VarIsNull(LValue) and not VarIsEmpty(LValue) then
        LDetail.CommandLine := VarToStr(LValue);
      LList.Add(LDetail);
      LItem := Unassigned;
    end;
    ALines := LList.ToArray;
  finally
    LValue := Unassigned;
    LItem := Unassigned;
    LEnum := nil;
    LObjects := Unassigned;
    LService := Unassigned;
    LLocator := Unassigned;
    LList.Free;
    LSeen.Free;
    LQuery.Free;
  end;
end;

function TMHWinContextApi.ReadCommandLines(const APids: TArray<Cardinal>;
  out ALines: TArray<TMHProcessDetail>; out AError: string): Boolean;
var
  LInit: HResult;
begin
  ALines := nil;
  AError := '';
  if Length(APids) = 0 then
    Exit(True);

  LInit := CoInitializeEx(nil, COINIT_MULTITHREADED);
  // RPC_E_CHANGED_MODE: поток уже в STA (например, главный поток VCL) —
  // COM доступен, но CoUninitialize для него вызывать нельзя.
  if Failed(LInit) and (LInit <> RPC_E_CHANGED_MODE) then
  begin
    AError := Format(MHL('не удалось инициализировать COM (0x%.8x)', 'failed to initialize COM (0x%.8x)'), [Cardinal(LInit)]);
    Exit(False);
  end;
  try
    try
      QueryCommandLines(APids, ALines);
      Result := True;
    except
      on E: Exception do
      begin
        ALines := nil;
        AError := 'WMI: ' + E.Message;
        Result := False;
      end;
    end;
  finally
    // S_OK и S_FALSE требуют парного вызова CoUninitialize.
    if Succeeded(LInit) then
      CoUninitialize;
  end;
end;

end.
