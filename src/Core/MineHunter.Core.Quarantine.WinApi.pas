unit MineHunter.Core.Quarantine.WinApi;

{
  Реализация IMHQuarantineOps на документированных функциях Windows:
    - файлы: MoveFileEx (MOVEFILE_COPY_ALLOWED — перенос между дисками),
      GetFileAttributes/SetFileAttributes, DeleteFile, потоковый SHA-256;
    - манифест записывается атомарно (временный файл + MoveFileEx с заменой);
    - реестр: RegOpenKeyEx/RegQueryValueEx/RegSetValueEx/RegDeleteValue
      в 64-битном представлении (KEY_WOW64_64KEY);
    - службы: OpenSCManager/OpenService/QueryServiceConfig/ChangeServiceConfig;
    - задания: COM «Schedule.Service» (ITaskService), свойство Enabled.
  Права не повышаются: отказ в доступе возвращается как rorAccessDenied.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Quarantine;

type
  TMHWinQuarantineOps = class(TInterfacedObject, IMHQuarantineOps)
  public
    function WindowsDir: string;
    function SelfPath: string;
    function FileExists(const APath: string): Boolean;
    function GetAttributes(const APath: string; out AAttributes: Cardinal): Boolean;
    function SetAttributes(const APath: string; AAttributes: Cardinal): Boolean;
    function MoveFile(const ASource, ADest: string; out AError: string; out AAccessDenied: Boolean): Boolean;
    function DeleteFile(const APath: string; out AError: string): Boolean;
    function ForceDirectories(const APath: string): Boolean;
    function RemoveDirectory(const APath: string): Boolean;
    function ListDirectories(const APath: string): TArray<string>;
    function FileSha256(const APath: string; out ASha256: string; out ASize: Int64): Boolean;
    function ReadTextFile(const APath: string; out AText: string): Boolean;
    function WriteTextFile(const APath, AText: string): Boolean;
    function RegReadValue(const AKey, AName: string; out AType: Cardinal; out AData: TBytes;
      out AError: string): TMHRegOpResult;
    function RegWriteValue(const AKey, AName: string; AType: Cardinal; const AData: TBytes;
      out AError: string): TMHRegOpResult;
    function RegDeleteValue(const AKey, AName: string; out AError: string): TMHRegOpResult;
    function ServiceGetStartType(const AName: string; out AStartType: Cardinal; out AError: string): TMHRegOpResult;
    function ServiceSetStartType(const AName: string; AStartType: Cardinal; out AError: string): TMHRegOpResult;
    function TaskSetEnabled(const APath: string; AEnabled: Boolean; out AError: string): TMHRegOpResult;
  end;

implementation

uses
  Winapi.Windows, Winapi.WinSvc, Winapi.ActiveX, System.Classes, System.IOUtils, System.Hash,
  System.Variants, System.Win.ComObj;

const
  ERROR_SERVICE_DOES_NOT_EXIST_CODE = 1060;
  HR_FILE_NOT_FOUND = HRESULT($80070002);
  HR_PATH_NOT_FOUND = HRESULT($80070003);
  HR_ACCESS_DENIED = HRESULT($80070005);

function MapError(ACode: Cardinal): TMHRegOpResult;
begin
  case ACode of
    ERROR_SUCCESS: Result := rorOk;
    ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SERVICE_DOES_NOT_EXIST_CODE: Result := rorNotFound;
    ERROR_ACCESS_DENIED: Result := rorAccessDenied;
  else
    Result := rorFailed;
  end;
end;

/// «HKLM\SOFTWARE\…» -> корень и подраздел.
function SplitKey(const AKey: string; out ARoot: HKEY; out ASubKey: string): Boolean;
var
  LPos: Integer;
  LRoot: string;
begin
  LPos := Pos('\', AKey);
  Result := LPos > 0;
  if not Result then
    Exit;
  LRoot := Copy(AKey, 1, LPos - 1).ToUpper;
  ASubKey := Copy(AKey, LPos + 1, MaxInt);
  if (LRoot = 'HKLM') or (LRoot = 'HKEY_LOCAL_MACHINE') then
    ARoot := HKEY_LOCAL_MACHINE
  else if (LRoot = 'HKCU') or (LRoot = 'HKEY_CURRENT_USER') then
    ARoot := HKEY_CURRENT_USER
  else
    Result := False;
end;

{ TMHWinQuarantineOps }

function TMHWinQuarantineOps.WindowsDir: string;
var
  LBuffer: array[0..MAX_PATH] of Char;
begin
  SetString(Result, LBuffer, GetWindowsDirectory(LBuffer, MAX_PATH));
end;

function TMHWinQuarantineOps.SelfPath: string;
begin
  Result := ParamStr(0);
end;

function TMHWinQuarantineOps.FileExists(const APath: string): Boolean;
begin
  Result := System.SysUtils.FileExists(APath, False);
end;

function TMHWinQuarantineOps.GetAttributes(const APath: string; out AAttributes: Cardinal): Boolean;
begin
  AAttributes := GetFileAttributes(PChar(APath));
  Result := AAttributes <> INVALID_FILE_ATTRIBUTES;
  if not Result then
    AAttributes := 0;
end;

function TMHWinQuarantineOps.SetAttributes(const APath: string; AAttributes: Cardinal): Boolean;
begin
  if AAttributes = 0 then
    AAttributes := FILE_ATTRIBUTE_NORMAL;
  Result := SetFileAttributes(PChar(APath), AAttributes);
end;

function TMHWinQuarantineOps.MoveFile(const ASource, ADest: string; out AError: string;
  out AAccessDenied: Boolean): Boolean;
var
  LCode: Cardinal;
begin
  AError := '';
  AAccessDenied := False;
  Result := MoveFileEx(PChar(ASource), PChar(ADest), MOVEFILE_COPY_ALLOWED or MOVEFILE_WRITE_THROUGH);
  if not Result then
  begin
    LCode := GetLastError;
    AAccessDenied := LCode = ERROR_ACCESS_DENIED;
    AError := SysErrorMessage(LCode);
  end;
end;

function TMHWinQuarantineOps.DeleteFile(const APath: string; out AError: string): Boolean;
begin
  AError := '';
  Result := Winapi.Windows.DeleteFile(PChar(APath));
  if not Result then
    AError := SysErrorMessage(GetLastError);
end;

function TMHWinQuarantineOps.ForceDirectories(const APath: string): Boolean;
begin
  Result := System.SysUtils.ForceDirectories(APath);
end;

function TMHWinQuarantineOps.RemoveDirectory(const APath: string): Boolean;
begin
  Result := RemoveDir(APath);
end;

function TMHWinQuarantineOps.ListDirectories(const APath: string): TArray<string>;
begin
  if TDirectory.Exists(APath) then
    Result := TDirectory.GetDirectories(APath)
  else
    Result := nil;
end;

function TMHWinQuarantineOps.FileSha256(const APath: string; out ASha256: string; out ASize: Int64): Boolean;
var
  LStream: TFileStream;
  LHash: THashSHA2;
  LBuffer: TBytes;
  LRead: Integer;
begin
  ASha256 := '';
  ASize := -1;
  try
    LStream := TFileStream.Create(APath, fmOpenRead or fmShareDenyNone);
    try
      ASize := LStream.Size;
      LHash := THashSHA2.Create(SHA256);
      SetLength(LBuffer, 1024 * 1024);
      repeat
        LRead := LStream.Read(LBuffer[0], Length(LBuffer));
        if LRead > 0 then
          LHash.Update(LBuffer, LRead);
      until LRead <= 0;
      ASha256 := LHash.HashAsString.ToLower;
    finally
      LStream.Free;
    end;
    Result := True;
  except
    Result := False;
  end;
end;

function TMHWinQuarantineOps.ReadTextFile(const APath: string; out AText: string): Boolean;
begin
  AText := '';
  try
    Result := System.SysUtils.FileExists(APath);
    if Result then
      AText := TFile.ReadAllText(APath, TEncoding.UTF8);
  except
    Result := False;
  end;
end;

function TMHWinQuarantineOps.WriteTextFile(const APath, AText: string): Boolean;
var
  LTemp: string;
begin
  // Атомарно: временный файл рядом, затем замена — манифест не останется недописанным.
  LTemp := APath + '.tmp';
  try
    TFile.WriteAllText(LTemp, AText, TEncoding.UTF8);
    Result := MoveFileEx(PChar(LTemp), PChar(APath), MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH);
    if not Result then
      Winapi.Windows.DeleteFile(PChar(LTemp));
  except
    Result := False;
  end;
end;

function OpenRegKey(const AKey: string; AAccess: REGSAM; out AHandle: HKEY; out AError: string): TMHRegOpResult;
var
  LRoot: HKEY;
  LSubKey: string;
  LStatus: Longint;
begin
  AError := '';
  if not SplitKey(AKey, LRoot, LSubKey) then
  begin
    AError := 'неизвестный раздел реестра: ' + AKey;
    Exit(rorFailed);
  end;
  LStatus := RegOpenKeyEx(LRoot, PChar(LSubKey), 0, AAccess or KEY_WOW64_64KEY, AHandle);
  Result := MapError(Cardinal(LStatus));
  if Result <> rorOk then
    AError := SysErrorMessage(Cardinal(LStatus));
end;

function TMHWinQuarantineOps.RegReadValue(const AKey, AName: string; out AType: Cardinal;
  out AData: TBytes; out AError: string): TMHRegOpResult;
var
  LKey: HKEY;
  LSize: DWORD;
  LStatus: Longint;
begin
  AType := 0;
  AData := nil;
  Result := OpenRegKey(AKey, KEY_QUERY_VALUE, LKey, AError);
  if Result <> rorOk then
    Exit;
  try
    LSize := 0;
    LStatus := RegQueryValueEx(LKey, PChar(AName), nil, @AType, nil, @LSize);
    if LStatus = ERROR_SUCCESS then
    begin
      SetLength(AData, LSize);
      if LSize > 0 then
        LStatus := RegQueryValueEx(LKey, PChar(AName), nil, @AType, @AData[0], @LSize);
    end;
    Result := MapError(Cardinal(LStatus));
    if Result <> rorOk then
      AError := SysErrorMessage(Cardinal(LStatus));
  finally
    RegCloseKey(LKey);
  end;
end;

function TMHWinQuarantineOps.RegWriteValue(const AKey, AName: string; AType: Cardinal;
  const AData: TBytes; out AError: string): TMHRegOpResult;
var
  LKey: HKEY;
  LStatus: Longint;
  LRoot: HKEY;
  LSubKey: string;
  LDisposition: DWORD;
begin
  AError := '';
  if not SplitKey(AKey, LRoot, LSubKey) then
    Exit(rorFailed);
  // Раздел мог быть удалён вместе с последним значением — создаётся заново.
  LStatus := RegCreateKeyEx(LRoot, PChar(LSubKey), 0, nil, REG_OPTION_NON_VOLATILE,
    KEY_SET_VALUE or KEY_WOW64_64KEY, nil, LKey, @LDisposition);
  Result := MapError(Cardinal(LStatus));
  if Result <> rorOk then
  begin
    AError := SysErrorMessage(Cardinal(LStatus));
    Exit;
  end;
  try
    if Length(AData) > 0 then
      LStatus := RegSetValueEx(LKey, PChar(AName), 0, AType, @AData[0], Length(AData))
    else
      LStatus := RegSetValueEx(LKey, PChar(AName), 0, AType, nil, 0);
    Result := MapError(Cardinal(LStatus));
    if Result <> rorOk then
      AError := SysErrorMessage(Cardinal(LStatus));
  finally
    RegCloseKey(LKey);
  end;
end;

function TMHWinQuarantineOps.RegDeleteValue(const AKey, AName: string; out AError: string): TMHRegOpResult;
var
  LKey: HKEY;
  LStatus: Longint;
begin
  Result := OpenRegKey(AKey, KEY_SET_VALUE, LKey, AError);
  if Result <> rorOk then
    Exit;
  try
    LStatus := Winapi.Windows.RegDeleteValue(LKey, PChar(AName));
    Result := MapError(Cardinal(LStatus));
    if Result <> rorOk then
      AError := SysErrorMessage(Cardinal(LStatus));
  finally
    RegCloseKey(LKey);
  end;
end;

function TMHWinQuarantineOps.ServiceGetStartType(const AName: string; out AStartType: Cardinal;
  out AError: string): TMHRegOpResult;
var
  LManager, LService: SC_HANDLE;
  LNeeded: DWORD;
  LBuffer: TBytes;
begin
  AStartType := 0;
  AError := '';
  LManager := OpenSCManager(nil, nil, SC_MANAGER_CONNECT);
  if LManager = 0 then
  begin
    AError := SysErrorMessage(GetLastError);
    Exit(MapError(GetLastError));
  end;
  try
    LService := OpenService(LManager, PChar(AName), SERVICE_QUERY_CONFIG);
    if LService = 0 then
    begin
      Result := MapError(GetLastError);
      AError := SysErrorMessage(GetLastError);
      Exit;
    end;
    try
      LNeeded := 0;
      QueryServiceConfig(LService, nil, 0, LNeeded);
      if LNeeded = 0 then
        Exit(rorFailed);
      SetLength(LBuffer, LNeeded);
      if not QueryServiceConfig(LService, PQueryServiceConfig(@LBuffer[0]), LNeeded, LNeeded) then
      begin
        AError := SysErrorMessage(GetLastError);
        Exit(rorFailed);
      end;
      AStartType := PQueryServiceConfig(@LBuffer[0]).dwStartType;
      Result := rorOk;
    finally
      CloseServiceHandle(LService);
    end;
  finally
    CloseServiceHandle(LManager);
  end;
end;

function TMHWinQuarantineOps.ServiceSetStartType(const AName: string; AStartType: Cardinal;
  out AError: string): TMHRegOpResult;
var
  LManager, LService: SC_HANDLE;
begin
  AError := '';
  LManager := OpenSCManager(nil, nil, SC_MANAGER_CONNECT);
  if LManager = 0 then
  begin
    AError := SysErrorMessage(GetLastError);
    Exit(MapError(GetLastError));
  end;
  try
    LService := OpenService(LManager, PChar(AName), SERVICE_CHANGE_CONFIG);
    if LService = 0 then
    begin
      Result := MapError(GetLastError);
      AError := SysErrorMessage(GetLastError);
      Exit;
    end;
    try
      if ChangeServiceConfig(LService, SERVICE_NO_CHANGE, AStartType, SERVICE_NO_CHANGE, nil, nil, nil, nil,
         nil, nil, nil) then
        Result := rorOk
      else
      begin
        Result := MapError(GetLastError);
        AError := SysErrorMessage(GetLastError);
      end;
    finally
      CloseServiceHandle(LService);
    end;
  finally
    CloseServiceHandle(LManager);
  end;
end;

function TMHWinQuarantineOps.TaskSetEnabled(const APath: string; AEnabled: Boolean;
  out AError: string): TMHRegOpResult;
var
  LInit: HResult;
  LService, LRoot, LTask: OleVariant;
begin
  AError := '';
  LInit := CoInitializeEx(nil, COINIT_APARTMENTTHREADED);
  if Failed(LInit) and (LInit <> RPC_E_CHANGED_MODE) then
  begin
    AError := Format('COM недоступен (0x%.8x)', [Cardinal(LInit)]);
    Exit(rorFailed);
  end;
  try
    try
      LService := CreateOleObject('Schedule.Service');
      LService.Connect;
      LRoot := LService.GetFolder('\');
      LTask := LRoot.GetTask(APath);
      LTask.Enabled := AEnabled;
      Result := rorOk;
    except
      on E: EOleException do
      begin
        AError := E.Message;
        if (E.ErrorCode = HR_FILE_NOT_FOUND) or (E.ErrorCode = HR_PATH_NOT_FOUND) then
          Result := rorNotFound
        else if E.ErrorCode = HR_ACCESS_DENIED then
          Result := rorAccessDenied
        else
          Result := rorFailed;
      end;
      on E: Exception do
      begin
        AError := E.Message;
        Result := rorFailed;
      end;
    end;
  finally
    LTask := Unassigned;
    LRoot := Unassigned;
    LService := Unassigned;
    if Succeeded(LInit) then
      CoUninitialize;
  end;
end;

end.
