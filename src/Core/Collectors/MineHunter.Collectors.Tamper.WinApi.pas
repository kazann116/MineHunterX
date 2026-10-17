unit MineHunter.Collectors.Tamper.WinApi;

{
  Реализация IMHTamperApi на документированных механизмах Windows:
    - WMI root\subscription: CommandLineEventConsumer, ActiveScriptEventConsumer,
      __FilterToConsumerBinding (только администратор);
    - реестр (только чтение, 64-битное представление):
        HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\(Paths, Processes, Extensions)
        и то же в Policies (только администратор);
        Image File Execution Options\<программа>\Debugger (и WOW6432Node),
        SilentProcessExit\<программа>\MonitorProcess;
        политики System (DisableTaskMgr, DisableRegistryTools, EnableLUA),
        Windows\System (DisableCMD), Windows Defender (Disable*);
        Tcpip\Parameters\DataBasePath — каталог файла hosts;
    - файл hosts (до MAX_HOSTS_BYTES).
  Ничего не изменяет. COM-объекты живут только внутри вызова.
}

interface

uses
  MineHunter.Core.Types, MineHunter.Collectors.Tamper;

type
  TMHWinTamperApi = class(TInterfacedObject, IMHTamperApi)
  private
    class function QueryWmi(out AEntries: TArray<TMHTamperEntry>): Boolean; static;
  public
    function ReadWmiSubscriptions(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;
    function ReadDefenderExclusions(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;
    function ReadExecutionHijacks(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;
    function ReadHostsFile(out AText, APath, ADefaultPath: string; out AError: string): Boolean;
    function ReadPolicies(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;
    function IsManagedComputer: Boolean;
  end;

implementation

uses
  Winapi.Windows, Winapi.ActiveX, System.SysUtils, System.Classes, System.Variants,
  System.Win.ComObj, System.Generics.Collections, System.Math, System.StrUtils,
  MineHunter.Core.Paths, MineHunter.Collectors.Autostart, MineHunter.Analysis.Indicators;

const
  IFEO_KEY = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options';
  IFEO_WOW_KEY = 'SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options';
  SILENT_EXIT_KEY = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit';
  DEFENDER_EXCL_KEY = 'SOFTWARE\Microsoft\Windows Defender\Exclusions';
  DEFENDER_POLICY_EXCL_KEY = 'SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions';
  TCPIP_KEY = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters';
  MAX_HOSTS_BYTES = 8 * 1024 * 1024;
  WBEM_E_ACCESS_DENIED = HRESULT($80041003);
  wbemFlagForwardOnly = $00000020;
  ADMIN_REQUIRED = 'видны только с правами администратора';

type
  TRegResult = (rrOk, rrMissing, rrDenied, rrError);

const
  NETSETUP_DOMAIN_NAME = 3;
  MAX_DIR_SCAN = 300;

function NetGetJoinInformation(lpServer: PWideChar; out lpNameBuffer: PWideChar;
  out BufferType: DWORD): DWORD; stdcall; external 'netapi32.dll' name 'NetGetJoinInformation';
function NetApiBufferFree(Buffer: Pointer): DWORD; stdcall; external 'netapi32.dll' name 'NetApiBufferFree';

/// Сведения о файле исключения: существует ли, скрыт ли, что лежит рядом.
function DescribeExcludedTarget(const APath: string): string;
var
  LAttr: DWORD;
  LDir: string;
  LSearch: TSearchRec;
  LCount: Integer;
  LFound: string;
begin
  Result := '';
  if APath = '' then
    Exit;
  LAttr := GetFileAttributes(PChar(APath));
  if LAttr = INVALID_FILE_ATTRIBUTES then
    Exit('; файла нет на диске');
  if LAttr and FILE_ATTRIBUTE_DIRECTORY <> 0 then
    LDir := APath
  else
  begin
    LDir := ExtractFileDir(APath);
    if (LAttr and FILE_ATTRIBUTE_HIDDEN <> 0) and (LAttr and FILE_ATTRIBUTE_SYSTEM <> 0) then
      Result := Result + '; файл скрытый и системный';
  end;
  // Слишком общие папки (корень диска, ProgramData целиком) не просматриваются.
  if (LDir = '') or (Length(ExcludeTrailingPathDelimiter(LDir)) <= 3) or
     (ExtractFileName(ExcludeTrailingPathDelimiter(LDir)).ToLower = 'programdata') then
    Exit;
  LFound := '';
  LCount := 0;
  if FindFirst(IncludeTrailingPathDelimiter(LDir) + '*', faAnyFile, LSearch) = 0 then
    try
      repeat
        Inc(LCount);
        if MHIsMinerArtifact(LSearch.Name) and not LFound.Contains(LSearch.Name) then
          LFound := LFound + IfThen(LFound <> '', ', ', '') + LSearch.Name;
      until (LCount >= MAX_DIR_SCAN) or (FindNext(LSearch) <> 0);
    finally
      FindClose(LSearch);
    end;
  if LFound <> '' then
    Result := Result + '; рядом: ' + LFound;
end;

function ExpandEnvironmentText(const AText: string): string;
var
  LSize: DWORD;
begin
  if AText = '' then
    Exit('');
  LSize := ExpandEnvironmentStrings(PChar(AText), nil, 0);
  if LSize = 0 then
    Exit(AText);
  SetLength(Result, LSize);
  LSize := ExpandEnvironmentStrings(PChar(AText), PChar(Result), LSize);
  if LSize = 0 then
    Exit(AText);
  SetLength(Result, LSize - 1);
end;

function RootName(ARoot: HKEY): string;
begin
  if ARoot = HKEY_LOCAL_MACHINE then
    Result := 'HKLM\'
  else
    Result := 'HKCU\';
end;

function OpenKey(ARoot: HKEY; const APath: string; out AKey: HKEY): TRegResult;
var
  LStatus: Longint;
begin
  LStatus := RegOpenKeyEx(ARoot, PChar(APath), 0, KEY_READ or KEY_WOW64_64KEY, AKey);
  case LStatus of
    ERROR_SUCCESS: Result := rrOk;
    ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND: Result := rrMissing;
    ERROR_ACCESS_DENIED: Result := rrDenied;
  else
    Result := rrError;
  end;
end;

/// Строковое или числовое значение как текст ('' — нет значения).
function ReadValue(AKey: HKEY; const AName: string): string;
var
  LType, LSize: DWORD;
  LBuffer: TBytes;
  LDword: DWORD;
begin
  Result := '';
  LSize := 0;
  if RegQueryValueEx(AKey, PChar(AName), nil, @LType, nil, @LSize) <> ERROR_SUCCESS then
    Exit;
  case LType of
    REG_SZ, REG_EXPAND_SZ:
      begin
        if (LSize = 0) or (LSize > 65536) then
          Exit;
        SetLength(LBuffer, LSize + 2);
        FillChar(LBuffer[0], Length(LBuffer), 0);
        if RegQueryValueEx(AKey, PChar(AName), nil, nil, @LBuffer[0], @LSize) = ERROR_SUCCESS then
          Result := string(PChar(@LBuffer[0]));
      end;
    REG_DWORD:
      begin
        LSize := SizeOf(LDword);
        if RegQueryValueEx(AKey, PChar(AName), nil, nil, @LDword, @LSize) = ERROR_SUCCESS then
          Result := IntToStr(LDword);
      end;
  end;
end;

function SubKeyNames(AKey: HKEY): TArray<string>;
var
  LIndex, LLen: DWORD;
  LName: array[0..511] of Char;
  LText: string;
begin
  Result := nil;
  LIndex := 0;
  while True do
  begin
    LLen := Length(LName);
    if RegEnumKeyEx(AKey, LIndex, @LName[0], LLen, nil, nil, nil, nil) <> ERROR_SUCCESS then
      Break;
    SetString(LText, PChar(@LName[0]), LLen);
    Result := Result + [LText];
    Inc(LIndex);
  end;
end;

function ValueNames(AKey: HKEY): TArray<string>;
var
  LIndex, LLen: DWORD;
  LName: array[0..32767] of Char;
  LText: string;
begin
  Result := nil;
  LIndex := 0;
  while True do
  begin
    LLen := Length(LName);
    if RegEnumValue(AKey, LIndex, @LName[0], LLen, nil, nil, nil, nil) <> ERROR_SUCCESS then
      Break;
    SetString(LText, PChar(@LName[0]), LLen);
    Result := Result + [LText];
    Inc(LIndex);
  end;
end;

function WindowsDir: string;
var
  LBuffer: array[0..MAX_PATH] of Char;
begin
  SetString(Result, LBuffer, GetWindowsDirectory(LBuffer, MAX_PATH));
end;

function ExecutableOf(const ACommand: string): string;
begin
  Result := MHExtractExecutable(ACommand, WindowsDir,
    function(APath: string): Boolean
    begin
      Result := System.SysUtils.FileExists(APath);
    end);
  if Result <> '' then
    Result := MHNormalizePath(Result);
end;

{ TMHWinTamperApi }

class function TMHWinTamperApi.QueryWmi(out AEntries: TArray<TMHTamperEntry>): Boolean;
var
  LLocator, LService, LObjects, LItem, LValue, LFilter: OleVariant;
  LEnum: IEnumVARIANT;
  LFetched: LongWord;
  LBound: TDictionary<string, string>;
  LList: TList<TMHTamperEntry>;
  LEntry: TMHTamperEntry;
  LConsumer, LFilterPath, LName, LQuery, LCommand: string;
  LPos: Integer;

  function NameFromPath(const APath: string): string;
  var
    LStart: Integer;
  begin
    // __EventFilter.Name="X" / CommandLineEventConsumer.Name="Y"
    LStart := Pos('Name="', APath);
    if LStart = 0 then
      Exit(APath);
    Result := Copy(APath, LStart + 6, MaxInt);
    if Result.EndsWith('"') then
      SetLength(Result, Length(Result) - 1);
    Result := Result.Replace('\"', '"').Replace('\\', '\');
  end;

  procedure ReadConsumers(const AClass: string; AScript: Boolean);
  begin
    LObjects := LService.ExecQuery('SELECT * FROM ' + AClass, 'WQL', wbemFlagForwardOnly);
    LEnum := IUnknown(LObjects._NewEnum) as IEnumVARIANT;
    while LEnum.Next(1, LItem, LFetched) = S_OK do
    begin
      LValue := LItem.Name;
      LName := VarToStr(LValue);
      if AScript then
      begin
        LValue := LItem.ScriptFileName;
        LCommand := VarToStr(LValue);
        if LCommand = '' then
        begin
          LValue := LItem.ScriptText;
          LCommand := Copy(VarToStr(LValue), 1, 2000);
        end;
      end
      else
      begin
        LValue := LItem.CommandLineTemplate;
        LCommand := VarToStr(LValue);
        if LCommand = '' then
        begin
          LValue := LItem.ExecutablePath;
          LCommand := VarToStr(LValue);
        end;
      end;
      LEntry := TMHTamperEntry.Create(tpWmiSubscription, LName, LCommand, 'root\subscription');
      if AScript then
        LEntry.Details := 'сценарий (ActiveScriptEventConsumer)'
      else
      begin
        LEntry.Details := 'команда (CommandLineEventConsumer)';
        LEntry.ImagePath := ExecutableOf(LCommand);
      end;
      if LBound.TryGetValue(AClass + '|' + LName.ToLower, LQuery) then
        LEntry.Details := LEntry.Details + '; срабатывает по запросу: ' + Copy(LQuery, 1, 300)
      else
        LEntry.Details := LEntry.Details + '; не привязана к событию';
      LList.Add(LEntry);
      LItem := Unassigned;
    end;
    LEnum := nil;
    LObjects := Unassigned;
  end;

begin
  AEntries := nil;
  LBound := TDictionary<string, string>.Create;
  LList := TList<TMHTamperEntry>.Create;
  try
    LLocator := CreateOleObject('WbemScripting.SWbemLocator');
    LService := LLocator.ConnectServer('.', 'root\subscription');
    // Привязки: какой потребитель к какому фильтру (событию) подключён.
    LObjects := LService.ExecQuery('SELECT * FROM __FilterToConsumerBinding', 'WQL', wbemFlagForwardOnly);
    LEnum := IUnknown(LObjects._NewEnum) as IEnumVARIANT;
    while LEnum.Next(1, LItem, LFetched) = S_OK do
    begin
      LValue := LItem.Consumer;
      LConsumer := VarToStr(LValue);
      LValue := LItem.Filter;
      LFilterPath := VarToStr(LValue);
      LQuery := '';
      try
        LFilter := LService.Get(LFilterPath);
        LValue := LFilter.Query;
        LQuery := VarToStr(LValue);
      except
        LQuery := NameFromPath(LFilterPath);
      end;
      LFilter := Unassigned;
      LPos := Pos('.', LConsumer);
      if LPos > 0 then
        LBound.AddOrSetValue(Copy(LConsumer, 1, LPos - 1) + '|' + NameFromPath(LConsumer).ToLower, LQuery);
      LItem := Unassigned;
    end;
    LEnum := nil;
    LObjects := Unassigned;
    ReadConsumers('CommandLineEventConsumer', False);
    ReadConsumers('ActiveScriptEventConsumer', True);
    AEntries := LList.ToArray;
    Result := True;
  finally
    LValue := Unassigned;
    LItem := Unassigned;
    LFilter := Unassigned;
    LEnum := nil;
    LObjects := Unassigned;
    LService := Unassigned;
    LLocator := Unassigned;
    LList.Free;
    LBound.Free;
  end;
end;

function TMHWinTamperApi.ReadWmiSubscriptions(out AEntries: TArray<TMHTamperEntry>;
  out AError: string): Boolean;
var
  LInit: HResult;
begin
  AEntries := nil;
  AError := '';
  LInit := CoInitializeEx(nil, COINIT_MULTITHREADED);
  if Failed(LInit) and (LInit <> RPC_E_CHANGED_MODE) then
  begin
    AError := Format('не удалось инициализировать COM (0x%.8x)', [Cardinal(LInit)]);
    Exit(False);
  end;
  try
    try
      Result := QueryWmi(AEntries);
    except
      on E: EOleException do
      begin
        if (E.ErrorCode = WBEM_E_ACCESS_DENIED) or (E.ErrorCode = E_ACCESSDENIED) then
          AError := ADMIN_REQUIRED
        else
          AError := 'WMI: ' + E.Message;
        Result := False;
      end;
      on E: Exception do
      begin
        AError := 'WMI: ' + E.Message;
        Result := False;
      end;
    end;
  finally
    if Succeeded(LInit) then
      CoUninitialize;
  end;
end;

function TMHWinTamperApi.ReadDefenderExclusions(out AEntries: TArray<TMHTamperEntry>;
  out AError: string): Boolean;
const
  KINDS: array[0..3] of string = ('Paths', 'Processes', 'Extensions', 'IpAddresses');
  KIND_TEXT: array[0..3] of string = ('путь', 'процесс', 'расширение', 'IP-адрес');
var
  LBase: string;
  LKey: HKEY;
  I: Integer;
  LName: string;
  LEntry: TMHTamperEntry;
  LDenied, LReadAny: Boolean;
  LPolicy: Boolean;
  P: Integer;
begin
  AEntries := nil;
  AError := '';
  LDenied := False;
  LReadAny := False;
  for P := 0 to 1 do
  begin
    LPolicy := P = 1;
    if LPolicy then
      LBase := DEFENDER_POLICY_EXCL_KEY
    else
      LBase := DEFENDER_EXCL_KEY;
    for I := Low(KINDS) to High(KINDS) do
      case OpenKey(HKEY_LOCAL_MACHINE, LBase + '\' + KINDS[I], LKey) of
        rrOk:
          try
            LReadAny := True;
            for LName in ValueNames(LKey) do
            begin
              if LName = '' then
                Continue;
              LEntry := TMHTamperEntry.Create(tpDefenderExclusion, LName, LName,
                'HKLM\' + LBase + '\' + KINDS[I]);
              LEntry.Details := KIND_TEXT[I] + IfThen(LPolicy, ', задано политикой', '');
              if I in [0, 1] then
              begin
                LEntry.ImagePath := MHNormalizePath(ExpandEnvironmentText(LName));
                LEntry.Details := LEntry.Details + DescribeExcludedTarget(LEntry.ImagePath);
              end;
              AEntries := AEntries + [LEntry];
            end;
          finally
            RegCloseKey(LKey);
          end;
        rrDenied: LDenied := True;
      end;
  end;
  // Ключ Exclusions закрыт для обычных пользователей; отсутствие ключей — «исключений нет».
  if LDenied then
    AError := ADMIN_REQUIRED;
  Result := LReadAny or not LDenied;
end;

function TMHWinTamperApi.ReadExecutionHijacks(out AEntries: TArray<TMHTamperEntry>;
  out AError: string): Boolean;
var
  LKey, LSub: HKEY;
  LName, LValue, LBase: string;
  LEntry: TMHTamperEntry;
  LOk: Boolean;
  B: Integer;
const
  IFEO_KEYS: array[0..1] of string = (IFEO_KEY, IFEO_WOW_KEY);
begin
  AEntries := nil;
  AError := '';
  LOk := False;
  for B := Low(IFEO_KEYS) to High(IFEO_KEYS) do
  begin
    LBase := IFEO_KEYS[B];
    if OpenKey(HKEY_LOCAL_MACHINE, LBase, LKey) = rrOk then
      try
        LOk := True;
        for LName in SubKeyNames(LKey) do
          if RegOpenKeyEx(LKey, PChar(LName), 0, KEY_READ or KEY_WOW64_64KEY, LSub) = ERROR_SUCCESS then
            try
              LValue := ReadValue(LSub, 'Debugger');
              if LValue.Trim <> '' then
              begin
                LEntry := TMHTamperEntry.Create(tpIfeoDebugger, LName, LValue,
                  'HKLM\' + LBase + '\' + LName);
                LEntry.ImagePath := ExecutableOf(LValue);
                LEntry.Details := 'при запуске ' + LName + ' вместо неё выполняется указанная команда';
                AEntries := AEntries + [LEntry];
              end;
            finally
              RegCloseKey(LSub);
            end;
      finally
        RegCloseKey(LKey);
      end;
  end;
  if OpenKey(HKEY_LOCAL_MACHINE, SILENT_EXIT_KEY, LKey) = rrOk then
    try
      LOk := True;
      for LName in SubKeyNames(LKey) do
        if RegOpenKeyEx(LKey, PChar(LName), 0, KEY_READ or KEY_WOW64_64KEY, LSub) = ERROR_SUCCESS then
          try
            LValue := ReadValue(LSub, 'MonitorProcess');
            if LValue.Trim <> '' then
            begin
              LEntry := TMHTamperEntry.Create(tpSilentExitMonitor, LName, LValue,
                'HKLM\' + SILENT_EXIT_KEY + '\' + LName);
              LEntry.ImagePath := ExecutableOf(LValue);
              LEntry.Details := 'при завершении ' + LName + ' запускается указанная команда';
              AEntries := AEntries + [LEntry];
            end;
          finally
            RegCloseKey(LSub);
          end;
    finally
      RegCloseKey(LKey);
    end;
  if not LOk then
    AError := 'раздел Image File Execution Options недоступен';
  Result := LOk;
end;

function TMHWinTamperApi.IsManagedComputer: Boolean;
var
  LName: PWideChar;
  LType: DWORD;
begin
  LName := nil;
  Result := (NetGetJoinInformation(nil, LName, LType) = 0) and (LType = NETSETUP_DOMAIN_NAME);
  if LName <> nil then
    NetApiBufferFree(LName);
end;

function TMHWinTamperApi.ReadHostsFile(out AText, APath, ADefaultPath: string;
  out AError: string): Boolean;
var
  LKey: HKEY;
  LDir, LDefault: string;
  LStream: TFileStream;
  LBytes: TBytes;
begin
  AText := '';
  AError := '';
  LDefault := IncludeTrailingPathDelimiter(WindowsDir) + 'System32\drivers\etc';
  LDir := '';
  if OpenKey(HKEY_LOCAL_MACHINE, TCPIP_KEY, LKey) = rrOk then
    try
      LDir := ExpandEnvironmentText(ReadValue(LKey, 'DataBasePath'));
    finally
      RegCloseKey(LKey);
    end;
  if LDir = '' then
    LDir := LDefault;
  APath := IncludeTrailingPathDelimiter(LDir) + 'hosts';
  ADefaultPath := IncludeTrailingPathDelimiter(LDefault) + 'hosts';
  if not System.SysUtils.FileExists(APath) then
  begin
    // Файла нет — перенаправлений нет; это не ошибка.
    Result := True;
    Exit;
  end;
  try
    LStream := TFileStream.Create(APath, fmOpenRead or fmShareDenyNone);
    try
      SetLength(LBytes, Min(LStream.Size, MAX_HOSTS_BYTES));
      if Length(LBytes) > 0 then
        LStream.ReadBuffer(LBytes[0], Length(LBytes));
    finally
      LStream.Free;
    end;
    AText := TEncoding.ANSI.GetString(LBytes);
    Result := True;
  except
    on E: Exception do
    begin
      AError := E.Message;
      Result := False;
    end;
  end;
end;

function TMHWinTamperApi.ReadPolicies(out AEntries: TArray<TMHTamperEntry>; out AError: string): Boolean;

  procedure Check(ARoot: HKEY; const APath, AName: string; ADisabledWhenZero: Boolean);
  var
    LKey: HKEY;
    LValue: string;
    LEntry: TMHTamperEntry;
    LNumber: Integer;
  begin
    if OpenKey(ARoot, APath, LKey) <> rrOk then
      Exit;
    try
      LValue := ReadValue(LKey, AName);
    finally
      RegCloseKey(LKey);
    end;
    if (LValue = '') or not TryStrToInt(LValue, LNumber) then
      Exit;
    if (ADisabledWhenZero and (LNumber = 0)) or (not ADisabledWhenZero and (LNumber <> 0)) then
    begin
      LEntry := TMHTamperEntry.Create(tpPolicyRestriction, AName, LValue, RootName(ARoot) + APath);
      LEntry.Details := RootName(ARoot).Replace('\', '');
      AEntries := AEntries + [LEntry];
    end;
  end;

const
  SYSTEM_POLICY = 'Software\Microsoft\Windows\CurrentVersion\Policies\System';
  WINDOWS_SYSTEM_POLICY = 'Software\Policies\Microsoft\Windows\System';
  DEFENDER_POLICY = 'SOFTWARE\Policies\Microsoft\Windows Defender';
  ROOTS: array[0..1] of HKEY = (HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE);
var
  R: Integer;
begin
  AEntries := nil;
  AError := '';
  for R := Low(ROOTS) to High(ROOTS) do
  begin
    Check(ROOTS[R], SYSTEM_POLICY, 'DisableTaskMgr', False);
    Check(ROOTS[R], SYSTEM_POLICY, 'DisableRegistryTools', False);
    Check(ROOTS[R], WINDOWS_SYSTEM_POLICY, 'DisableCMD', False);
  end;
  Check(HKEY_LOCAL_MACHINE, SYSTEM_POLICY, 'EnableLUA', True);
  Check(HKEY_LOCAL_MACHINE, DEFENDER_POLICY, 'DisableAntiSpyware', False);
  Check(HKEY_LOCAL_MACHINE, DEFENDER_POLICY, 'DisableAntiVirus', False);
  Check(HKEY_LOCAL_MACHINE, DEFENDER_POLICY + '\Real-Time Protection', 'DisableRealtimeMonitoring', False);
  Check(HKEY_LOCAL_MACHINE, DEFENDER_POLICY + '\Real-Time Protection', 'DisableBehaviorMonitoring', False);
  Check(HKEY_LOCAL_MACHINE, DEFENDER_POLICY + '\Real-Time Protection', 'DisableOnAccessProtection', False);
  Result := True;
end;

end.
