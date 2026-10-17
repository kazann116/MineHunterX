unit MineHunter.Collectors.Autostart.WinApi;

{
  Реализация IMHAutostartApi на документированных интерфейсах Windows.
  Модуль только читает данные: реестр, файлы, службы и задания НЕ изменяются.

  Источники:
    - Реестр (TRegistry, только чтение, KEY_WOW64_64KEY / KEY_WOW64_32KEY):
        HKLM и HKCU ...\CurrentVersion\Run и RunOnce;
        HKLM\SOFTWARE\WOW6432Node\...\Run и RunOnce (32-разрядное представление);
        HKLM и HKCU ...\Policies\Explorer\Run (групповые политики — частое
        место закрепления вредоносных программ).
      Признак «отключено» берётся из ...\Explorer\StartupApproved\Run|Run32|
      StartupFolder: туда записывает состояние Диспетчер задач (вкладка
      «Автозагрузка»). Первый байт двоичного значения 03 — элемент отключён
      пользователем (02/06 — включён). Формат не документирован Microsoft
      официально, поэтому используется только для поля Enabled и никогда
      не скрывает запись.
    - Папки автозагрузки (SHGetKnownFolderPath FOLDERID_Startup /
      FOLDERID_CommonStartup). Ярлыки .lnk читаются через IShellLinkW +
      IPersistFile без вызова Resolve (Resolve может искать цель и изменять
      ярлык). CLSID_ShellLink зарегистрирован с ThreadingModel=Both и работает
      в MTA потока сканера; если создать объект в текущем апартаменте не
      удалось, чтение выполняется во вспомогательном кратковременном потоке
      с STA (см. ReadShortcut).
    - Службы (OpenSCManager / EnumServicesStatusEx(SERVICE_WIN32) /
      OpenService(SERVICE_QUERY_CONFIG) / QueryServiceConfig / QueryServiceConfig2).
      Включаются службы с типом запуска «автоматически» (в т.ч. отложенный),
      boot/system, а также «вручную» с триггерами запуска (служба стартует
      сама по событию системы). Отключённые службы пропускаются: они не
      запускаются и не являются автозапуском. Драйверы не перечисляются.
      Для служб в svchost.exe в Details указывается ServiceDll.
    - Планировщик заданий 2.0 (COM, позднее связывание через IDispatch:
      модуль Winapi.TaskSchd в Delphi 12 отсутствует). Обходятся все папки,
      включая скрытые задания (TASK_ENUM_HIDDEN). Каждое действие запуска
      программы — отдельная запись; для действий-COM-обработчиков путь
      берётся из InprocServer32 класса.

  COM: методы вызываются из фонового потока сканера. Каждый метод, использующий
  COM, вызывает CoInitializeEx(COINIT_MULTITHREADED) и парный CoUninitialize,
  только если инициализация вернула S_OK/S_FALSE. При RPC_E_CHANGED_MODE
  (поток уже в STA) работа продолжается в существующем апартаменте.
  Все дескрипторы и COM-ссылки освобождаются в finally / при выходе из
  процедур до CoUninitialize.
}

interface

uses
  MineHunter.Core.Types, MineHunter.Collectors.Autostart;

type
  TMHWinAutostartApi = class(TInterfacedObject, IMHAutostartApi)
  private
    FWindowsDir: string;
    function ReadTasksCore(out AEntries: TArray<TMHAutostartEntry>; out AError: string): Boolean;
    class function ReadShortcutDirect(const ALinkPath: string; out ATarget, AArguments,
      AError: string; out ACreateFailed: Boolean): Boolean; static;
    class function ReadShortcutSta(const ALinkPath: string; out ATarget, AArguments,
      AError: string): Boolean; static;
  public
    constructor Create;
    function ReadRegistryRun(out AEntries: TArray<TMHAutostartEntry>; out AError: string): Boolean;
    function ReadStartupFolders(out AEntries: TArray<TMHAutostartEntry>; out AError: string): Boolean;
    function ReadServices(out AEntries: TArray<TMHAutostartEntry>; out AError: string): Boolean;
    function ReadScheduledTasks(out AEntries: TArray<TMHAutostartEntry>; out AError: string): Boolean;
    function WindowsDir: string;
    function FileExists(const APath: string): Boolean;
    function ExpandEnvironment(const AText: string): string;
    /// Читает цель (без подстановки переменных) и аргументы ярлыка .lnk.
    /// Ярлык не разрешается и не изменяется. AForceStaThread = True — читать
    /// во вспомогательном STA-потоке (запасной путь; используется и в тестах).
    class function ReadShortcut(const ALinkPath: string; out ATarget, AArguments,
      AError: string; AForceStaThread: Boolean = False): Boolean; static;
  end;

implementation

uses
  Winapi.Windows, Winapi.WinSvc, Winapi.ActiveX, Winapi.ShlObj, Winapi.KnownFolders,
  System.SysUtils, System.Classes, System.Variants, System.Win.Registry, System.Win.ComObj,
  System.Generics.Collections,
  MineHunter.Core.Paths;

const
  /// Task Scheduler 2.0, taskschd.h: CLSID_TaskScheduler.
  CLSID_TASK_SCHEDULER: TGUID = '{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}';
  /// taskschd.h: TASK_ENUM_HIDDEN — включать скрытые задания.
  TASK_ENUM_HIDDEN = 1;
  /// taskschd.h: TASK_ACTION_TYPE.
  TASK_ACTION_EXEC = 0;
  TASK_ACTION_COM_HANDLER = 5;
  /// winerror.h: E_ACCESSDENIED как HRESULT.
  HR_ACCESS_DENIED = HRESULT($80070005);
  MAX_LONG_PATH = 32768;

  RUN_KEY = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run';
  RUNONCE_KEY = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';
  POLICY_RUN_KEY = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run';
  APPROVED_KEY = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\';
  SERVICES_KEY = 'SYSTEM\CurrentControlSet\Services\';
  /// Первый байт значения StartupApproved для отключённого элемента.
  APPROVED_DISABLED_FLAG = 3;

type
  TRunKeySpec = record
    Root: HKEY;
    Path: string;
    Display: string;
    WowFlag: LongWord;
    Kind: TMHAutostartKind;
    Scope: TMHAutostartScope;
    /// Имя подраздела StartupApproved ('' — признак отключения не применяется).
    Approved: string;
  end;

  /// Пара CoInitializeEx / CoUninitialize с учётом RPC_E_CHANGED_MODE.
  TComApartment = record
  private
    FNeedUninit: Boolean;
  public
    procedure Enter(ACoInit: Longint);
    procedure Leave;
  end;

  /// Вспомогательный STA-поток для чтения ярлыка (запасной путь).
  TShortcutStaThread = class(TThread)
  private
    FLinkPath: string;
    FTarget: string;
    FArguments: string;
    FError: string;
    FSuccess: Boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(const ALinkPath: string);
    property Target: string read FTarget;
    property Arguments: string read FArguments;
    property Error: string read FError;
    property Success: Boolean read FSuccess;
  end;

function RunKeySpecs: TArray<TRunKeySpec>;

  function Spec(ARoot: HKEY; const APath, ADisplay: string; AWow: LongWord;
    AKind: TMHAutostartKind; AScope: TMHAutostartScope; const AApproved: string): TRunKeySpec;
  begin
    Result.Root := ARoot;
    Result.Path := APath;
    Result.Display := ADisplay;
    Result.WowFlag := AWow;
    Result.Kind := AKind;
    Result.Scope := AScope;
    Result.Approved := AApproved;
  end;

begin
  Result := [
    Spec(HKEY_LOCAL_MACHINE, RUN_KEY, 'HKLM\' + RUN_KEY, KEY_WOW64_64KEY,
      akRegistryRun, asMachine, 'Run'),
    Spec(HKEY_LOCAL_MACHINE, RUNONCE_KEY, 'HKLM\' + RUNONCE_KEY, KEY_WOW64_64KEY,
      akRegistryRunOnce, asMachine, ''),
    Spec(HKEY_LOCAL_MACHINE, RUN_KEY,
      'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', KEY_WOW64_32KEY,
      akRegistryRun, asMachine, 'Run32'),
    Spec(HKEY_LOCAL_MACHINE, RUNONCE_KEY,
      'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce', KEY_WOW64_32KEY,
      akRegistryRunOnce, asMachine, ''),
    Spec(HKEY_LOCAL_MACHINE, POLICY_RUN_KEY, 'HKLM\' + POLICY_RUN_KEY, KEY_WOW64_64KEY,
      akRegistryRun, asMachine, ''),
    Spec(HKEY_CURRENT_USER, RUN_KEY, 'HKCU\' + RUN_KEY, KEY_WOW64_64KEY,
      akRegistryRun, asUser, 'Run'),
    Spec(HKEY_CURRENT_USER, RUNONCE_KEY, 'HKCU\' + RUNONCE_KEY, KEY_WOW64_64KEY,
      akRegistryRunOnce, asUser, ''),
    Spec(HKEY_CURRENT_USER, POLICY_RUN_KEY, 'HKCU\' + POLICY_RUN_KEY, KEY_WOW64_64KEY,
      akRegistryRun, asUser, '')
  ];
end;

{ TComApartment }

procedure TComApartment.Enter(ACoInit: Longint);
var
  LHr: HRESULT;
begin
  LHr := CoInitializeEx(nil, ACoInit);
  // S_FALSE — COM уже инициализирован в этом режиме, вызов всё равно парный.
  // RPC_E_CHANGED_MODE — поток уже в другом апартаменте: работаем в нём без Uninitialize.
  FNeedUninit := (LHr = S_OK) or (LHr = S_FALSE);
end;

procedure TComApartment.Leave;
begin
  if FNeedUninit then
    CoUninitialize;
  FNeedUninit := False;
end;

{ Вспомогательные функции }

/// Имена значений StartupApproved, отключённых пользователем.
function ReadDisabledNames(ARoot: HKEY; const ASubKey: string): TArray<string>;
var
  LReg: TRegistry;
  LNames: TStringList;
  LName: string;
  LData: TBytes;
  LSize: Integer;
begin
  Result := nil;
  if ASubKey = '' then
    Exit;
  LReg := TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  try
    LReg.RootKey := ARoot;
    if not LReg.OpenKeyReadOnly(APPROVED_KEY + ASubKey) then
      Exit;
    LNames := TStringList.Create;
    try
      LReg.GetValueNames(LNames);
      for LName in LNames do
      begin
        if LReg.GetDataType(LName) <> rdBinary then
          Continue;
        LSize := LReg.GetDataSize(LName);
        if LSize < 1 then
          Continue;
        SetLength(LData, LSize);
        try
          LReg.ReadBinaryData(LName, LData[0], LSize);
        except
          on ERegistryException do
            Continue;
        end;
        if LData[0] = APPROVED_DISABLED_FLAG then
          Result := Result + [LName];
      end;
    finally
      LNames.Free;
    end;
  finally
    LReg.Free;
  end;
end;

function NameInList(const AList: TArray<string>; const AValue: string): Boolean;
var
  LItem: string;
begin
  for LItem in AList do
    if SameText(LItem, AValue) then
      Exit(True);
  Result := False;
end;

function KnownFolderPath(const AFolderId: TGUID; out APath: string): Boolean;
var
  LPtr: PWideChar;
begin
  LPtr := nil;
  APath := '';
  try
    Result := Succeeded(SHGetKnownFolderPath(AFolderId, 0, 0, LPtr)) and (LPtr <> nil);
    if Result then
      APath := string(LPtr);
  finally
    // Буфер выделяется даже при ошибке; CoTaskMemFree(nil) допустим.
    CoTaskMemFree(LPtr);
  end;
end;

function QuoteIfNeeded(const APath: string): string;
begin
  if (APath <> '') and (Pos(' ', APath) > 0) then
    Result := '"' + APath + '"'
  else
    Result := APath;
end;

function ServiceStartTypeText(AStartType: DWORD; ADelayed, ATriggered: Boolean): string;
begin
  case AStartType of
    SERVICE_BOOT_START:   Result := 'при загрузке ядра (boot)';
    SERVICE_SYSTEM_START: Result := 'при инициализации системы (system)';
    SERVICE_AUTO_START:
      if ADelayed then
        Result := 'автоматически (отложенный запуск)'
      else
        Result := 'автоматически';
    SERVICE_DEMAND_START: Result := 'вручную';
  else
    Result := Format('тип %d', [AStartType]);
  end;
  if ATriggered then
    Result := Result + ', запуск по триггеру';
end;

function ServiceStateText(AState: DWORD): string;
begin
  case AState of
    SERVICE_STOPPED:          Result := 'остановлена';
    SERVICE_START_PENDING:    Result := 'запускается';
    SERVICE_STOP_PENDING:     Result := 'останавливается';
    SERVICE_RUNNING:          Result := 'работает';
    SERVICE_CONTINUE_PENDING: Result := 'возобновляется';
    SERVICE_PAUSE_PENDING:    Result := 'приостанавливается';
    SERVICE_PAUSED:           Result := 'приостановлена';
  else
    Result := Format('состояние %d', [AState]);
  end;
end;

function TaskTriggerText(AType: Integer): string;
begin
  // taskschd.h: TASK_TRIGGER_TYPE2.
  case AType of
    0:  Result := 'по событию';
    1:  Result := 'однократно по времени';
    2:  Result := 'ежедневно';
    3:  Result := 'еженедельно';
    4:  Result := 'ежемесячно';
    5:  Result := 'ежемесячно по дням недели';
    6:  Result := 'при простое';
    7:  Result := 'при создании или изменении задания';
    8:  Result := 'при загрузке системы';
    9:  Result := 'при входе в систему';
    11: Result := 'при изменении состояния сеанса';
    12: Result := 'особый триггер';
  else
    Result := Format('триггер типа %d', [AType]);
  end;
end;

/// Значение свойства IDispatch по имени. Нужна для свойств с именем,
/// совпадающим с зарезервированным словом Delphi (Type).
function DispProp(const AObject: OleVariant; const AName: string): OleVariant;
begin
  Result := GetDispatchPropValue(IDispatch(AObject), AName);
end;

function OleToStr(const AValue: OleVariant): string;
begin
  if VarIsNull(AValue) or VarIsEmpty(AValue) then
    Result := ''
  else
    Result := VarToStr(AValue);
end;

{ TShortcutStaThread }

constructor TShortcutStaThread.Create(const ALinkPath: string);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FLinkPath := ALinkPath;
end;

procedure TShortcutStaThread.Execute;
var
  LApartment: TComApartment;
  LCreateFailed: Boolean;
begin
  try
    LApartment.Enter(COINIT_APARTMENTTHREADED);
    try
      FSuccess := TMHWinAutostartApi.ReadShortcutDirect(FLinkPath, FTarget, FArguments, FError,
        LCreateFailed);
    finally
      LApartment.Leave;
    end;
  except
    on E: Exception do
    begin
      FSuccess := False;
      FError := E.Message;
    end;
  end;
end;

{ TMHWinAutostartApi }

constructor TMHWinAutostartApi.Create;
var
  LBuffer: array[0..MAX_PATH] of Char;
  LLen: UINT;
begin
  inherited Create;
  LLen := GetWindowsDirectory(LBuffer, Length(LBuffer));
  if (LLen > 0) and (LLen < UINT(Length(LBuffer))) then
    SetString(FWindowsDir, LBuffer, LLen)
  else
    FWindowsDir := GetEnvironmentVariable('SystemRoot');
  FWindowsDir := ExcludeTrailingPathDelimiter(FWindowsDir);
end;

function TMHWinAutostartApi.WindowsDir: string;
begin
  Result := FWindowsDir;
end;

function TMHWinAutostartApi.FileExists(const APath: string): Boolean;
begin
  Result := (APath <> '') and System.SysUtils.FileExists(APath);
end;

function TMHWinAutostartApi.ExpandEnvironment(const AText: string): string;
var
  LSize: DWORD;
begin
  if Pos('%', AText) = 0 then
    Exit(AText);
  LSize := ExpandEnvironmentStrings(PChar(AText), nil, 0);
  if LSize = 0 then
    Exit(AText);
  SetLength(Result, LSize);
  LSize := ExpandEnvironmentStrings(PChar(AText), PChar(Result), LSize);
  if (LSize = 0) or (LSize > DWORD(Length(Result))) then
    Exit(AText);
  // LSize включает завершающий нуль.
  SetLength(Result, LSize - 1);
end;

function TMHWinAutostartApi.ReadRegistryRun(out AEntries: TArray<TMHAutostartEntry>;
  out AError: string): Boolean;
var
  LSpec: TRunKeySpec;
  LReg: TRegistry;
  LNames: TStringList;
  LName: string;
  LDisabled: TArray<string>;
  LEntry: TMHAutostartEntry;
  LList: TList<TMHAutostartEntry>;
  LOpened, LDenied, LBadValues: Integer;
begin
  AEntries := nil;
  AError := '';
  LOpened := 0;
  LDenied := 0;
  LBadValues := 0;
  LList := TList<TMHAutostartEntry>.Create;
  LNames := TStringList.Create;
  try
    for LSpec in RunKeySpecs do
    begin
      LReg := TRegistry.Create(KEY_READ or LSpec.WowFlag);
      try
        LReg.RootKey := LSpec.Root;
        if not LReg.OpenKeyReadOnly(LSpec.Path) then
        begin
          // Отсутствующий раздел (RunOnce, политики) — обычная ситуация.
          if LReg.LastError <> ERROR_FILE_NOT_FOUND then
            Inc(LDenied);
          Continue;
        end;
        Inc(LOpened);
        if LSpec.Scope = asMachine then
          LDisabled := ReadDisabledNames(HKEY_LOCAL_MACHINE, LSpec.Approved)
        else
          LDisabled := ReadDisabledNames(HKEY_CURRENT_USER, LSpec.Approved);
        LNames.Clear;
        LReg.GetValueNames(LNames);
        for LName in LNames do
        begin
          if not (LReg.GetDataType(LName) in [rdString, rdExpandString]) then
            Continue;
          LEntry := Default(TMHAutostartEntry);
          try
            LEntry.Command := Trim(LReg.ReadString(LName));
          except
            on ERegistryException do
            begin
              Inc(LBadValues);
              Continue;
            end;
          end;
          if (LName = '') and (LEntry.Command = '') then
            Continue;
          LEntry.Kind := LSpec.Kind;
          LEntry.Scope := LSpec.Scope;
          LEntry.Name := LName;
          if LEntry.Name = '' then
            LEntry.Name := '(по умолчанию)';
          LEntry.Location := LSpec.Display;
          LEntry.Enabled := not NameInList(LDisabled, LName);
          if not LEntry.Enabled then
            LEntry.Details := 'Отключено в Диспетчере задач (StartupApproved)';
          LList.Add(LEntry);
        end;
      finally
        LReg.Free;
      end;
    end;

    if LOpened = 0 then
    begin
      AError := 'нет доступа ни к одному разделу Run/RunOnce';
      Exit(False);
    end;
    if LDenied > 0 then
      AError := Format('нет доступа к %d разделам реестра', [LDenied]);
    if LBadValues > 0 then
      AError := Trim(AError + Format(' не прочитано значений: %d', [LBadValues]));
    AEntries := LList.ToArray;
    Result := True;
  finally
    LNames.Free;
    LList.Free;
  end;
end;

class function TMHWinAutostartApi.ReadShortcutDirect(const ALinkPath: string; out ATarget,
  AArguments, AError: string; out ACreateFailed: Boolean): Boolean;
var
  LLink: IShellLinkW;
  LFile: IPersistFile;
  LHr: HRESULT;
  LFind: TWin32FindDataW;
  LBuffer: array of WideChar;
begin
  ATarget := '';
  AArguments := '';
  AError := '';
  ACreateFailed := False;
  LHr := CoCreateInstance(CLSID_ShellLink, nil, CLSCTX_INPROC_SERVER, IShellLinkW, LLink);
  if Failed(LHr) then
  begin
    ACreateFailed := True;
    AError := 'не удалось создать объект ShellLink: ' + SysErrorMessage(Cardinal(LHr));
    Exit(False);
  end;
  if not Supports(LLink, IPersistFile, LFile) then
  begin
    AError := 'объект ShellLink не поддерживает IPersistFile';
    Exit(False);
  end;
  LHr := LFile.Load(PWideChar(ALinkPath), STGM_READ);
  if Failed(LHr) then
  begin
    AError := 'не удалось прочитать ярлык: ' + SysErrorMessage(Cardinal(LHr));
    Exit(False);
  end;
  SetLength(LBuffer, MAX_LONG_PATH);
  LBuffer[0] := #0;
  FillChar(LFind, SizeOf(LFind), 0);
  // SLGP_RAWPATH — путь как записан в ярлыке (переменные окружения не подставлены).
  // S_FALSE — у ярлыка нет пути к файлу (объект оболочки, ярлык установщика).
  if LLink.GetPath(PWideChar(LBuffer), Length(LBuffer), LFind, SLGP_RAWPATH) = S_OK then
    ATarget := Trim(string(PWideChar(LBuffer)));
  LBuffer[0] := #0;
  if Succeeded(LLink.GetArguments(PWideChar(LBuffer), Length(LBuffer))) then
    AArguments := Trim(string(PWideChar(LBuffer)));
  Result := True;
end;

class function TMHWinAutostartApi.ReadShortcutSta(const ALinkPath: string; out ATarget,
  AArguments, AError: string): Boolean;
var
  LThread: TShortcutStaThread;
begin
  LThread := TShortcutStaThread.Create(ALinkPath);
  try
    LThread.Start;
    LThread.WaitFor;
    ATarget := LThread.Target;
    AArguments := LThread.Arguments;
    AError := LThread.Error;
    Result := LThread.Success;
  finally
    LThread.Free;
  end;
end;

class function TMHWinAutostartApi.ReadShortcut(const ALinkPath: string; out ATarget,
  AArguments, AError: string; AForceStaThread: Boolean): Boolean;
var
  LApartment: TComApartment;
  LCreateFailed: Boolean;
begin
  if AForceStaThread then
    Exit(ReadShortcutSta(ALinkPath, ATarget, AArguments, AError));
  LApartment.Enter(COINIT_MULTITHREADED);
  try
    Result := ReadShortcutDirect(ALinkPath, ATarget, AArguments, AError, LCreateFailed);
  finally
    LApartment.Leave;
  end;
  // Объект не создаётся в текущем апартаменте — пробуем в отдельном STA-потоке.
  if not Result and LCreateFailed then
    Result := ReadShortcutSta(ALinkPath, ATarget, AArguments, AError);
end;

function TMHWinAutostartApi.ReadStartupFolders(out AEntries: TArray<TMHAutostartEntry>;
  out AError: string): Boolean;
type
  TFolderSpec = record
    Id: TGUID;
    Scope: TMHAutostartScope;
    Root: HKEY;
  end;
var
  LFolders: array[0..1] of TFolderSpec;
  LApartment: TComApartment;
  LList: TList<TMHAutostartEntry>;
  LFolder: TFolderSpec;
  LDir, LFull, LTarget, LArgs, LLinkError: string;
  LDisabled: TArray<string>;
  LSearch: TSearchRec;
  LEntry: TMHAutostartEntry;
  LFound, LBadLinks: Integer;
begin
  AEntries := nil;
  AError := '';
  LFound := 0;
  LBadLinks := 0;
  LFolders[0].Id := FOLDERID_Startup;
  LFolders[0].Scope := asUser;
  LFolders[0].Root := HKEY_CURRENT_USER;
  LFolders[1].Id := FOLDERID_CommonStartup;
  LFolders[1].Scope := asMachine;
  LFolders[1].Root := HKEY_LOCAL_MACHINE;
  LApartment.Enter(COINIT_MULTITHREADED);
  try
    LList := TList<TMHAutostartEntry>.Create;
    try
      for LFolder in LFolders do
      begin
        if not KnownFolderPath(LFolder.Id, LDir) then
          Continue;
        Inc(LFound);
        LDisabled := ReadDisabledNames(LFolder.Root, 'StartupFolder');
        if FindFirst(IncludeTrailingPathDelimiter(LDir) + '*', faAnyFile, LSearch) <> 0 then
          Continue;
        try
          repeat
            if (LSearch.Attr and faDirectory) <> 0 then
              Continue;
            if SameText(LSearch.Name, 'desktop.ini') then
              Continue;
            LFull := IncludeTrailingPathDelimiter(LDir) + LSearch.Name;
            LEntry := Default(TMHAutostartEntry);
            LEntry.Kind := akStartupFolder;
            LEntry.Scope := LFolder.Scope;
            LEntry.Name := LSearch.Name;
            LEntry.Location := LDir;
            LEntry.Enabled := not NameInList(LDisabled, LSearch.Name);
            if SameText(ExtractFileExt(LSearch.Name), '.lnk') then
            begin
              if ReadShortcut(LFull, LTarget, LArgs, LLinkError) and (LTarget <> '') then
              begin
                LEntry.Command := Trim(QuoteIfNeeded(LTarget) + ' ' + LArgs);
                LEntry.ImagePath := MHNormalizePath(ExpandEnvironment(LTarget), FWindowsDir);
                LEntry.Details := 'Ярлык: ' + LFull;
              end
              else
              begin
                if LLinkError <> '' then
                  Inc(LBadLinks);
                LEntry.Command := QuoteIfNeeded(LFull);
                LEntry.ImagePath := LFull;
                if LLinkError <> '' then
                  LEntry.Details := 'Ярлык не прочитан: ' + LLinkError
                else
                  LEntry.Details := 'Ярлык без пути к файлу (объект оболочки или ярлык установщика)';
              end;
            end
            else
            begin
              LEntry.Command := QuoteIfNeeded(LFull);
              LEntry.ImagePath := LFull;
            end;
            if not LEntry.Enabled then
              LEntry.Details := Trim(LEntry.Details + '; отключено в Диспетчере задач');
            LList.Add(LEntry);
          until FindNext(LSearch) <> 0;
        finally
          FindClose(LSearch);
        end;
      end;
      if LFound = 0 then
      begin
        AError := 'не удалось определить расположение папок автозагрузки';
        Exit(False);
      end;
      if LBadLinks > 0 then
        AError := Format('не прочитано ярлыков: %d', [LBadLinks]);
      AEntries := LList.ToArray;
      Result := True;
    finally
      LList.Free;
    end;
  finally
    LApartment.Leave;
  end;
end;

function TMHWinAutostartApi.ReadServices(out AEntries: TArray<TMHAutostartEntry>;
  out AError: string): Boolean;
type
  TServiceItem = record
    Name: string;
    DisplayName: string;
    State: DWORD;
  end;
const
  ENUM_BUFFER_SIZE = 64 * 1024;
var
  LScm, LSvc: SC_HANDLE;
  LBuffer, LConfigBuf, LTriggerBuf: TBytes;
  LNeeded, LReturned, LResume, LErr: DWORD;
  LOk: Boolean;
  LItems: TList<TServiceItem>;
  LItem: TServiceItem;
  LRaw: LPENUM_SERVICE_STATUS_PROCESSW;
  I: Integer;
  LConfig: LPQUERY_SERVICE_CONFIGW;
  LDelayed: SERVICE_DELAYED_AUTO_START_INFO;
  LIsDelayed, LTriggered: Boolean;
  LList: TList<TMHAutostartEntry>;
  LEntry: TMHAutostartEntry;
  LReg: TRegistry;
  LServiceDll, LAccount: string;
  LDenied: Integer;
begin
  AEntries := nil;
  AError := '';
  LDenied := 0;
  LScm := OpenSCManager(nil, nil, SC_MANAGER_CONNECT or SC_MANAGER_ENUMERATE_SERVICE);
  if LScm = 0 then
  begin
    AError := 'OpenSCManager: ' + SysErrorMessage(GetLastError);
    Exit(False);
  end;
  LItems := TList<TServiceItem>.Create;
  LList := TList<TMHAutostartEntry>.Create;
  LReg := TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  try
    LReg.RootKey := HKEY_LOCAL_MACHINE;
    // 1. Перечень служб (порциями, с продолжением по LResume).
    SetLength(LBuffer, ENUM_BUFFER_SIZE);
    LResume := 0;
    repeat
      LNeeded := 0;
      LReturned := 0;
      LOk := EnumServicesStatusEx(LScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        @LBuffer[0], Length(LBuffer), @LNeeded, @LReturned, @LResume, nil);
      LErr := ERROR_SUCCESS;
      if not LOk then
      begin
        LErr := GetLastError;
        if LErr <> ERROR_MORE_DATA then
        begin
          AError := 'EnumServicesStatusEx: ' + SysErrorMessage(LErr);
          Exit(False);
        end;
      end;
      LRaw := LPENUM_SERVICE_STATUS_PROCESSW(@LBuffer[0]);
      for I := 1 to Integer(LReturned) do
      begin
        LItem.Name := string(LRaw.lpServiceName);
        LItem.DisplayName := string(LRaw.lpDisplayName);
        LItem.State := LRaw.ServiceStatus.dwCurrentState;
        LItems.Add(LItem);
        Inc(LRaw);
      end;
      if (LErr = ERROR_MORE_DATA) and (LReturned = 0) then
      begin
        // Одна запись не помещается в буфер — увеличиваем его.
        if LNeeded <= DWORD(Length(LBuffer)) then
        begin
          AError := 'EnumServicesStatusEx: некорректный размер буфера';
          Exit(False);
        end;
        SetLength(LBuffer, LNeeded);
      end;
    until LOk;

    // 2. Конфигурация каждой службы.
    for LItem in LItems do
    begin
      LSvc := OpenService(LScm, PChar(LItem.Name), SERVICE_QUERY_CONFIG);
      if LSvc = 0 then
      begin
        // Служба могла быть удалена между перечислением и открытием.
        if GetLastError <> ERROR_SERVICE_DOES_NOT_EXIST then
          Inc(LDenied);
        Continue;
      end;
      try
        LNeeded := 0;
        if not QueryServiceConfig(LSvc, nil, 0, LNeeded) and
           (GetLastError <> ERROR_INSUFFICIENT_BUFFER) then
        begin
          Inc(LDenied);
          Continue;
        end;
        SetLength(LConfigBuf, LNeeded);
        LConfig := LPQUERY_SERVICE_CONFIGW(@LConfigBuf[0]);
        if not QueryServiceConfig(LSvc, LConfig, LNeeded, LNeeded) then
        begin
          Inc(LDenied);
          Continue;
        end;

        LIsDelayed := False;
        LTriggered := False;
        case LConfig.dwStartType of
          SERVICE_AUTO_START:
            begin
              LDelayed._DelayedAutostart := 0;
              if QueryServiceConfig2(LSvc, SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                @LDelayed, SizeOf(LDelayed), @LNeeded) then
                LIsDelayed := LDelayed.fDelayedAutostart;
            end;
          SERVICE_DEMAND_START:
            begin
              // «Вручную» — автозапуск, только если у службы есть триггеры запуска.
              LNeeded := 0;
              if not QueryServiceConfig2(LSvc, SERVICE_CONFIG_TRIGGER_INFO, nil, 0, @LNeeded) and
                 (GetLastError = ERROR_INSUFFICIENT_BUFFER) and (LNeeded >= SizeOf(SERVICE_TRIGGER_INFO)) then
              begin
                SetLength(LTriggerBuf, LNeeded);
                if QueryServiceConfig2(LSvc, SERVICE_CONFIG_TRIGGER_INFO, @LTriggerBuf[0],
                  LNeeded, @LNeeded) then
                  LTriggered := PSERVICE_TRIGGER_INFO(@LTriggerBuf[0]).cTriggers > 0;
              end;
              if not LTriggered then
                Continue;
            end;
          SERVICE_BOOT_START, SERVICE_SYSTEM_START:
            ;
        else
          // SERVICE_DISABLED и неизвестные значения — служба не запускается сама.
          Continue;
        end;

        LEntry := Default(TMHAutostartEntry);
        LEntry.Kind := akService;
        LEntry.Scope := asMachine;
        LEntry.Name := LItem.Name;
        LEntry.Command := Trim(string(LConfig.lpBinaryPathName));
        LEntry.Location := 'services';
        LEntry.Enabled := True;
        LAccount := string(LConfig.lpServiceStartName);
        if LAccount = '' then
          LAccount := 'не указана';
        LEntry.Details := Format('%s; запуск: %s; учётная запись: %s; состояние: %s',
          [LItem.DisplayName, ServiceStartTypeText(LConfig.dwStartType, LIsDelayed, LTriggered),
           LAccount, ServiceStateText(LItem.State)]);

        // Для служб внутри svchost.exe исполняемый код находится в ServiceDll.
        if Pos('svchost', LowerCase(LEntry.Command)) > 0 then
        begin
          LServiceDll := '';
          if LReg.OpenKeyReadOnly(SERVICES_KEY + LItem.Name + '\Parameters') then
          try
            if LReg.GetDataType('ServiceDll') in [rdString, rdExpandString] then
              LServiceDll := LReg.ReadString('ServiceDll');
          finally
            LReg.CloseKey;
          end;
          if (LServiceDll = '') and LReg.OpenKeyReadOnly(SERVICES_KEY + LItem.Name) then
          try
            if LReg.GetDataType('ServiceDll') in [rdString, rdExpandString] then
              LServiceDll := LReg.ReadString('ServiceDll');
          finally
            LReg.CloseKey;
          end;
          if LServiceDll <> '' then
            LEntry.Details := LEntry.Details + '; ServiceDll: ' +
              MHNormalizePath(ExpandEnvironment(LServiceDll), FWindowsDir);
        end;
        LList.Add(LEntry);
      finally
        CloseServiceHandle(LSvc);
      end;
    end;

    if (LItems.Count > 0) and (LDenied = LItems.Count) then
    begin
      AError := 'нет доступа к настройкам служб';
      Exit(False);
    end;
    if LDenied > 0 then
      AError := Format('нет доступа к настройкам %d из %d служб', [LDenied, LItems.Count]);
    AEntries := LList.ToArray;
    Result := True;
  finally
    LReg.Free;
    LList.Free;
    LItems.Free;
    CloseServiceHandle(LScm);
  end;
end;

function TMHWinAutostartApi.ReadScheduledTasks(out AEntries: TArray<TMHAutostartEntry>;
  out AError: string): Boolean;
var
  LApartment: TComApartment;
begin
  AEntries := nil;
  AError := '';
  LApartment.Enter(COINIT_MULTITHREADED);
  try
    try
      // Все COM-ссылки живут внутри ReadTasksCore и освобождаются до CoUninitialize.
      Result := ReadTasksCore(AEntries, AError);
    except
      on E: Exception do
      begin
        AEntries := nil;
        AError := E.Message;
        Result := False;
      end;
    end;
  finally
    LApartment.Leave;
  end;
end;

function TMHWinAutostartApi.ReadTasksCore(out AEntries: TArray<TMHAutostartEntry>;
  out AError: string): Boolean;
var
  LList: TList<TMHAutostartEntry>;
  LClsidReg: TRegistry;
  LDeniedFolders, LFailedTasks: Integer;

  /// Сервер COM-класса: InprocServer32 (путь DLL) или LocalServer32 (командная
  /// строка EXE). '' — класс размещён в службе (AppID) или не зарегистрирован.
  function ComHandlerServer(const AClassId: string): string;
  const
    SERVER_KEYS: array[0..1] of string = ('InprocServer32', 'LocalServer32');
  var
    LKey: string;
  begin
    Result := '';
    if AClassId = '' then
      Exit;
    for LKey in SERVER_KEYS do
    begin
      if LClsidReg.OpenKeyReadOnly('SOFTWARE\Classes\CLSID\' + AClassId + '\' + LKey) then
      try
        if LClsidReg.GetDataType('') in [rdString, rdExpandString] then
          Result := Trim(LClsidReg.ReadString(''));
      finally
        LClsidReg.CloseKey;
      end;
      if Result <> '' then
        Exit;
    end;
  end;

  procedure AddTask(const ATask: OleVariant; const AFolderPath: string);
  var
    LDefinition, LActions, LAction, LTriggers, LTrigger, LPrincipal, LSettings: OleVariant;
    LBase: TMHAutostartEntry;
    LEntry: TMHAutostartEntry;
    LTriggerTexts: TArray<string>;
    LDetails, LUser, LClassId, LServer, LPath: string;
    I, LActionType, LAdded: Integer;
  begin
    LDefinition := ATask.Definition;
    LBase := Default(TMHAutostartEntry);
    LBase.Kind := akScheduledTask;
    LBase.Scope := asMachine;
    LBase.Name := OleToStr(ATask.Path);
    LBase.Location := AFolderPath;
    LBase.Enabled := Boolean(ATask.Enabled);

    LTriggerTexts := nil;
    LTriggers := LDefinition.Triggers;
    for I := 1 to Integer(LTriggers.Count) do
    begin
      LTrigger := LTriggers.Item[I];
      LTriggerTexts := LTriggerTexts + [TaskTriggerText(Integer(DispProp(LTrigger, 'Type')))];
    end;
    if Length(LTriggerTexts) > 0 then
      LDetails := 'Триггеры: ' + string.Join(', ', LTriggerTexts)
    else
      LDetails := 'Триггеров нет (запуск вручную или другим заданием)';

    LPrincipal := LDefinition.Principal;
    LUser := OleToStr(LPrincipal.UserId);
    if LUser = '' then
      LUser := OleToStr(LPrincipal.GroupId);
    if LUser <> '' then
      LDetails := LDetails + '; учётная запись: ' + LUser;
    // TASK_RUNLEVEL_HIGHEST = 1.
    if Integer(LPrincipal.RunLevel) = 1 then
      LDetails := LDetails + '; наивысшие права';
    LSettings := LDefinition.Settings;
    if Boolean(LSettings.Hidden) then
      LDetails := LDetails + '; скрытое';

    LAdded := 0;
    LActions := LDefinition.Actions;
    for I := 1 to Integer(LActions.Count) do
    begin
      LAction := LActions.Item[I];
      LActionType := Integer(DispProp(LAction, 'Type'));
      LEntry := LBase;
      LEntry.Details := LDetails;
      case LActionType of
        TASK_ACTION_EXEC:
          begin
            // Некоторые установщики сохраняют Path уже в кавычках.
            LPath := Trim(OleToStr(LAction.Path));
            if (Length(LPath) >= 2) and (LPath[1] = '"') and (LPath[Length(LPath)] = '"') then
              LPath := Trim(Copy(LPath, 2, Length(LPath) - 2));
            LEntry.Command := Trim(QuoteIfNeeded(LPath) + ' ' + Trim(OleToStr(LAction.Arguments)));
            if OleToStr(LAction.WorkingDirectory) <> '' then
              LEntry.Details := LEntry.Details + '; рабочая папка: ' +
                OleToStr(LAction.WorkingDirectory);
          end;
        TASK_ACTION_COM_HANDLER:
          begin
            LClassId := OleToStr(LAction.ClassId);
            LServer := ComHandlerServer(LClassId);
            if LServer <> '' then
            begin
              // Путь сервера разбирается коллектором как обычная команда.
              LEntry.Command := LServer;
              LEntry.Details := LEntry.Details + '; COM-обработчик ' + LClassId;
            end
            else
            begin
              // Класс размещён в службе или не зарегистрирован: ImagePath останется
              // пустым — из «COM-обработчик {CLSID}» путь не извлекается.
              LEntry.Command := 'COM-обработчик ' + LClassId;
              LEntry.Details := LEntry.Details +
                '; сервер COM-обработчика не зарегистрирован в CLSID (размещён в службе)';
            end;
          end;
      else
        // Устаревшие действия (письмо, сообщение) ничего не запускают.
        Continue;
      end;
      LList.Add(LEntry);
      Inc(LAdded);
    end;
    if LAdded = 0 then
    begin
      LEntry := LBase;
      LEntry.Details := LDetails + '; нет действий запуска программ';
      LList.Add(LEntry);
    end;
  end;

  procedure Walk(const AFolder: OleVariant);
  var
    LTasks, LFolders: OleVariant;
    LPath: string;
    I: Integer;
  begin
    LPath := OleToStr(AFolder.Path);
    try
      LTasks := AFolder.GetTasks(TASK_ENUM_HIDDEN);
      for I := 1 to Integer(LTasks.Count) do
        try
          AddTask(LTasks.Item[I], LPath);
        except
          // Повреждённое или недоступное задание не прерывает обход.
          on Exception do
            Inc(LFailedTasks);
        end;
    except
      on Exception do
        Inc(LDeniedFolders);
    end;
    try
      LFolders := AFolder.GetFolders(0);
    except
      on Exception do
      begin
        Inc(LDeniedFolders);
        Exit;
      end;
    end;
    for I := 1 to Integer(LFolders.Count) do
      Walk(LFolders.Item[I]);
  end;

var
  LService, LRoot: OleVariant;
begin
  AEntries := nil;
  AError := '';
  LDeniedFolders := 0;
  LFailedTasks := 0;
  LList := TList<TMHAutostartEntry>.Create;
  LClsidReg := TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
  try
    LClsidReg.RootKey := HKEY_LOCAL_MACHINE;
    try
      LService := CreateComObject(CLSID_TASK_SCHEDULER) as IDispatch;
      LService.Connect;
      LRoot := LService.GetFolder('\');
    except
      on E: EOleSysError do
      begin
        if E.ErrorCode = HR_ACCESS_DENIED then
          AError := 'нет доступа к службе планировщика заданий'
        else
          AError := 'служба планировщика заданий недоступна: ' + E.Message;
        Exit(False);
      end;
    end;
    Walk(LRoot);
    if LDeniedFolders > 0 then
      AError := Format('нет доступа к %d папкам планировщика (нужны права администратора)',
        [LDeniedFolders]);
    if LFailedTasks > 0 then
      AError := Trim(AError + Format(' не прочитано заданий: %d', [LFailedTasks]));
    AEntries := LList.ToArray;
    Result := True;
  finally
    LClsidReg.Free;
    LList.Free;
  end;
end;

end.
