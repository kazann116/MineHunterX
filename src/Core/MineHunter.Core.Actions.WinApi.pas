unit MineHunter.Core.Actions.WinApi;

{
  Реализация IMHSystemOps на документированных функциях Windows.

    - процесс открывается с минимальными правами для остановки:
      PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
      SeDebugPrivilege не включается, права не повышаются;
    - Проводник запускается по полному пути %WINDIR%\explorer.exe, путь
      к файлу передаётся в кавычках (ShellExecuteEx, без командной оболочки);
    - MpCmdRun.exe ищется в известных папках (SHGetFolderPath), а не через
      переменные окружения или PATH, которые можно подменить;
    - внешняя программа запускается без окна (CREATE_NO_WINDOW), её вывод
      читается через анонимный канал; при отмене или превышении времени
      запущенный процесс принудительно завершается.
  Каждый открытый дескриптор закрывается в finally.
}

interface

uses
  MineHunter.Core.Actions;

type
  TMHWinSystemOps = class(TInterfacedObject, IMHSystemOps)
  public const
    /// Предельный объём сохраняемого вывода внешней программы.
    MaxOutputBytes = 1024 * 1024;
  public
    function CurrentPid: Cardinal;
    function OpenProcessForTerminate(APid: Cardinal; out AHandle: THandle;
      out AError: Cardinal): Boolean;
    procedure CloseProcess(AHandle: THandle);
    function GetCreateTime(AHandle: THandle; out ACreateTime: UInt64): Boolean;
    function GetImagePath(AHandle: THandle; out APath: string): Boolean;
    function IsCritical(AHandle: THandle; out ACritical: Boolean): Boolean;
    function Terminate(AHandle: THandle; AExitCode: Cardinal; out AError: Cardinal): Boolean;
    function WaitExit(AHandle: THandle; ATimeoutMs: Cardinal): Boolean;
    function FileExists(const APath: string): Boolean;
    function ShellOpenSelect(const APath: string; out AError: string): Boolean;
    function FindDefenderCli: string;
    function RunHidden(const AExe, AArgs: string; ATimeoutMs: Cardinal;
      const ACancel: TMHCancelFunc; out AExitCode: Cardinal; out AOutput: string): TMHRunOutcome;
  end;

implementation

uses
  Winapi.Windows, Winapi.ShellAPI, Winapi.ShlObj, System.SysUtils, System.Classes,
  System.IOUtils,
  MineHunter.Core.Calc, MineHunter.Core.Lang;

const
  // Не объявлены в Winapi.Windows Delphi 12; значения из документации Windows SDK.
  PROCESS_QUERY_LIMITED_INFORMATION = $1000;
  MAX_LONG_PATH = 32768;
  POLL_INTERVAL_MS = 100;

function QueryFullProcessImageNameW(hProcess: THandle; dwFlags: DWORD;
  lpExeName: PWideChar; var lpdwSize: DWORD): BOOL; stdcall;
  external kernel32 name 'QueryFullProcessImageNameW';

/// Windows 8.1+ (processthreadsapi.h).
function IsProcessCritical(hProcess: THandle; var Critical: BOOL): BOOL; stdcall;
  external kernel32 name 'IsProcessCritical';

function KnownFolder(ACsidl: Integer): string;
var
  LPath: array[0..MAX_PATH] of Char;
begin
  if Succeeded(SHGetFolderPath(0, ACsidl, 0, 0, @LPath[0])) then
    Result := string(PChar(@LPath[0]))
  else
    Result := '';
end;

{ TMHWinSystemOps }

function TMHWinSystemOps.CurrentPid: Cardinal;
begin
  Result := GetCurrentProcessId;
end;

function TMHWinSystemOps.OpenProcessForTerminate(APid: Cardinal; out AHandle: THandle;
  out AError: Cardinal): Boolean;
begin
  AHandle := OpenProcess(PROCESS_TERMINATE or SYNCHRONIZE or PROCESS_QUERY_LIMITED_INFORMATION,
    False, APid);
  Result := AHandle <> 0;
  if Result then
    AError := 0
  else
    AError := GetLastError;
end;

procedure TMHWinSystemOps.CloseProcess(AHandle: THandle);
begin
  if AHandle <> 0 then
    CloseHandle(AHandle);
end;

function TMHWinSystemOps.GetCreateTime(AHandle: THandle; out ACreateTime: UInt64): Boolean;
var
  LCreation, LExit, LKernel, LUser: TFileTime;
begin
  Result := GetProcessTimes(AHandle, LCreation, LExit, LKernel, LUser);
  if Result then
    ACreateTime := MHFileTimeToUInt64(LCreation.dwLowDateTime, LCreation.dwHighDateTime)
  else
    ACreateTime := 0;
end;

function TMHWinSystemOps.GetImagePath(AHandle: THandle; out APath: string): Boolean;
var
  LBuffer: array of WideChar;
  LSize: DWORD;
begin
  APath := '';
  SetLength(LBuffer, MAX_LONG_PATH);
  LSize := Length(LBuffer);
  Result := QueryFullProcessImageNameW(AHandle, 0, PWideChar(LBuffer), LSize) and (LSize > 0);
  if Result then
    SetString(APath, PWideChar(LBuffer), LSize);
end;

function TMHWinSystemOps.IsCritical(AHandle: THandle; out ACritical: Boolean): Boolean;
var
  LCritical: BOOL;
begin
  LCritical := False;
  Result := IsProcessCritical(AHandle, LCritical);
  ACritical := Result and LCritical;
end;

function TMHWinSystemOps.Terminate(AHandle: THandle; AExitCode: Cardinal;
  out AError: Cardinal): Boolean;
begin
  Result := Winapi.Windows.TerminateProcess(AHandle, AExitCode);
  if Result then
    AError := 0
  else
    AError := GetLastError;
end;

function TMHWinSystemOps.WaitExit(AHandle: THandle; ATimeoutMs: Cardinal): Boolean;
begin
  Result := WaitForSingleObject(AHandle, ATimeoutMs) = WAIT_OBJECT_0;
end;

function TMHWinSystemOps.FileExists(const APath: string): Boolean;
begin
  Result := System.SysUtils.FileExists(APath);
end;

function TMHWinSystemOps.ShellOpenSelect(const APath: string; out AError: string): Boolean;
var
  LWinDir: array[0..MAX_PATH] of Char;
  LLength: UINT;
  LExplorer, LParams: string;
  LInfo: TShellExecuteInfo;
begin
  AError := '';
  LLength := GetWindowsDirectory(@LWinDir[0], Length(LWinDir));
  if (LLength = 0) or (LLength >= UINT(Length(LWinDir))) then
  begin
    AError := MHL('Не удалось определить папку Windows', 'Failed to determine the Windows folder');
    Exit(False);
  end;
  LExplorer := IncludeTrailingPathDelimiter(string(PChar(@LWinDir[0]))) + 'explorer.exe';
  LParams := '/select,"' + APath + '"';
  FillChar(LInfo, SizeOf(LInfo), 0);
  LInfo.cbSize := SizeOf(LInfo);
  LInfo.fMask := SEE_MASK_NOASYNC or SEE_MASK_FLAG_NO_UI;
  LInfo.lpVerb := 'open';
  LInfo.lpFile := PChar(LExplorer);
  LInfo.lpParameters := PChar(LParams);
  LInfo.nShow := SW_SHOWNORMAL;
  Result := ShellExecuteEx(@LInfo);
  if not Result then
    AError := SysErrorMessage(GetLastError);
end;

function TMHWinSystemOps.FindDefenderCli: string;
var
  LPlatformDir, LCandidate, LProgramFiles, LProgramData: string;
  LNames: TArray<string>;
  LDirs: TArray<string>;
  I: Integer;
begin
  LProgramData := KnownFolder(CSIDL_COMMON_APPDATA);
  if LProgramData <> '' then
  begin
    LPlatformDir := TPath.Combine(LProgramData, 'Microsoft\Windows Defender\Platform');
    if TDirectory.Exists(LPlatformDir) then
    begin
      try
        LDirs := TDirectory.GetDirectories(LPlatformDir);
      except
        LDirs := nil;
      end;
      SetLength(LNames, Length(LDirs));
      for I := 0 to High(LDirs) do
        LNames[I] := ExtractFileName(LDirs[I]);
      for LCandidate in MHSortDefenderPlatforms(LNames) do
        if System.SysUtils.FileExists(TPath.Combine(TPath.Combine(LPlatformDir, LCandidate),
          'MpCmdRun.exe')) then
          Exit(TPath.Combine(TPath.Combine(LPlatformDir, LCandidate), 'MpCmdRun.exe'));
    end;
  end;
  LProgramFiles := KnownFolder(CSIDL_PROGRAM_FILES);
  if LProgramFiles <> '' then
  begin
    Result := TPath.Combine(LProgramFiles, 'Windows Defender\MpCmdRun.exe');
    if System.SysUtils.FileExists(Result) then
      Exit;
  end;
  Result := '';
end;

/// Читает из канала всё, что уже доступно, не блокируясь.
procedure DrainPipe(APipe: THandle; AStream: TBytesStream);
var
  LAvailable, LRead: DWORD;
  LBuffer: array[0..4095] of Byte;
begin
  while PeekNamedPipe(APipe, nil, 0, nil, @LAvailable, nil) and (LAvailable > 0) do
  begin
    if not ReadFile(APipe, LBuffer[0], SizeOf(LBuffer), LRead, nil) or (LRead = 0) then
      Break;
    if AStream.Size < TMHWinSystemOps.MaxOutputBytes then
      AStream.WriteBuffer(LBuffer[0], LRead);
  end;
end;

function DecodeConsoleOutput(const ABytes: TBytes; ACount: Integer): string;
var
  LEncoding: TEncoding;
begin
  if ACount <= 0 then
    Exit('');
  // Консольные программы пишут в кодировке OEM.
  LEncoding := TEncoding.GetEncoding(GetOEMCP);
  try
    Result := LEncoding.GetString(ABytes, 0, ACount);
  finally
    LEncoding.Free;
  end;
end;

function TMHWinSystemOps.RunHidden(const AExe, AArgs: string; ATimeoutMs: Cardinal;
  const ACancel: TMHCancelFunc; out AExitCode: Cardinal; out AOutput: string): TMHRunOutcome;
var
  LSecurity: TSecurityAttributes;
  LRead, LWrite: THandle;
  LStartup: TStartupInfo;
  LProcess: TProcessInformation;
  LCommandLine: string;
  LStream: TBytesStream;
  LStart: UInt64;
  LExitCode: DWORD;
begin
  AExitCode := 0;
  AOutput := '';
  FillChar(LSecurity, SizeOf(LSecurity), 0);
  LSecurity.nLength := SizeOf(LSecurity);
  LSecurity.bInheritHandle := True;
  if not CreatePipe(LRead, LWrite, @LSecurity, 0) then
  begin
    AOutput := MHL('Не удалось создать канал вывода: ', 'Failed to create the output pipe: ') +
      SysErrorMessage(GetLastError);
    Exit(roStartFailed);
  end;
  LStream := TBytesStream.Create;
  try
    // Дочернему процессу наследуется только конец канала для записи.
    SetHandleInformation(LRead, HANDLE_FLAG_INHERIT, 0);
    FillChar(LStartup, SizeOf(LStartup), 0);
    LStartup.cb := SizeOf(LStartup);
    LStartup.dwFlags := STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW;
    LStartup.wShowWindow := SW_HIDE;
    LStartup.hStdInput := 0;
    LStartup.hStdOutput := LWrite;
    LStartup.hStdError := LWrite;
    LCommandLine := '"' + AExe + '" ' + AArgs;
    UniqueString(LCommandLine);
    FillChar(LProcess, SizeOf(LProcess), 0);
    if not CreateProcess(PChar(AExe), PChar(LCommandLine), nil, nil, True, CREATE_NO_WINDOW,
      nil, nil, LStartup, LProcess) then
    begin
      AOutput := Format(MHL('Не удалось запустить «%s»: %s', 'Failed to start "%s": %s'),
        [AExe, SysErrorMessage(GetLastError)]);
      Exit(roStartFailed);
    end;
    // Без своей копии конца для записи чтение получит EOF после выхода программы.
    CloseHandle(LWrite);
    LWrite := 0;
    CloseHandle(LProcess.hThread);
    try
      Result := roCompleted;
      LStart := GetTickCount64;
      while WaitForSingleObject(LProcess.hProcess, POLL_INTERVAL_MS) = WAIT_TIMEOUT do
      begin
        DrainPipe(LRead, LStream);
        if Assigned(ACancel) and ACancel() then
          Result := roCancelled
        else if GetTickCount64 - LStart >= ATimeoutMs then
          Result := roTimeout;
        if Result <> roCompleted then
        begin
          Winapi.Windows.TerminateProcess(LProcess.hProcess, 1);
          WaitForSingleObject(LProcess.hProcess, 5000);
          Break;
        end;
      end;
      DrainPipe(LRead, LStream);
      if (Result = roCompleted) and GetExitCodeProcess(LProcess.hProcess, LExitCode) then
        AExitCode := LExitCode;
      AOutput := DecodeConsoleOutput(LStream.Bytes, LStream.Size);
    finally
      CloseHandle(LProcess.hProcess);
    end;
  finally
    LStream.Free;
    if LWrite <> 0 then
      CloseHandle(LWrite);
    CloseHandle(LRead);
  end;
end;

end.
