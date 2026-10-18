unit MineHunter.Collectors.Processes.WinApi;

{
  Реализация IMHProcessApi на документированных функциях Windows:
    - CreateToolhelp32Snapshot / Process32FirstW / Process32NextW — перечень;
    - OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) — минимально необходимое
      право; работает без прав администратора для процессов текущего
      пользователя и части системных;
    - GetProcessTimes, QueryFullProcessImageNameW, GetProcessMemoryInfo;
    - PDH «\Process(*)\Working Set - Private» — частный рабочий набор (колонка
      «Память» диспетчера задач). Опрос объекта Process дорогой, поэтому
      значения обновляются не чаще раза в PRIVATE_WS_REFRESH_MS.
  SeDebugPrivilege не включается: MineHunter работает с минимальными правами,
  а недоступные процессы явно помечаются как alDenied.
  Каждый открытый дескриптор закрывается в finally.
}

interface

uses
  MineHunter.Collectors.Processes, MineHunter.Collectors.Pdh;

type
  TMHWinProcessApi = class(TInterfacedObject, IMHProcessApi)
  private
    FCpuCount: Integer;
    FElevated: Boolean;
    FPdh: TMHPdhQuery;
    FPrivateCounter: THandle;
    FPidCounter: THandle;
    FPrivateTick: UInt64;
    FPrivateSets: TArray<TMHPidBytes>;
    procedure RefreshPrivateSets;
  public
    /// Запущен ли текущий процесс с повышенными правами (токен elevated).
    class function QueryElevation: Boolean; static;
    constructor Create;
    destructor Destroy; override;
    function PrivateWorkingSets: TArray<TMHPidBytes>;
    function Enumerate(out AEntries: TArray<TMHRawProcessEntry>; out AError: string): Boolean;
    function Query(APid: Cardinal): TMHRawProcessDetails;
    function NowFileTime: UInt64;
    function LogicalCpuCount: Integer;
    function IsElevated: Boolean;
  end;

implementation

uses
  Winapi.Windows, Winapi.TlHelp32, Winapi.PsAPI, System.SysUtils,
  System.Generics.Collections,
  MineHunter.Core.Calc;

const
  // Не объявлены в Winapi.Windows Delphi 12; значения из документации Windows SDK.
  PROCESS_QUERY_LIMITED_INFORMATION = $1000;
  STILL_ACTIVE_CODE = 259;
  MAX_LONG_PATH = 32768;
  PRIVATE_WS_REFRESH_MS = 5000;

function QueryFullProcessImageNameW(hProcess: THandle; dwFlags: DWORD;
  lpExeName: PWideChar; var lpdwSize: DWORD): BOOL; stdcall;
  external kernel32 name 'QueryFullProcessImageNameW';

{ TMHWinProcessApi }

constructor TMHWinProcessApi.Create;
var
  LInfo: TSystemInfo;
begin
  inherited Create;
  GetSystemInfo(LInfo);
  FCpuCount := Integer(LInfo.dwNumberOfProcessors);
  if FCpuCount <= 0 then
    FCpuCount := 1;
  FElevated := QueryElevation;
  FPdh := TMHPdhQuery.Create;
  FPrivateCounter := FPdh.AddCounter('\Process(*)\Working Set - Private');
  FPidCounter := FPdh.AddCounter('\Process(*)\ID Process');
end;

destructor TMHWinProcessApi.Destroy;
begin
  FPdh.Free;
  inherited;
end;

procedure TMHWinProcessApi.RefreshPrivateSets;
var
  LPrivate, LPids: TArray<TMHPdhItem>;
  LPidByName: TDictionary<string, Cardinal>;
  LItem: TMHPdhItem;
  LPid: Cardinal;
  LList: TList<TMHPidBytes>;
  LValue: TMHPidBytes;
begin
  FPrivateSets := nil;
  if (FPrivateCounter = 0) or (FPidCounter = 0) or not FPdh.Collect then
    Exit;
  if not (FPdh.ReadArray(FPrivateCounter, LPrivate) and FPdh.ReadArray(FPidCounter, LPids)) then
    Exit;
  // Экземпляры объекта Process называются «имя#N»; PID берётся из счётчика
  // «ID Process» того же экземпляра в том же замере.
  LPidByName := TDictionary<string, Cardinal>.Create(Length(LPids));
  LList := TList<TMHPidBytes>.Create;
  try
    for LItem in LPids do
      LPidByName.AddOrSetValue(LItem.Name, Cardinal(Round(LItem.Value)));
    for LItem in LPrivate do
      // PID 0 — «Idle» и «_Total».
      if LPidByName.TryGetValue(LItem.Name, LPid) and (LPid <> 0) and (LItem.Value >= 0) then
      begin
        LValue.Pid := LPid;
        LValue.Bytes := UInt64(Round(LItem.Value));
        LList.Add(LValue);
      end;
    FPrivateSets := LList.ToArray;
  finally
    LList.Free;
    LPidByName.Free;
  end;
end;

function TMHWinProcessApi.PrivateWorkingSets: TArray<TMHPidBytes>;
var
  LNow: UInt64;
begin
  LNow := GetTickCount64;
  if (FPrivateTick = 0) or (LNow - FPrivateTick >= PRIVATE_WS_REFRESH_MS) then
  begin
    FPrivateTick := LNow;
    RefreshPrivateSets;
  end;
  Result := FPrivateSets;
end;

class function TMHWinProcessApi.QueryElevation: Boolean;
var
  LToken: THandle;
  LElevation: TTokenElevation;
  LSize: DWORD;
begin
  Result := False;
  if not OpenProcessToken(GetCurrentProcess, TOKEN_QUERY, LToken) then
    Exit;
  try
    LSize := 0;
    if GetTokenInformation(LToken, TokenElevation, @LElevation, SizeOf(LElevation), LSize) then
      Result := LElevation.TokenIsElevated <> 0;
  finally
    CloseHandle(LToken);
  end;
end;

function TMHWinProcessApi.Enumerate(out AEntries: TArray<TMHRawProcessEntry>;
  out AError: string): Boolean;
var
  LSnap: THandle;
  LEntry: TProcessEntry32W;
  LList: TList<TMHRawProcessEntry>;
  LRaw: TMHRawProcessEntry;
begin
  AEntries := nil;
  AError := '';
  LSnap := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if LSnap = INVALID_HANDLE_VALUE then
  begin
    AError := SysErrorMessage(GetLastError);
    Exit(False);
  end;
  LList := TList<TMHRawProcessEntry>.Create;
  try
    LEntry.dwSize := SizeOf(LEntry);
    if Process32FirstW(LSnap, LEntry) then
      repeat
        LRaw.Pid := LEntry.th32ProcessID;
        LRaw.ParentPid := LEntry.th32ParentProcessID;
        LRaw.ExeName := string(PWideChar(@LEntry.szExeFile[0]));
        LRaw.ThreadCount := Integer(LEntry.cntThreads);
        LList.Add(LRaw);
        LEntry.dwSize := SizeOf(LEntry);
      until not Process32NextW(LSnap, LEntry);
    if LList.Count = 0 then
    begin
      AError := SysErrorMessage(GetLastError);
      Exit(False);
    end;
    AEntries := LList.ToArray;
    Result := True;
  finally
    LList.Free;
    CloseHandle(LSnap);
  end;
end;

function TMHWinProcessApi.Query(APid: Cardinal): TMHRawProcessDetails;
var
  LHandle: THandle;
  LCreation, LExit, LKernel, LUser: TFileTime;
  LExitCode: DWORD;
  LBuffer: array of WideChar;
  LSize: DWORD;
  LCounters: TProcessMemoryCountersEx;
  LIo: TIoCounters;
begin
  Result := Default(TMHRawProcessDetails);
  // PID 0 — псевдопроцесс «System Idle Process»: открыть его нельзя,
  // но он существует; возвращаем пустые сведения без ошибки.
  if APid = 0 then
  begin
    Result.Status := pqOk;
    Exit;
  end;

  LHandle := OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, APid);
  if LHandle = 0 then
  begin
    if GetLastError = ERROR_INVALID_PARAMETER then
      Result.Status := pqGone
    else
      Result.Status := pqAccessDenied;
    Exit;
  end;
  try
    // Дескриптор мог открыться для уже завершённого процесса (зомби-объект).
    if GetExitCodeProcess(LHandle, LExitCode) and (LExitCode <> STILL_ACTIVE_CODE) then
    begin
      // Код возврата 259 мог вернуть и сам процесс; тогда проверяем время выхода ниже.
      if GetProcessTimes(LHandle, LCreation, LExit, LKernel, LUser) and
         (MHFileTimeToUInt64(LExit.dwLowDateTime, LExit.dwHighDateTime) <> 0) then
      begin
        Result.Status := pqGone;
        Exit;
      end;
    end;

    Result.Status := pqOk;
    if GetProcessTimes(LHandle, LCreation, LExit, LKernel, LUser) then
    begin
      Result.HasTimes := True;
      Result.CreateTime := MHFileTimeToUInt64(LCreation.dwLowDateTime, LCreation.dwHighDateTime);
      Result.CpuTime100ns :=
        MHFileTimeToUInt64(LKernel.dwLowDateTime, LKernel.dwHighDateTime) +
        MHFileTimeToUInt64(LUser.dwLowDateTime, LUser.dwHighDateTime);
    end;

    SetLength(LBuffer, MAX_LONG_PATH);
    LSize := Length(LBuffer);
    if QueryFullProcessImageNameW(LHandle, 0, PWideChar(LBuffer), LSize) and (LSize > 0) then
      SetString(Result.ImagePath, PWideChar(LBuffer), LSize);

    if GetProcessIoCounters(LHandle, LIo) then
    begin
      Result.HasIo := True;
      Result.IoReadBytes := LIo.ReadTransferCount;
      Result.IoWriteBytes := LIo.WriteTransferCount;
    end;

    FillChar(LCounters, SizeOf(LCounters), 0);
    LCounters.cb := SizeOf(LCounters);
    if GetProcessMemoryInfo(LHandle, PPROCESS_MEMORY_COUNTERS(@LCounters), SizeOf(LCounters)) then
    begin
      Result.HasMemory := True;
      Result.WorkingSetBytes := LCounters.WorkingSetSize;
      Result.PrivateBytes := LCounters.PrivateUsage;
    end;
  finally
    CloseHandle(LHandle);
  end;
end;

function TMHWinProcessApi.NowFileTime: UInt64;
var
  LFt: TFileTime;
begin
  GetSystemTimeAsFileTime(LFt);
  Result := MHFileTimeToUInt64(LFt.dwLowDateTime, LFt.dwHighDateTime);
end;

function TMHWinProcessApi.LogicalCpuCount: Integer;
begin
  Result := FCpuCount;
end;

function TMHWinProcessApi.IsElevated: Boolean;
begin
  Result := FElevated;
end;

end.
