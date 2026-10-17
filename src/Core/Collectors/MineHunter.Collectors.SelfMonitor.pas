unit MineHunter.Collectors.SelfMonitor;

{
  Коллектор самодиагностики: нагрузка CPU и память процесса MineHunter.
  Нужен для контроля нефункциональных требований (≤ 2% CPU, ≤ 200 МБ)
  и как эталон контракта IMHCollector.

  Первый вызов возвращает ssPartial: загрузка CPU считается по дельте
  и становится доступна со второго замера.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

type
  TMHSelfMonitorCollector = class(TInterfacedObject, IMHCollector)
  public const
    SourceIdValue = MH_SELF_SOURCE_ID;
  private
    FClock: IMHClock;
    FHasPrevious: Boolean;
    FPrevCpu100ns: UInt64;
    FPrevWall100ns: UInt64;
    FCpuCount: Integer;
  public
    constructor Create(const AClock: IMHClock);
    function GetSourceId: string;
    function GetDisplayName: string;
    function Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
  end;

implementation

uses
  Winapi.Windows, Winapi.PsAPI,
  MineHunter.Core.Calc, MineHunter.Core.Lang;

{ TMHSelfMonitorCollector }

constructor TMHSelfMonitorCollector.Create(const AClock: IMHClock);
var
  LInfo: TSystemInfo;
begin
  inherited Create;
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  FClock := AClock;
  GetSystemInfo(LInfo);
  FCpuCount := Integer(LInfo.dwNumberOfProcessors);
  if FCpuCount <= 0 then
    FCpuCount := 1;
end;

function TMHSelfMonitorCollector.GetSourceId: string;
begin
  Result := SourceIdValue;
end;

function TMHSelfMonitorCollector.GetDisplayName: string;
begin
  Result := MHL('Самодиагностика MineHunter', 'MineHunter self-monitoring');
end;

function TMHSelfMonitorCollector.Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
var
  LNow: TDateTime;
  LCreation, LExit, LKernel, LUser, LWallFt: TFileTime;
  LCpuNow, LWallNow, LCpuDelta, LWallDelta: UInt64;
  LPercent: Double;
  LCounters: TProcessMemoryCounters;
  LInfo: TMHProcessInfo;
  LState: TMHSourceState;
  LMessage: string;
  LProcess: THandle;
begin
  LNow := ASnapshot.TimestampUtc;
  if LNow = 0 then
    LNow := FClock.NowUtc;
  LProcess := GetCurrentProcess; // псевдодескриптор, закрывать не нужно
  LState := ssSuccess;
  LMessage := '';

  if not GetProcessTimes(LProcess, LCreation, LExit, LKernel, LUser) then
    Exit(TMHCollectionResult.Create(TMHSourceStatus.Create(SourceIdValue, ssError,
      'GetProcessTimes: ' + SysErrorMessage(GetLastError), LNow)));

  LInfo := TMHProcessInfo.Create(
    TMHProcessId.Create(GetCurrentProcessId,
      MHFileTimeToUInt64(LCreation.dwLowDateTime, LCreation.dwHighDateTime)),
    ExtractFileName(ParamStr(0)), LNow);
  LInfo.ImagePath := ParamStr(0);
  LInfo.Access := alFull;
  LInfo.SourceId := SourceIdValue;

  GetSystemTimeAsFileTime(LWallFt);
  LCpuNow := MHFileTimeToUInt64(LKernel.dwLowDateTime, LKernel.dwHighDateTime) +
    MHFileTimeToUInt64(LUser.dwLowDateTime, LUser.dwHighDateTime);
  LWallNow := MHFileTimeToUInt64(LWallFt.dwLowDateTime, LWallFt.dwHighDateTime);

  if FHasPrevious and MHTryCounterDelta(FPrevCpu100ns, LCpuNow, LCpuDelta) and
     MHTryCounterDelta(FPrevWall100ns, LWallNow, LWallDelta) and
     MHTryCalcCpuPercent(LCpuDelta, LWallDelta, FCpuCount, LPercent) then
    LInfo.Cpu := TMHMetric.Available(mkCpuPercent, LPercent, LNow)
  else
  begin
    LState := ssPartial;
    LMessage := MHL('Загрузка CPU будет доступна после следующего замера',
      'CPU load will be available after the next measurement');
  end;
  FPrevCpu100ns := LCpuNow;
  FPrevWall100ns := LWallNow;
  FHasPrevious := True;

  FillChar(LCounters, SizeOf(LCounters), 0);
  LCounters.cb := SizeOf(LCounters);
  if GetProcessMemoryInfo(LProcess, @LCounters, SizeOf(LCounters)) then
  begin
    LInfo.WorkingSet := TMHMetric.Available(mkWorkingSetBytes, LCounters.WorkingSetSize, LNow);
    LInfo.PrivateBytes := TMHMetric.Available(mkPrivateBytes, LCounters.PagefileUsage, LNow);
  end
  else
  begin
    LState := ssPartial;
    LMessage := 'GetProcessMemoryInfo: ' + SysErrorMessage(GetLastError);
  end;

  Result := TMHCollectionResult.Create(
    TMHSourceStatus.Create(SourceIdValue, LState, LMessage, LNow));
  Result.Status.ItemCount := 1;
  Result.Processes := [LInfo];
end;

end.
