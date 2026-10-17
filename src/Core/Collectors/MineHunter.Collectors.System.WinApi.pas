unit MineHunter.Collectors.System.WinApi;

{
  Реализация IMHSystemMetricsApi:
    - GetSystemTimes — время работы процессоров;
    - GlobalMemoryStatusEx — память;
    - PDH (Performance Data Helper, MineHunter.Collectors.Pdh) — загруженность
      и частота процессора, предел производительности, диски, сеть. Счётчики
      независимы: недоступность одного не отключает остальные.
  Права администратора не требуются. Если счётчики производительности
  отключены или повреждены, соответствующие значения помечаются как
  недоступные с причиной, а CPU и память продолжают собираться.
}

interface

uses
  Winapi.Windows,
  MineHunter.Collectors.System, MineHunter.Collectors.Pdh;

type
  TMHWinSystemMetricsApi = class(TInterfacedObject, IMHSystemMetricsApi)
  private
    FPdh: TMHPdhQuery;
    FReadCounter: THandle;
    FWriteCounter: THandle;
    FDiskIdleCounter: THandle;
    FUtilityCounter: THandle;
    FPerformanceCounter: THandle;
    FLimitCounter: THandle;
    FNetworkCounter: THandle;
    FDiskError: string;
    procedure InitPdh;
    function ReadDisk: TMHDiskCounters;
  public
    constructor Create;
    destructor Destroy; override;
    function GetSystemTimes(out ATimes: TMHSystemTimes; out AError: string): Boolean;
    function GetMemory(out AStatus: TMHMemoryStatus; out AError: string): Boolean;
    function GetCounters: TMHSystemCounters;
  end;

implementation

uses
  System.SysUtils, System.Math,
  MineHunter.Core.Calc, MineHunter.Core.Lang;

{ TMHWinSystemMetricsApi }

constructor TMHWinSystemMetricsApi.Create;
begin
  inherited Create;
  InitPdh;
end;

destructor TMHWinSystemMetricsApi.Destroy;
begin
  FPdh.Free;
  inherited;
end;

procedure TMHWinSystemMetricsApi.InitPdh;
begin
  FPdh := TMHPdhQuery.Create;
  if not FPdh.IsOpen then
  begin
    FDiskError := FPdh.LastError;
    Exit;
  end;
  FReadCounter := FPdh.AddCounter('\PhysicalDisk(_Total)\Disk Read Bytes/sec');
  FWriteCounter := FPdh.AddCounter('\PhysicalDisk(_Total)\Disk Write Bytes/sec');
  FDiskIdleCounter := FPdh.AddCounter('\PhysicalDisk(*)\% Idle Time');
  if (FReadCounter = 0) or (FWriteCounter = 0) or (FDiskIdleCounter = 0) then
    FDiskError := FPdh.LastError;
  // Счётчики процессора есть в Windows 8+; «% Processor Utility» — то, что
  // показывает диспетчер задач Windows 10/11.
  FUtilityCounter := FPdh.AddCounter('\Processor Information(_Total)\% Processor Utility');
  FPerformanceCounter := FPdh.AddCounter('\Processor Information(_Total)\% Processor Performance');
  FLimitCounter := FPdh.AddCounter('\Processor Information(_Total)\% Performance Limit');
  FNetworkCounter := FPdh.AddCounter('\Network Interface(*)\Bytes Total/sec');
end;
function TMHWinSystemMetricsApi.GetSystemTimes(out ATimes: TMHSystemTimes;
  out AError: string): Boolean;
var
  LIdle, LKernel, LUser: TFileTime;
begin
  ATimes := Default(TMHSystemTimes);
  AError := '';
  Result := Winapi.Windows.GetSystemTimes(LIdle, LKernel, LUser);
  if not Result then
  begin
    AError := SysErrorMessage(GetLastError);
    Exit;
  end;
  ATimes.Idle := MHFileTimeToUInt64(LIdle.dwLowDateTime, LIdle.dwHighDateTime);
  ATimes.Kernel := MHFileTimeToUInt64(LKernel.dwLowDateTime, LKernel.dwHighDateTime);
  ATimes.User := MHFileTimeToUInt64(LUser.dwLowDateTime, LUser.dwHighDateTime);
end;

function TMHWinSystemMetricsApi.GetMemory(out AStatus: TMHMemoryStatus;
  out AError: string): Boolean;
var
  LStatus: TMemoryStatusEx;
begin
  AStatus := Default(TMHMemoryStatus);
  AError := '';
  FillChar(LStatus, SizeOf(LStatus), 0);
  LStatus.dwLength := SizeOf(LStatus);
  Result := GlobalMemoryStatusEx(LStatus);
  if not Result then
  begin
    AError := SysErrorMessage(GetLastError);
    Exit;
  end;
  AStatus.TotalBytes := LStatus.ullTotalPhys;
  AStatus.AvailableBytes := LStatus.ullAvailPhys;
  AStatus.LoadPercent := LStatus.dwMemoryLoad;
end;

function TMHWinSystemMetricsApi.ReadDisk: TMHDiskCounters;
var
  LItems: TArray<TMHPdhItem>;
  LItem: TMHPdhItem;
  LActive, LMaxActive: Double;
  LHasDisk: Boolean;
begin
  Result := Default(TMHDiskCounters);
  if (FReadCounter = 0) or (FWriteCounter = 0) or (FDiskIdleCounter = 0) then
  begin
    Result.Reason := FDiskError;
    Exit;
  end;
  if FPdh.Collects < 2 then
  begin
    Result.Reason := MHL('скорость будет доступна после следующего замера', 'speed will be available after the next measurement');
    Exit;
  end;
  if not (FPdh.Read(FReadCounter, Result.ReadBytesPerSec) and
          FPdh.Read(FWriteCounter, Result.WriteBytesPerSec) and
          FPdh.ReadArray(FDiskIdleCounter, LItems)) then
  begin
    Result.Reason := MHL('счётчики диска вернули некорректные данные', 'disk counters returned invalid data');
    Exit;
  end;
  // Как в диспетчере задач: активность — у самого загруженного диска.
  LHasDisk := False;
  LMaxActive := 0;
  for LItem in LItems do
  begin
    if SameText(LItem.Name, '_Total') then
      Continue;
    LActive := EnsureRange(100.0 - LItem.Value, 0.0, 100.0);
    if not LHasDisk or (LActive > LMaxActive) then
      LMaxActive := LActive;
    LHasDisk := True;
  end;
  if not LHasDisk then
  begin
    Result.Reason := MHL('физические диски не найдены в счётчиках производительности',
      'no physical disks found in performance counters');
    Exit;
  end;
  Result.ActivePercent := LMaxActive;
  Result.Available := True;
end;

function TMHWinSystemMetricsApi.GetCounters: TMHSystemCounters;
var
  LItems: TArray<TMHPdhItem>;
  LItem: TMHPdhItem;
  LSum: Double;
begin
  Result := Default(TMHSystemCounters);
  if not FPdh.Collect then
  begin
    Result.Disk.Reason := FPdh.LastError;
    Exit;
  end;
  Result.Disk := ReadDisk;
  if FPdh.Collects >= 2 then
  begin
    Result.Processor.HasUtility := FPdh.Read(FUtilityCounter, Result.Processor.UtilityPercent);
    Result.Processor.HasPerformance := FPdh.Read(FPerformanceCounter, Result.Processor.PerformancePercent);
    Result.Processor.HasLimit := FPdh.Read(FLimitCounter, Result.Processor.LimitPercent);
    if FPdh.ReadArray(FNetworkCounter, LItems) then
    begin
      LSum := 0;
      for LItem in LItems do
        LSum := LSum + Max(0.0, LItem.Value);
      Result.Network.BytesPerSec := LSum;
      Result.Network.Available := True;
    end;
  end;
end;

end.
