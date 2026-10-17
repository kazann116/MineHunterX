unit MineHunter.Tests.FakeSystemApi;

{
  Управляемая имитация IMHSystemMetricsApi с эталонными значениями.
}

interface

uses
  MineHunter.Collectors.System;

type
  TFakeSystemMetricsApi = class(TInterfacedObject, IMHSystemMetricsApi)
  public
    Times: TMHSystemTimes;
    Memory: TMHMemoryStatus;
    Disk: TMHDiskCounters;
    /// По умолчанию недоступны: коллектор берёт загрузку CPU из GetSystemTimes.
    Processor: TMHProcessorCounters;
    Network: TMHNetworkCounters;
    TimesFail: Boolean;
    MemoryFail: Boolean;
    constructor Create;
    function GetSystemTimes(out ATimes: TMHSystemTimes; out AError: string): Boolean;
    function GetMemory(out AStatus: TMHMemoryStatus; out AError: string): Boolean;
    function GetCounters: TMHSystemCounters;
    /// Продвигает счётчики: за интервал AWall100ns на ACpuCount ядрах
    /// занято ABusyPercent процентов времени (ядро/пользователь — пополам).
    procedure Advance(AWall100ns: UInt64; ACpuCount: Integer; ABusyPercent: Double);
  end;

const
  GB = UInt64(1024) * 1024 * 1024;

implementation

constructor TFakeSystemMetricsApi.Create;
begin
  inherited Create;
  Times.Idle := 1000000000;
  Times.Kernel := 2000000000; // включает Idle
  Times.User := 500000000;
  Memory.TotalBytes := 16 * GB;
  Memory.AvailableBytes := 6 * GB;
  Memory.LoadPercent := 62;
  Disk.Available := True;
  Disk.ReadBytesPerSec := 1048576;
  Disk.WriteBytesPerSec := 524288;
  Disk.ActivePercent := 12.5;
end;

function TFakeSystemMetricsApi.GetSystemTimes(out ATimes: TMHSystemTimes;
  out AError: string): Boolean;
begin
  ATimes := Times;
  AError := '';
  Result := not TimesFail;
  if not Result then
    AError := 'simulated GetSystemTimes failure';
end;

function TFakeSystemMetricsApi.GetMemory(out AStatus: TMHMemoryStatus;
  out AError: string): Boolean;
begin
  AStatus := Memory;
  AError := '';
  Result := not MemoryFail;
  if not Result then
    AError := 'simulated memory failure';
end;

function TFakeSystemMetricsApi.GetCounters: TMHSystemCounters;
begin
  Result.Disk := Disk;
  Result.Processor := Processor;
  Result.Network := Network;
end;

procedure TFakeSystemMetricsApi.Advance(AWall100ns: UInt64; ACpuCount: Integer;
  ABusyPercent: Double);
var
  LTotal, LBusy, LIdle: UInt64;
begin
  LTotal := AWall100ns * UInt64(ACpuCount);
  LBusy := Round(LTotal * ABusyPercent / 100);
  LIdle := LTotal - LBusy;
  Inc(Times.Idle, LIdle);
  Inc(Times.Kernel, LIdle + LBusy div 2);
  Inc(Times.User, LBusy - LBusy div 2);
end;

end.
