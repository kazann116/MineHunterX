unit MineHunter.Collectors.System;

{
  Коллектор системных метрик (MH-02): загрузка CPU, память, диск, сеть,
  частота и предел производительности процессора.

  Загрузка CPU (mkCpuPercent) — «загруженность» с учётом частоты, как в
  диспетчере задач Windows 10/11 (счётчик «% Processor Utility»). Время работы
  без учёта частоты (GetSystemTimes) — mkCpuTimePercent; если счётчик
  загруженности недоступен, mkCpuPercent берётся из него.
  Активность диска — самый загруженный физический диск (как график диска в
  диспетчере задач), а не среднее по всем дискам.

  Системные вызовы скрыты за IMHSystemMetricsApi (реализация —
  MineHunter.Collectors.System.WinApi), поэтому расчёты проверяются на
  эталонных значениях без реальной нагрузки.

  GPU и датчики температуры — отдельные коллекторы (gpu, sensors).

  Коллектор не потокобезопасен: сканер вызывает Collect последовательно.
}

interface

uses
  System.SysUtils,
  MineHunter.Core.Types, MineHunter.Core.Interfaces;

type
  /// Значения GetSystemTimes в 100-нс единицах. Kernel включает Idle.
  TMHSystemTimes = record
    Idle: UInt64;
    Kernel: UInt64;
    User: UInt64;
  end;

  TMHMemoryStatus = record
    TotalBytes: UInt64;
    AvailableBytes: UInt64;
    LoadPercent: Cardinal;
  end;

  TMHDiskCounters = record
    /// False — значения недоступны (первый замер, отключены счётчики и т.п.).
    Available: Boolean;
    ReadBytesPerSec: Double;
    WriteBytesPerSec: Double;
    /// Активность самого загруженного физического диска, %.
    ActivePercent: Double;
    /// Причина недоступности для пользователя.
    Reason: string;
  end;

  /// Счётчики процессора; каждый может отсутствовать независимо от других.
  TMHProcessorCounters = record
    HasUtility: Boolean;
    /// «Загруженность» с учётом частоты, % (может превышать 100 при турбочастоте).
    UtilityPercent: Double;
    HasPerformance: Boolean;
    /// Производительность относительно базовой частоты, %.
    PerformancePercent: Double;
    HasLimit: Boolean;
    /// Предел производительности, % (100 — ограничений нет).
    LimitPercent: Double;
  end;

  TMHNetworkCounters = record
    Available: Boolean;
    /// Принято + передано всеми сетевыми адаптерами, байт/с.
    BytesPerSec: Double;
  end;

  /// Значения счётчиков производительности за один замер.
  TMHSystemCounters = record
    Disk: TMHDiskCounters;
    Processor: TMHProcessorCounters;
    Network: TMHNetworkCounters;
  end;

  IMHSystemMetricsApi = interface
    ['{6F0B7C1E-2E1A-4F57-9A0C-3D5B8E7A1C50}']
    function GetSystemTimes(out ATimes: TMHSystemTimes; out AError: string): Boolean;
    function GetMemory(out AStatus: TMHMemoryStatus; out AError: string): Boolean;
    /// Один замер всех счётчиков производительности. Скорости и загруженность
    /// считаются по двум замерам, поэтому в первом вызове недоступны.
    function GetCounters: TMHSystemCounters;
  end;

  TMHSystemCollector = class(TInterfacedObject, IMHCollector)
  public const
    SourceIdValue = 'system';
  private
    FApi: IMHSystemMetricsApi;
    FClock: IMHClock;
    FHasPrevious: Boolean;
    FPrevious: TMHSystemTimes;
  public
    constructor Create(const AApi: IMHSystemMetricsApi; const AClock: IMHClock);
    function GetSourceId: string;
    function GetDisplayName: string;
    function Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
  end;

implementation

uses
  System.Generics.Collections, System.Math,
  MineHunter.Core.Calc, MineHunter.Core.Lang;

constructor TMHSystemCollector.Create(const AApi: IMHSystemMetricsApi; const AClock: IMHClock);
begin
  inherited Create;
  if AApi = nil then
    raise EArgumentNilException.Create('AApi');
  if AClock = nil then
    raise EArgumentNilException.Create('AClock');
  FApi := AApi;
  FClock := AClock;
end;

function TMHSystemCollector.GetSourceId: string;
begin
  Result := SourceIdValue;
end;

function TMHSystemCollector.GetDisplayName: string;
begin
  Result := MHL('Система: CPU, память, диск', 'System: CPU, memory, disk');
end;

function TMHSystemCollector.Collect(const ASnapshot: TMHSnapshot): TMHCollectionResult;
var
  LNow: TDateTime;
  LMetrics: TList<TMHMetric>;
  LNotes: TStringBuilder;
  LTimes: TMHSystemTimes;
  LMemory: TMHMemoryStatus;
  LDisk: TMHDiskCounters;
  LCounters: TMHSystemCounters;
  LError: string;
  LIdle, LKernel, LUser: UInt64;
  LPercent, LUtility: Double;
  LCpuOk, LMemOk, LCpuValue: Boolean;
  LState: TMHSourceState;
begin
  LNow := ASnapshot.TimestampUtc;
  if LNow = 0 then
    LNow := FClock.NowUtc;
  LMetrics := TList<TMHMetric>.Create;
  LNotes := TStringBuilder.Create;
  try
    LCounters := FApi.GetCounters;

    // CPU: время работы (GetSystemTimes) и загруженность с учётом частоты.
    LCpuValue := False;
    LPercent := 0;
    LCpuOk := FApi.GetSystemTimes(LTimes, LError);
    if LCpuOk then
    begin
      if FHasPrevious and MHTryCounterDelta(FPrevious.Idle, LTimes.Idle, LIdle) and
         MHTryCounterDelta(FPrevious.Kernel, LTimes.Kernel, LKernel) and
         MHTryCounterDelta(FPrevious.User, LTimes.User, LUser) and
         MHTryCalcSystemCpuPercent(LIdle, LKernel, LUser, LPercent) then
        LCpuValue := True
      else
        LNotes.Append(MHL('Загрузка CPU будет доступна после следующего замера. ',
          'CPU load will be available after the next measurement. '));
      FPrevious := LTimes;
      FHasPrevious := True;
    end
    else
      LNotes.Append('CPU: ' + LError + '. ');
    if LCounters.Processor.HasUtility then
    begin
      // Диспетчер задач ограничивает загруженность 100%.
      LUtility := EnsureRange(LCounters.Processor.UtilityPercent, 0.0, 100.0);
      LMetrics.Add(TMHMetric.Available(mkCpuPercent, LUtility, LNow));
    end
    else if LCpuValue then
      LMetrics.Add(TMHMetric.Available(mkCpuPercent, LPercent, LNow))
    else
      LMetrics.Add(TMHMetric.NoData(mkCpuPercent, LNow));
    if LCpuValue then
      LMetrics.Add(TMHMetric.Available(mkCpuTimePercent, LPercent, LNow))
    else
      LMetrics.Add(TMHMetric.NoData(mkCpuTimePercent, LNow));
    if LCounters.Processor.HasPerformance and (LCounters.Processor.PerformancePercent > 0) then
      LMetrics.Add(TMHMetric.Available(mkCpuFrequencyPercent,
        LCounters.Processor.PerformancePercent, LNow))
    else
      LMetrics.Add(TMHMetric.NoData(mkCpuFrequencyPercent, LNow));
    if LCounters.Processor.HasLimit and (LCounters.Processor.LimitPercent > 0) then
      LMetrics.Add(TMHMetric.Available(mkCpuPerformanceLimitPercent,
        EnsureRange(LCounters.Processor.LimitPercent, 0.0, 100.0), LNow))
    else
      LMetrics.Add(TMHMetric.NoData(mkCpuPerformanceLimitPercent, LNow));

    // Память
    LMemOk := FApi.GetMemory(LMemory, LError) and (LMemory.TotalBytes > 0) and
      (LMemory.AvailableBytes <= LMemory.TotalBytes);
    if LMemOk then
    begin
      LMetrics.Add(TMHMetric.Available(mkMemoryUsedBytes,
        LMemory.TotalBytes - LMemory.AvailableBytes, LNow));
      LMetrics.Add(TMHMetric.Available(mkMemoryTotalBytes, LMemory.TotalBytes, LNow));
      // Точная доля вместо целого dwMemoryLoad — как «Используется» в диспетчере задач.
      LMetrics.Add(TMHMetric.Available(mkMemoryLoadPercent,
        Min(100.0, (LMemory.TotalBytes - LMemory.AvailableBytes) * 100.0 / LMemory.TotalBytes), LNow));
    end
    else
    begin
      if LError = '' then
        LError := MHL('некорректные данные о памяти', 'invalid memory data');
      LNotes.Append(MHL('Память: ', 'Memory: ') + LError + '. ');
      LMetrics.Add(TMHMetric.NoData(mkMemoryUsedBytes, LNow));
      LMetrics.Add(TMHMetric.NoData(mkMemoryTotalBytes, LNow));
      LMetrics.Add(TMHMetric.NoData(mkMemoryLoadPercent, LNow));
    end;

    // Диск
    LDisk := LCounters.Disk;
    if LDisk.Available then
    begin
      LMetrics.Add(TMHMetric.Available(mkDiskReadBytesPerSec, Max(0.0, LDisk.ReadBytesPerSec), LNow));
      LMetrics.Add(TMHMetric.Available(mkDiskWriteBytesPerSec, Max(0.0, LDisk.WriteBytesPerSec), LNow));
      LMetrics.Add(TMHMetric.Available(mkDiskActivePercent,
        EnsureRange(LDisk.ActivePercent, 0.0, 100.0), LNow));
    end
    else
    begin
      if LDisk.Reason <> '' then
        LNotes.Append(MHL('Диск: ', 'Disk: ') + LDisk.Reason + '. ');
      LMetrics.Add(TMHMetric.NoData(mkDiskReadBytesPerSec, LNow));
      LMetrics.Add(TMHMetric.NoData(mkDiskWriteBytesPerSec, LNow));
      LMetrics.Add(TMHMetric.NoData(mkDiskActivePercent, LNow));
    end;

    // Сеть (необязательно: на статус источника не влияет).
    if LCounters.Network.Available then
      LMetrics.Add(TMHMetric.Available(mkNetworkBytesPerSec, Max(0.0, LCounters.Network.BytesPerSec), LNow))
    else
      LMetrics.Add(TMHMetric.NoData(mkNetworkBytesPerSec, LNow));

    if not LCpuOk and not LMemOk and not LDisk.Available then
      LState := ssError
    else if LCpuValue and LMemOk and LDisk.Available then
      LState := ssSuccess
    else
      LState := ssPartial;

    Result := TMHCollectionResult.Create(TMHSourceStatus.Create(SourceIdValue, LState,
      Trim(LNotes.ToString), LNow));
    Result.Status.ItemCount := LMetrics.Count;
    Result.Metrics := LMetrics.ToArray;
  finally
    LNotes.Free;
    LMetrics.Free;
  end;
end;

end.
