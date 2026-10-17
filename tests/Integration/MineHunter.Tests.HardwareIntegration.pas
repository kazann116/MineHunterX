unit MineHunter.Tests.HardwareIntegration;

{
  Реальные источники Windows: счётчики процессора, GPU (PDH, D3DKMT, NVML),
  частный рабочий набор, температуры накопителей и LibreHardwareMonitor.
  Значения зависят от оборудования, поэтому проверяются диапазоны и
  устойчивость (нет исключений, «нет данных» — с причиной); фактические
  числа выводятся в журнал теста для сверки с диспетчером задач.
}

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  [Category('Integration')]
  THardwareIntegrationTests = class
  public
    [Test] procedure SystemCounters_UtilityAndLimitsInRange;
    [Test] procedure PrivateWorkingSet_IncludesOwnProcess;
    [Test] procedure Gpu_CountersAndSensors_InRangeOrReason;
    [Test] procedure Sensors_DiskAndCpu_InRangeOrReason;
    [Test] procedure Tamper_RealSources_ReadOrExplain;
  end;

implementation

uses
  Winapi.Windows, System.SysUtils,
  MineHunter.Collectors.System, MineHunter.Collectors.System.WinApi,
  MineHunter.Collectors.Processes, MineHunter.Collectors.Processes.WinApi,
  MineHunter.Collectors.Gpu, MineHunter.Collectors.Gpu.WinApi,
  MineHunter.Collectors.Sensors, MineHunter.Collectors.Sensors.WinApi,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Collectors.Tamper,
  MineHunter.Collectors.Tamper.WinApi, MineHunter.Tests.Fakes;

procedure Log(const AText: string);
begin
  System.Writeln('  [hw] ' + AText);
end;

procedure THardwareIntegrationTests.SystemCounters_UtilityAndLimitsInRange;
var
  LApi: IMHSystemMetricsApi;
  LCounters: TMHSystemCounters;
begin
  LApi := TMHWinSystemMetricsApi.Create;
  LApi.GetCounters;
  Sleep(1000);
  LCounters := LApi.GetCounters;
  Log(Format('CPU: загруженность %s, частота %s, предел %s; диск %s; сеть %s',
    [BoolToStr(LCounters.Processor.HasUtility, True) + ' ' + FormatFloat('0.0', LCounters.Processor.UtilityPercent),
     FormatFloat('0', LCounters.Processor.PerformancePercent),
     FormatFloat('0', LCounters.Processor.LimitPercent),
     FormatFloat('0.0', LCounters.Disk.ActivePercent),
     FormatFloat('0', LCounters.Network.BytesPerSec)]));
  if LCounters.Processor.HasUtility then
    Assert.IsTrue((LCounters.Processor.UtilityPercent >= 0) and (LCounters.Processor.UtilityPercent < 1000));
  if LCounters.Processor.HasLimit then
    Assert.IsTrue((LCounters.Processor.LimitPercent >= 0) and (LCounters.Processor.LimitPercent <= 100.5));
  if LCounters.Disk.Available then
    Assert.IsTrue((LCounters.Disk.ActivePercent >= 0) and (LCounters.Disk.ActivePercent <= 100))
  else
    Assert.IsTrue(LCounters.Disk.Reason <> '');
end;

procedure THardwareIntegrationTests.PrivateWorkingSet_IncludesOwnProcess;
var
  LApi: IMHProcessApi;
  LValue: TMHPidBytes;
  LFound: Boolean;
  LCount: Integer;
begin
  LApi := TMHWinProcessApi.Create;
  LFound := False;
  LCount := 0;
  for LValue in LApi.PrivateWorkingSets do
  begin
    Inc(LCount);
    if LValue.Pid = GetCurrentProcessId then
    begin
      LFound := True;
      Log(Format('Частный рабочий набор теста: %.1f МБ (процессов: всего в счётчике)',
        [LValue.Bytes / 1048576]));
      Assert.IsTrue(LValue.Bytes > 1048576, 'У процесса теста больше 1 МБ частной памяти');
    end;
  end;
  Log(Format('Процессов с частным рабочим набором: %d', [LCount]));
  Assert.IsTrue(LCount > 10, 'Счётчик Process(*) возвращает процессы системы');
  Assert.IsTrue(LFound, 'Собственный процесс найден по PID');
end;

procedure THardwareIntegrationTests.Gpu_CountersAndSensors_InRangeOrReason;
var
  LApi: IMHGpuApi;
  LCounters: TMHGpuCounters;
  LSensors: TArray<TMHGpuSensor>;
  LSensor: TMHGpuSensor;
  LReason: string;
  LSample: TMHGpuCounterSample;
begin
  LApi := TMHWinGpuApi.Create;
  LCounters := LApi.GetCounters;
  Assert.IsFalse(LCounters.Available, 'Первый замер — только подготовка скоростей');
  Sleep(1000);
  LCounters := LApi.GetCounters;
  Log(Format('GPU: счётчики %s (%s), движков %d, памяти процессов %d, адаптеров %d',
    [BoolToStr(LCounters.Available, True), LCounters.Reason, Length(LCounters.Engines),
     Length(LCounters.ProcessMemory), Length(LCounters.AdapterMemory)]));
  if LCounters.Available then
    for LSample in LCounters.Engines do
      Assert.IsTrue((LSample.Value >= 0) and (LSample.Value <= 100.5), LSample.InstanceName)
  else
    Assert.IsTrue(LCounters.Reason <> '');
  LSensors := LApi.GetSensors(LReason);
  for LSensor in LSensors do
  begin
    Log(Format('GPU-датчик %s [%s]: %s %.1f °C, порог снижения частоты %s %.0f °C',
      [LSensor.AdapterName, LSensor.Source, BoolToStr(LSensor.HasTemperature, True),
       LSensor.TemperatureCelsius, BoolToStr(LSensor.HasSlowdown, True), LSensor.SlowdownCelsius]));
    if LSensor.HasTemperature then
      Assert.IsTrue((LSensor.TemperatureCelsius > 0) and (LSensor.TemperatureCelsius < 150));
  end;
  if LReason <> '' then
    Log('GPU-датчики: ' + LReason);
end;

procedure THardwareIntegrationTests.Sensors_DiskAndCpu_InRangeOrReason;
var
  LApi: IMHSensorApi;
  LReading: TMHTemperatureReading;
  LReason: string;
  LReadings: TArray<TMHTemperatureReading>;
begin
  LApi := TMHWinSensorApi.Create;
  LReadings := LApi.ReadDiskTemperatures(LReason);
  for LReading in LReadings do
  begin
    Log(Format('Накопитель %s: %.0f °C (порог %s %.0f °C)', [LReading.Device, LReading.Celsius,
      BoolToStr(LReading.HasWarning, True), LReading.WarningCelsius]));
    Assert.IsTrue((LReading.Celsius > 0) and (LReading.Celsius < 150));
  end;
  if Length(LReadings) = 0 then
  begin
    Log('Накопители: ' + LReason);
    Assert.IsTrue(LReason <> '');
  end;
  LReadings := LApi.ReadCpuTemperatures(LReason);
  for LReading in LReadings do
    Log(Format('CPU-датчик %s [%s]: %.1f °C', [LReading.Device, LReading.Source, LReading.Celsius]));
  if Length(LReadings) = 0 then
  begin
    Log('CPU: ' + LReason);
    Assert.IsTrue(LReason <> '');
  end;
end;

procedure THardwareIntegrationTests.Tamper_RealSources_ReadOrExplain;
var
  LCollector: IMHCollector;
  LResult: TMHCollectionResult;
  LEntry: TMHTamperEntry;
begin
  LCollector := TMHTamperCollector.Create(TMHWinTamperApi.Create, TFakeClock.Create(FAKE_NOW));
  LResult := LCollector.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Log(Format('Вмешательство: состояние %s, записей %d; %s', [MHSourceStateToString(LResult.Status.State),
    Length(LResult.Tamper), LResult.Status.Message]));
  for LEntry in LResult.Tamper do
    Log(Format('  %s: %s = %s (%s)', [MHTamperKindToString(LEntry.Kind), LEntry.Name,
      Copy(LEntry.Value, 1, 120), LEntry.Location]));
  Assert.AreNotEqual<TMHSourceState>(ssError, LResult.Status.State,
    'Хотя бы реестр и hosts читаются без прав администратора');
end;

initialization
  TDUnitX.RegisterTestFixture(THardwareIntegrationTests);

end.
