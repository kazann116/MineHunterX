unit MineHunter.Tests.GpuSensors;

{
  Коллекторы GPU и датчиков температуры на управляемых двойниках API:
  разбор имён счётчиков, расчёт «как в диспетчере задач», сопоставление с
  процессами, вычислительные движки, температура, недоступность источников.
}

interface

uses
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.Interfaces,
  MineHunter.Collectors.Gpu, MineHunter.Collectors.Sensors;

type
  TFakeGpuApi = class(TInterfacedObject, IMHGpuApi)
  public
    Counters: TMHGpuCounters;
    Sensors: TArray<TMHGpuSensor>;
    SensorReason: string;
    function GetCounters: TMHGpuCounters;
    function GetSensors(out AReason: string): TArray<TMHGpuSensor>;
  end;

  TFakeSensorApi = class(TInterfacedObject, IMHSensorApi)
  public
    Disks: TArray<TMHTemperatureReading>;
    DiskReason: string;
    Cpu: TArray<TMHTemperatureReading>;
    CpuReason: string;
    function ReadDiskTemperatures(out AReason: string): TArray<TMHTemperatureReading>;
    function ReadCpuTemperatures(out AReason: string): TArray<TMHTemperatureReading>;
  end;

  [TestFixture]
  [Category('Unit')]
  TGpuCollectorTests = class
  private
    FApi: TFakeGpuApi;
    FApiIntf: IMHGpuApi;
    FCollector: IMHCollector;
    function Snapshot: TMHSnapshot;
    function Detail(const AResult: TMHCollectionResult; APid: Cardinal): TMHProcessDetail;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Parse_EngineInstance;
    [Test] procedure Parse_EngineTypeWithUnderscore;
    [Test] procedure Parse_Invalid_ReturnsFalse;
    [Test] procedure Parse_ProcessMemoryInstance;
    [Test] procedure ComputeEngineTypes;
    [Test] procedure ProcessGpu_IsBusiestEngine;
    [Test] procedure SystemGpu_IsBusiestEngineSummedOverProcesses;
    [Test] procedure Compute_OnlyComputeAndCudaEngines;
    [Test] procedure ProcessWithoutGpuInstances_IsZeroNotNoData;
    [Test] procedure UnknownPid_IsIgnored;
    [Test] procedure Memory_ProcessAndAdapter;
    [Test] procedure Values_AreClamped;
    [Test] procedure FirstSample_IsPartialNoData;
    [Test] procedure CountersUnavailable_IsUnavailableWithReason;
    [Test] procedure Temperature_HottestAdapter;
    [Test] procedure Temperature_ImplausibleIgnoredWithReason;
    [Test] procedure NilArguments_Raise;
  end;

  [TestFixture]
  [Category('Unit')]
  TSensorCollectorTests = class
  private
    FApi: TFakeSensorApi;
    FApiIntf: IMHSensorApi;
    FCollector: IMHCollector;
    function Metric(const AResult: TMHCollectionResult; AKind: TMHMetricKind): TMHMetric;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Disk_HottestDrive;
    [Test] procedure Cpu_PrefersPackageSensor;
    [Test] procedure Cpu_WithoutPackage_HottestSensor;
    [Test] procedure Nothing_IsUnavailableWithReasons;
    [Test] procedure OnlyDisk_IsPartial;
    [Test] procedure ImplausibleValues_Ignored;
  end;

implementation

uses
  System.SysUtils,
  MineHunter.Tests.Fakes;

const
  ADAPTER = 'luid_0x00000000_0x000102c2_phys_0';

function Engine(APid: Cardinal; AEngine: Integer; const AType: string; AValue: Double): TMHGpuCounterSample;
begin
  Result.InstanceName := Format('pid_%d_%s_eng_%d_engtype_%s', [APid, ADAPTER, AEngine, AType]);
  Result.Value := AValue;
end;

function Sample(const AName: string; AValue: Double): TMHGpuCounterSample;
begin
  Result.InstanceName := AName;
  Result.Value := AValue;
end;

function Sensor(const AName: string; ATemperature: Double; AHas: Boolean = True): TMHGpuSensor;
begin
  Result := Default(TMHGpuSensor);
  Result.AdapterName := AName;
  Result.Source := 'D3DKMT';
  Result.HasTemperature := AHas;
  Result.TemperatureCelsius := ATemperature;
end;

function Reading(const ADevice: string; ACelsius: Double): TMHTemperatureReading;
begin
  Result := Default(TMHTemperatureReading);
  Result.Device := ADevice;
  Result.Celsius := ACelsius;
end;

function MetricOf(const AResult: TMHCollectionResult; AKind: TMHMetricKind): TMHMetric;
var
  LMetric: TMHMetric;
begin
  for LMetric in AResult.Metrics do
    if LMetric.Kind = AKind then
      Exit(LMetric);
  Assert.Fail('Метрика отсутствует: ' + IntToStr(Ord(AKind)));
  Result := TMHMetric.NoData(AKind, 0);
end;

{ TFakeGpuApi }

function TFakeGpuApi.GetCounters: TMHGpuCounters;
begin
  Result := Counters;
end;

function TFakeGpuApi.GetSensors(out AReason: string): TArray<TMHGpuSensor>;
begin
  AReason := SensorReason;
  Result := Sensors;
end;

{ TFakeSensorApi }

function TFakeSensorApi.ReadDiskTemperatures(out AReason: string): TArray<TMHTemperatureReading>;
begin
  AReason := DiskReason;
  Result := Disks;
end;

function TFakeSensorApi.ReadCpuTemperatures(out AReason: string): TArray<TMHTemperatureReading>;
begin
  AReason := CpuReason;
  Result := Cpu;
end;

{ TGpuCollectorTests }

procedure TGpuCollectorTests.Setup;
begin
  FApi := TFakeGpuApi.Create;
  FApiIntf := FApi;
  FApi.Counters.Available := True;
  FCollector := TMHGpuCollector.Create(FApiIntf, TFakeClock.Create(FAKE_NOW));
end;

procedure TGpuCollectorTests.TearDown;
begin
  FCollector := nil;
  FApiIntf := nil;
  FApi := nil;
end;

function TGpuCollectorTests.Snapshot: TMHSnapshot;
begin
  Result := TMHSnapshot.Create(1, FAKE_NOW);
  Result.Processes := [
    TMHProcessInfo.Create(TMHProcessId.Create(100, 11), 'game.exe', FAKE_NOW),
    TMHProcessInfo.Create(TMHProcessId.Create(200, 22), 'miner.exe', FAKE_NOW),
    TMHProcessInfo.Create(TMHProcessId.Create(300, 33), 'notepad.exe', FAKE_NOW)];
end;

function TGpuCollectorTests.Detail(const AResult: TMHCollectionResult; APid: Cardinal): TMHProcessDetail;
var
  LDetail: TMHProcessDetail;
begin
  for LDetail in AResult.ProcessDetails do
    if LDetail.Id.Pid = APid then
      Exit(LDetail);
  Assert.Fail('Нет сведений о процессе ' + IntToStr(APid));
  Result := TMHProcessDetail.Create(TMHProcessId.Empty);
end;

procedure TGpuCollectorTests.Parse_EngineInstance;
var
  LInstance: TMHGpuEngineInstance;
begin
  Assert.IsTrue(MHParseGpuEngineInstance(
    'pid_972_luid_0x00000000_0x000102c2_phys_0_eng_0_engtype_3D', LInstance));
  Assert.AreEqual(Cardinal(972), LInstance.Pid);
  Assert.AreEqual(ADAPTER, LInstance.Adapter);
  Assert.AreEqual(ADAPTER + '_eng_0', LInstance.Engine);
  Assert.AreEqual('3d', LInstance.EngineType, 'Тип приводится к нижнему регистру');
end;

procedure TGpuCollectorTests.Parse_EngineTypeWithUnderscore;
var
  LInstance: TMHGpuEngineInstance;
begin
  Assert.IsTrue(MHParseGpuEngineInstance(
    'pid_18164_luid_0x00000000_0x000102c2_phys_0_eng_7_engtype_Compute_1', LInstance));
  Assert.AreEqual('compute_1', LInstance.EngineType);
  Assert.AreEqual(ADAPTER + '_eng_7', LInstance.Engine);
end;

procedure TGpuCollectorTests.Parse_Invalid_ReturnsFalse;
var
  LInstance: TMHGpuEngineInstance;
begin
  Assert.IsFalse(MHParseGpuEngineInstance('', LInstance));
  Assert.IsFalse(MHParseGpuEngineInstance('_Total', LInstance));
  Assert.IsFalse(MHParseGpuEngineInstance('pid_abc_luid_0x0_0x1_phys_0_eng_0_engtype_3d', LInstance));
  Assert.IsFalse(MHParseGpuEngineInstance('pid_5_luid_0x0_0x1_phys_0', LInstance), 'Нет движка');
  Assert.IsFalse(MHParseGpuEngineInstance('pid_99999999999_luid_0x0_0x1_phys_0_eng_0_engtype_3d', LInstance),
    'PID за пределами 32 бит');
end;

procedure TGpuCollectorTests.Parse_ProcessMemoryInstance;
var
  LPid: Cardinal;
  LAdapter: string;
begin
  Assert.IsTrue(MHParseGpuProcessMemoryInstance('pid_18164_' + ADAPTER, LPid, LAdapter));
  Assert.AreEqual(Cardinal(18164), LPid);
  Assert.AreEqual(ADAPTER, LAdapter);
  Assert.IsFalse(MHParseGpuProcessMemoryInstance(ADAPTER, LPid, LAdapter), 'Память адаптера — без PID');
end;

procedure TGpuCollectorTests.ComputeEngineTypes;
begin
  Assert.IsTrue(MHIsComputeEngineType('compute_0'));
  Assert.IsTrue(MHIsComputeEngineType('Compute_1'));
  Assert.IsTrue(MHIsComputeEngineType('cuda'));
  Assert.IsFalse(MHIsComputeEngineType('3d'));
  Assert.IsFalse(MHIsComputeEngineType('videodecode'));
  Assert.IsFalse(MHIsComputeEngineType('copy'));
end;

procedure TGpuCollectorTests.ProcessGpu_IsBusiestEngine;
var
  LResult: TMHCollectionResult;
begin
  FApi.Counters.Engines := [Engine(100, 0, '3d', 60), Engine(100, 5, 'copy', 10),
    Engine(100, 8, 'videodecode', 25)];
  LResult := FCollector.Collect(Snapshot);
  Assert.AreEqual(60.0, Detail(LResult, 100).Gpu.Value, 0.001);
  Assert.AreEqual(0.0, Detail(LResult, 100).GpuCompute.Value, 0.001);
  Assert.IsTrue(Detail(LResult, 100).Id = TMHProcessId.Create(100, 11),
    'Сведения привязаны к экземпляру процесса снимка');
end;

procedure TGpuCollectorTests.SystemGpu_IsBusiestEngineSummedOverProcesses;
var
  LResult: TMHCollectionResult;
begin
  // Два процесса делят движок 3D: 30 + 25 = 55%; копирование — 40%.
  FApi.Counters.Engines := [Engine(100, 0, '3d', 30), Engine(200, 0, '3d', 25),
    Engine(300, 5, 'copy', 40)];
  LResult := FCollector.Collect(Snapshot);
  Assert.AreEqual(55.0, MetricOf(LResult, mkGpuPercent).Value, 0.001);
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State);
end;

procedure TGpuCollectorTests.Compute_OnlyComputeAndCudaEngines;
var
  LResult: TMHCollectionResult;
begin
  FApi.Counters.Engines := [Engine(100, 0, '3d', 70), Engine(200, 3, 'compute_0', 95),
    Engine(200, 4, 'cuda', 40)];
  LResult := FCollector.Collect(Snapshot);
  Assert.AreEqual(95.0, Detail(LResult, 200).GpuCompute.Value, 0.001);
  Assert.AreEqual(95.0, Detail(LResult, 200).Gpu.Value, 0.001);
  Assert.AreEqual(0.0, Detail(LResult, 100).GpuCompute.Value, 0.001, 'Игра грузит 3D, не вычисления');
  Assert.AreEqual(95.0, MetricOf(LResult, mkGpuComputePercent).Value, 0.001);
  Assert.AreEqual(95.0, MetricOf(LResult, mkGpuPercent).Value, 0.001);
end;

procedure TGpuCollectorTests.ProcessWithoutGpuInstances_IsZeroNotNoData;
var
  LResult: TMHCollectionResult;
begin
  FApi.Counters.Engines := [Engine(100, 0, '3d', 5)];
  LResult := FCollector.Collect(Snapshot);
  Assert.IsTrue(Detail(LResult, 300).Gpu.HasValue);
  Assert.AreEqual(0.0, Detail(LResult, 300).Gpu.Value, 0.001);
  Assert.AreEqual(3, Integer(Length(LResult.ProcessDetails)));
end;

procedure TGpuCollectorTests.UnknownPid_IsIgnored;
var
  LResult: TMHCollectionResult;
  LDetail: TMHProcessDetail;
begin
  FApi.Counters.Engines := [Engine(999, 0, 'compute_0', 80)];
  LResult := FCollector.Collect(Snapshot);
  for LDetail in LResult.ProcessDetails do
    Assert.AreNotEqual(Cardinal(999), LDetail.Id.Pid);
  Assert.AreEqual(80.0, MetricOf(LResult, mkGpuComputePercent).Value, 0.001,
    'Загрузка системы учитывает и процессы, которых нет в снимке');
end;

procedure TGpuCollectorTests.Memory_ProcessAndAdapter;
var
  LResult: TMHCollectionResult;
begin
  FApi.Counters.ProcessMemory := [Sample('pid_200_' + ADAPTER, 512 * 1048576.0)];
  FApi.Counters.AdapterMemory := [Sample(ADAPTER, 1800 * 1048576.0),
    Sample('luid_0x00000000_0x00011046_phys_0', 0)];
  LResult := FCollector.Collect(Snapshot);
  Assert.AreEqual(512 * 1048576.0, Detail(LResult, 200).GpuMemory.Value, 1);
  Assert.AreEqual(0.0, Detail(LResult, 100).GpuMemory.Value, 1);
  Assert.AreEqual(1800 * 1048576.0, MetricOf(LResult, mkGpuMemoryBytes).Value, 1);
end;

procedure TGpuCollectorTests.Values_AreClamped;
var
  LResult: TMHCollectionResult;
begin
  FApi.Counters.Engines := [Engine(100, 0, '3d', 70), Engine(200, 0, '3d', 60),
    Engine(300, 1, 'copy', -5)];
  LResult := FCollector.Collect(Snapshot);
  Assert.AreEqual(100.0, MetricOf(LResult, mkGpuPercent).Value, 0.001);
  Assert.AreEqual(0.0, Detail(LResult, 300).Gpu.Value, 0.001);
end;

procedure TGpuCollectorTests.FirstSample_IsPartialNoData;
var
  LResult: TMHCollectionResult;
begin
  FApi.Counters := Default(TMHGpuCounters);
  FApi.Counters.Pending := True;
  FApi.Counters.Reason := 'загрузка будет доступна после следующего замера';
  LResult := FCollector.Collect(Snapshot);
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.IsFalse(MetricOf(LResult, mkGpuPercent).HasValue);
  Assert.AreEqual(0, Integer(Length(LResult.ProcessDetails)));
end;

procedure TGpuCollectorTests.CountersUnavailable_IsUnavailableWithReason;
var
  LResult: TMHCollectionResult;
begin
  FApi.Counters := Default(TMHGpuCounters);
  FApi.Counters.Reason := 'счётчики GPU отсутствуют';
  FApi.SensorReason := 'драйвер не сообщает температуру';
  LResult := FCollector.Collect(Snapshot);
  Assert.AreEqual<TMHSourceState>(ssUnavailable, LResult.Status.State);
  Assert.IsTrue(LResult.Status.Message.Contains('счётчики GPU отсутствуют'));
  Assert.IsTrue(LResult.Status.Message.Contains('температуру'));
  Assert.IsFalse(MetricOf(LResult, mkGpuTemperatureCelsius).HasValue);
end;

procedure TGpuCollectorTests.Temperature_HottestAdapter;
var
  LResult: TMHCollectionResult;
begin
  FApi.Sensors := [Sensor('Intel UHD', 48), Sensor('NVIDIA GeForce', 71.5), Sensor('Basic', 0, False)];
  FApi.Sensors[1].HasSlowdown := True;
  FApi.Sensors[1].SlowdownCelsius := 83;
  LResult := FCollector.Collect(Snapshot);
  Assert.AreEqual(71.5, MetricOf(LResult, mkGpuTemperatureCelsius).Value, 0.001);
  Assert.AreEqual(2, Integer(Length(LResult.Sensors)), 'Датчик без температуры не передаётся');
  Assert.AreEqual<TMHSensorKind>(skGpu, LResult.Sensors[1].Kind);
  Assert.AreEqual('NVIDIA GeForce', LResult.Sensors[1].Device);
  Assert.AreEqual(83.0, LResult.Sensors[1].LimitCelsius, 0.001);
  Assert.AreEqual(0.0, LResult.Sensors[0].LimitCelsius, 0.001, 'Порог неизвестен');
end;

procedure TGpuCollectorTests.Temperature_ImplausibleIgnoredWithReason;
var
  LResult: TMHCollectionResult;
begin
  FApi.Sensors := [Sensor('Broken', 255), Sensor('Zero', 0)];
  FApi.SensorReason := 'NVML: драйвер NVIDIA (nvml.dll) не найден';
  LResult := FCollector.Collect(Snapshot);
  Assert.IsFalse(MetricOf(LResult, mkGpuTemperatureCelsius).HasValue);
  Assert.IsTrue(LResult.Status.Message.Contains('nvml.dll'));
end;

procedure TGpuCollectorTests.NilArguments_Raise;
var
  LClock: IMHClock;
begin
  LClock := TFakeClock.Create(FAKE_NOW);
  Assert.WillRaise(
    procedure
    begin
      TMHGpuCollector.Create(nil, LClock).Free;
    end, EArgumentNilException);
  Assert.WillRaise(
    procedure
    begin
      TMHGpuCollector.Create(FApiIntf, nil).Free;
    end, EArgumentNilException);
end;

{ TSensorCollectorTests }

procedure TSensorCollectorTests.Setup;
begin
  FApi := TFakeSensorApi.Create;
  FApiIntf := FApi;
  FCollector := TMHSensorCollector.Create(FApiIntf, TFakeClock.Create(FAKE_NOW));
end;

procedure TSensorCollectorTests.TearDown;
begin
  FCollector := nil;
  FApiIntf := nil;
  FApi := nil;
end;

function TSensorCollectorTests.Metric(const AResult: TMHCollectionResult;
  AKind: TMHMetricKind): TMHMetric;
begin
  Result := MetricOf(AResult, AKind);
end;

procedure TSensorCollectorTests.Disk_HottestDrive;
var
  LResult: TMHCollectionResult;
begin
  FApi.Disks := [Reading('Samsung SSD 970', 44), Reading('WDC HDD', 38)];
  FApi.Disks[0].HasWarning := True;
  FApi.Disks[0].WarningCelsius := 70;
  LResult := FCollector.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual(44.0, Metric(LResult, mkDiskTemperatureCelsius).Value, 0.001);
  Assert.AreEqual(2, Integer(Length(LResult.Sensors)));
  Assert.AreEqual<TMHSensorKind>(skDisk, LResult.Sensors[0].Kind);
  Assert.AreEqual(70.0, LResult.Sensors[0].LimitCelsius, 0.001);
end;

procedure TSensorCollectorTests.Cpu_PrefersPackageSensor;
var
  LCelsius: Double;
begin
  Assert.IsTrue(MHPickCpuTemperature([Reading('CPU Core #1', 80), Reading('CPU Package', 72)], LCelsius));
  Assert.AreEqual(72.0, LCelsius, 0.001);
  Assert.IsTrue(MHPickCpuTemperature([Reading('Core (Tctl/Tdie)', 65), Reading('CCD1 (Tdie)', 70)], LCelsius));
  Assert.AreEqual(65.0, LCelsius, 0.001);
end;

procedure TSensorCollectorTests.Cpu_WithoutPackage_HottestSensor;
var
  LCelsius: Double;
begin
  Assert.IsTrue(MHPickCpuTemperature([Reading('CPU Core #1', 61), Reading('CPU Core #2', 66)], LCelsius));
  Assert.AreEqual(66.0, LCelsius, 0.001);
  Assert.IsFalse(MHPickCpuTemperature(nil, LCelsius));
end;

procedure TSensorCollectorTests.Nothing_IsUnavailableWithReasons;
var
  LResult: TMHCollectionResult;
begin
  FApi.DiskReason := 'накопители не сообщают температуру';
  FApi.CpuReason := 'запустите LibreHardwareMonitor';
  LResult := FCollector.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual<TMHSourceState>(ssUnavailable, LResult.Status.State);
  Assert.IsTrue(LResult.Status.Message.Contains('не сообщают'));
  Assert.IsTrue(LResult.Status.Message.Contains('LibreHardwareMonitor'));
  Assert.IsFalse(Metric(LResult, mkCpuTemperatureCelsius).HasValue);
  Assert.IsFalse(Metric(LResult, mkDiskTemperatureCelsius).HasValue);
end;

procedure TSensorCollectorTests.OnlyDisk_IsPartial;
var
  LResult: TMHCollectionResult;
begin
  FApi.Disks := [Reading('NVMe', 50)];
  LResult := FCollector.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  FApi.Cpu := [Reading('CPU Package', 60)];
  Assert.AreEqual<TMHSourceState>(ssSuccess, FCollector.Collect(TMHSnapshot.Create(2, FAKE_NOW)).Status.State);
end;

procedure TSensorCollectorTests.ImplausibleValues_Ignored;
var
  LResult: TMHCollectionResult;
begin
  FApi.Disks := [Reading('Broken', 255), Reading('Zero', 0), Reading('Ok', 41)];
  FApi.Cpu := [Reading('CPU Package', -1)];
  LResult := FCollector.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual(41.0, Metric(LResult, mkDiskTemperatureCelsius).Value, 0.001);
  Assert.IsFalse(Metric(LResult, mkCpuTemperatureCelsius).HasValue);
end;

initialization
  TDUnitX.RegisterTestFixture(TGpuCollectorTests);
  TDUnitX.RegisterTestFixture(TSensorCollectorTests);

end.
