unit MineHunter.Tests.Devices;

{
  Устройства по отдельности: сетевые адаптеры (фильтрация служебных, скорость
  по разнице счётчиков, раскладка MIB_IF_ROW2, настоящие адаптеры машины) и
  видеокарты (загрузка, видеопамять, имя, температура и мощность по адаптеру).
}

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Collectors.NetAdapters;

type
  TFakeNetApi = class(TInterfacedObject, IMHNetAdapterApi)
  public
    Adapters: TArray<TMHRawNetAdapter>;
    Fails: Boolean;
    function ReadAdapters(out AAdapters: TArray<TMHRawNetAdapter>; out AError: string): Boolean;
  end;

  [TestFixture]
  [Category('Unit')]
  TNetAdapterTests = class
  public
    [Test] procedure MibIfRow2_HasSdkSize;
    [Test] procedure Filtering_KindsAndRates;
    [Test] procedure Failure_Error;
    [Test] procedure Formatting;
  end;

  [TestFixture]
  [Category('Unit')]
  TGpuAdapterTests = class
  public
    [Test] procedure PerAdapter_LoadMemoryNameTemperaturePower;
  end;

  [TestFixture]
  [Category('Integration')]
  TNetAdapterIntegrationTests = class
  public
    [Test] procedure RealAdapters_AreRead;
  end;

function Raw(AIndex: Cardinal; const AAlias: string; AIfType: Cardinal; AHardware, AUp: Boolean;
  AIn, AOut: UInt64; AFilter: Boolean = False): TMHRawNetAdapter;

implementation

uses
  MineHunter.Core.Interfaces, MineHunter.Collectors.NetAdapters.WinApi, MineHunter.Collectors.Gpu,
  MineHunter.Tests.Fakes, MineHunter.Tests.GpuSensors;

function Raw(AIndex: Cardinal; const AAlias: string; AIfType: Cardinal; AHardware, AUp: Boolean;
  AIn, AOut: UInt64; AFilter: Boolean): TMHRawNetAdapter;
begin
  Result := Default(TMHRawNetAdapter);
  Result.Index := AIndex;
  Result.Alias := AAlias;
  Result.Description := AAlias + ' device';
  Result.IfType := AIfType;
  Result.Hardware := AHardware;
  Result.FilterInterface := AFilter;
  if AUp then
    Result.OperStatus := 1
  else
    Result.OperStatus := 2;
  Result.LinkSpeedBps := 1000000000;
  Result.InOctets := AIn;
  Result.OutOctets := AOut;
end;

{ TFakeNetApi }

function TFakeNetApi.ReadAdapters(out AAdapters: TArray<TMHRawNetAdapter>; out AError: string): Boolean;
begin
  AAdapters := Adapters;
  AError := 'сбой';
  Result := not Fails;
end;

{ TNetAdapterTests }

procedure TNetAdapterTests.MibIfRow2_HasSdkSize;
begin
  Assert.AreEqual(1352, SizeOf(TMibIfRow2), 'Раскладка MIB_IF_ROW2 для x64 по netioapi.h');
end;

procedure TNetAdapterTests.Filtering_KindsAndRates;
var
  LApi: TFakeNetApi;
  LClock: TFakeClock;
  LIntf: IMHCollector;
  LResult: TMHCollectionResult;
  LNames: string;
  LInfo: TMHNetAdapterInfo;
begin
  LApi := TFakeNetApi.Create;
  LClock := TFakeClock.Create(FAKE_NOW);
  LIntf := TMHNetAdapterCollector.Create(LApi, LClock);
  LApi.Adapters := [Raw(5, 'Ethernet', 6, True, True, 1000, 2000),
    Raw(6, 'Wi-Fi', 71, True, False, 0, 0),
    Raw(7, 'Ethernet-WFP', 6, True, True, 1000, 2000, True),    // фильтр — копия адаптера
    Raw(1, 'Loopback', 24, False, True, 0, 0),
    Raw(9, 'VPN', 53, False, True, 500, 700),
    Raw(11, 'WAN Miniport (IP)', 6, False, True, 0, 0),           // ни байта — служебный
    Raw(10, 'Hyper-V off', 6, False, False, 0, 0)];
  LResult := LIntf.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual(Ord(ssSuccess), Ord(LResult.Status.State));
  LNames := '';
  for LInfo in LResult.NetAdapters do
    LNames := LNames + LInfo.Name + ';';
  Assert.AreEqual('Ethernet;VPN;Wi-Fi;', LNames, 'Подключённые физические первыми, служебные отброшены');
  Assert.IsFalse(LResult.NetAdapters[0].HasRate, 'Скорость — со второго опроса');
  Assert.AreEqual(Ord(nkEthernet), Ord(LResult.NetAdapters[0].Kind));
  Assert.AreEqual(Ord(nkVirtual), Ord(LResult.NetAdapters[1].Kind));
  Assert.AreEqual(Ord(nkWifi), Ord(LResult.NetAdapters[2].Kind));
  Assert.AreEqual<UInt64>(0, LResult.NetAdapters[2].LinkSpeedBps, 'Не подключён — скорость канала не показывается');

  LClock.AdvanceMs(2000);
  LApi.Adapters[0].InOctets := 1000 + 4 * 1024 * 1024;
  LApi.Adapters[0].OutOctets := 2000 + 2 * 1024 * 1024;
  LResult := LIntf.Collect(TMHSnapshot.Create(2, FAKE_NOW));
  Assert.IsTrue(LResult.NetAdapters[0].HasRate);
  Assert.AreEqual(2.0 * 1024 * 1024, LResult.NetAdapters[0].ReceiveBytesPerSec, 1);
  Assert.AreEqual(1.0 * 1024 * 1024, LResult.NetAdapters[0].SendBytesPerSec, 1);
  // Счётчик сбросился (переподключение) — скорость не выдумывается.
  LClock.AdvanceMs(2000);
  LApi.Adapters[0].InOctets := 10;
  Assert.IsFalse(LIntf.Collect(TMHSnapshot.Create(3, FAKE_NOW)).NetAdapters[0].HasRate);
end;

procedure TNetAdapterTests.Failure_Error;
var
  LApi: TFakeNetApi;
  LIntf: IMHCollector;
begin
  LApi := TFakeNetApi.Create;
  LApi.Fails := True;
  LIntf := TMHNetAdapterCollector.Create(LApi, TFakeClock.Create(FAKE_NOW));
  Assert.AreEqual(Ord(ssError), Ord(LIntf.Collect(TMHSnapshot.Create(1, FAKE_NOW)).Status.State));
  Assert.WillRaise(
    procedure
    begin
      TMHNetAdapterCollector.Create(nil, TFakeClock.Create(FAKE_NOW)).Free;
    end, EArgumentNilException);
end;

procedure TNetAdapterTests.Formatting;
begin
  Assert.AreEqual('1 Гбит/с', MHFormatLinkSpeed(1000000000));
  Assert.AreEqual('100 Мбит/с', MHFormatLinkSpeed(100000000));
  Assert.AreEqual('', MHFormatLinkSpeed(0));
  // Скорость сети — в битах в секунду с десятичными приставками, как в диспетчере задач:
  // 19 КБ/с = 156 кбит/с (на снимке клиента: 20 КБ/с у нас и 152 кбит/с в диспетчере).
  Assert.AreEqual('156 кбит/с', MHFormatBitRate(19 * 1024));
  Assert.AreEqual('8' + FormatSettings.DecimalSeparator + '0 кбит/с', MHFormatBitRate(1000));
  Assert.AreEqual('0 кбит/с', MHFormatBitRate(0), 'Как в диспетчере задач');
  Assert.AreEqual('0 кбит/с', MHFormatBitRate(-5), 'Отрицательное — ноль');
  Assert.AreEqual('0' + FormatSettings.DecimalSeparator + '1 кбит/с', MHFormatBitRate(12));
  Assert.AreEqual('10 кбит/с', MHFormatBitRate(1250));
  Assert.AreEqual('1' + FormatSettings.DecimalSeparator + '2 Мбит/с', MHFormatBitRate(150000));
  Assert.AreEqual('1' + FormatSettings.DecimalSeparator + '60 Гбит/с', MHFormatBitRate(200E6));
  Assert.AreEqual(Ord(nkMobile), Ord(MHNetAdapterKindOf(243, True)));
  Assert.AreEqual(Ord(nkOther), Ord(MHNetAdapterKindOf(1, True)));
end;

{ TGpuAdapterTests }

function Sample(const AName: string; AValue: Double): TMHGpuCounterSample;
begin
  Result.InstanceName := AName;
  Result.Value := AValue;
end;

procedure TGpuAdapterTests.PerAdapter_LoadMemoryNameTemperaturePower;
const
  NV = 'luid_0x00000000_0x000102C2_phys_0';
  IGPU = 'luid_0x00000000_0x0000E3E8_phys_0';
var
  LGpu: TFakeGpuApi;
  LIntf: IMHCollector;
  LResult: TMHCollectionResult;
  LSensor: TMHGpuSensor;
  LNv, LIgpu: TMHGpuAdapterInfo;
  LInfo: TMHGpuAdapterInfo;
begin
  LGpu := TFakeGpuApi.Create;
  LGpu.Counters.Available := True;
  LGpu.Counters.Engines := [Sample('pid_200_' + NV + '_eng_0_engtype_3D', 30),
    Sample('pid_300_' + NV + '_eng_0_engtype_3D', 25),          // сумма по процессам на движке — 55
    Sample('pid_400_' + NV + '_eng_2_engtype_Compute_0', 40),
    Sample('pid_500_' + IGPU + '_eng_0_engtype_VideoDecode', 12)];
  LGpu.Counters.AdapterMemory := [Sample(NV, 2 * 1024 * 1024 * 1024.0), Sample(IGPU, 256 * 1024 * 1024.0),
    Sample('luid_0x00000000_0x0000AAAA_phys_0', 0)];                // пустой безымянный — скрыт
  LSensor := Default(TMHGpuSensor);
  LSensor.AdapterName := 'NVIDIA GeForce GTX 1660 Ti';
  LSensor.Adapter := NV.ToLower;
  LSensor.Source := 'D3DKMT';
  LSensor.HasTemperature := True;
  LSensor.TemperatureCelsius := 61;
  LGpu.Sensors := [LSensor];
  LSensor := Default(TMHGpuSensor);
  LSensor.AdapterName := 'NVIDIA GeForce GTX 1660 Ti';
  LSensor.Source := 'NVML';
  LSensor.HasPower := True;
  LSensor.PowerWatts := 95;
  LGpu.Sensors := LGpu.Sensors + [LSensor];
  LIntf := TMHGpuCollector.Create(LGpu, TFakeClock.Create(FAKE_NOW));
  LResult := LIntf.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual(2, Integer(Length(LResult.GpuAdapters)));
  for LInfo in LResult.GpuAdapters do
    if SameText(LInfo.Key, NV) then
      LNv := LInfo
    else
      LIgpu := LInfo;
  Assert.AreEqual('NVIDIA GeForce GTX 1660 Ti', LNv.Name);
  Assert.AreEqual(55.0, LNv.LoadPercent, 0.01, 'Самый загруженный движок, сумма по процессам');
  Assert.AreEqual(40.0, LNv.ComputePercent, 0.01);
  Assert.AreEqual(2.0 * 1024 * 1024 * 1024, LNv.MemoryBytes, 1);
  Assert.IsTrue(LNv.HasTemperature);
  Assert.AreEqual(61.0, LNv.TemperatureCelsius, 0.01);
  Assert.IsTrue(LNv.HasPower, 'Мощность NVML — по имени адаптера');
  Assert.AreEqual(95.0, LNv.PowerWatts, 0.01);
  Assert.AreEqual(12.0, LIgpu.LoadPercent, 0.01);
  Assert.IsTrue(LIgpu.Name.Contains('1'), 'Без датчика — «Видеокарта N»: ' + LIgpu.Name);
  Assert.IsFalse(LIgpu.HasPower);
end;

{ TNetAdapterIntegrationTests }

procedure TNetAdapterIntegrationTests.RealAdapters_AreRead;
var
  LApi: IMHNetAdapterApi;
  LRaw: TArray<TMHRawNetAdapter>;
  LError: string;
  LItem: TMHRawNetAdapter;
  LLoopback: Boolean;
begin
  LApi := TMHWinNetAdapterApi.Create;
  Assert.IsTrue(LApi.ReadAdapters(LRaw, LError), LError);
  Assert.IsTrue(Length(LRaw) >= 1);
  LLoopback := False;
  for LItem in LRaw do
  begin
    Assert.IsNotEmpty(LItem.Alias + LItem.Description, 'Имя прочитано (раскладка структуры верна)');
    if LItem.IfType = 24 then
      LLoopback := True;
  end;
  Assert.IsTrue(LLoopback, 'Loopback есть на любой машине — тип читается по верному смещению');
end;

initialization
  TDUnitX.RegisterTestFixture(TNetAdapterTests);
  TDUnitX.RegisterTestFixture(TGpuAdapterTests);
  TDUnitX.RegisterTestFixture(TNetAdapterIntegrationTests);

end.
