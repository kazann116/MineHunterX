unit MineHunter.Tests.Disks;

{
  Диски: разбор имён экземпляров счётчиков, сведение данных коллектора
  (поддельный IMHDiskApi), кэширование, отказы источников и интеграционная
  проверка настоящих дисков машины.
}

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Collectors.Disks,
  MineHunter.Collectors.DiskHealth, MineHunter.Tests.Fakes;

type
  TFakeDiskApi = class(TInterfacedObject, IMHDiskApi)
  public
    Disks: TArray<TMHRawDisk>;
    DisksOk: Boolean;
    Reliability: TArray<TMHRawReliability>;
    ReliabilityOk: Boolean;
    ReliabilityDenied: Boolean;
    Volumes: TArray<TMHVolumeInfo>;
    VolumesOk: Boolean;
    Counters: TArray<TMHRawDiskCounter>;
    CountersOk: Boolean;
    DiskReads: Integer;
    /// Атрибуты здоровья по номеру диска; номер в HealthDenied — нет прав.
    Health: TArray<TMHDiskHealthData>;
    HealthNumbers: TArray<Integer>;
    HealthDenied: TArray<Integer>;
    HealthReads: Integer;
    constructor Create;
    function ReadDisks(out ADisks: TArray<TMHRawDisk>; out AError: string): Boolean;
    function ReadReliability(out AItems: TArray<TMHRawReliability>; out AError: string;
      out AAccessDenied: Boolean): Boolean;
    function ReadVolumes(out AVolumes: TArray<TMHVolumeInfo>; out AError: string): Boolean;
    function ReadCounters(out ACounters: TArray<TMHRawDiskCounter>; out AError: string): Boolean;
    function ReadHealth(ANumber: Integer; const ABus: string; out AData: TMHDiskHealthData;
      out AError: string; out AAccessDenied: Boolean): Boolean;
  end;

  [TestFixture]
  [Category('Unit')]
  TDiskCollectorTests = class
  public
    [Test] procedure ParseInstance;
    [Test] procedure Collect_MergesAllSources;
    [Test] procedure TemperatureFallback_FromSensors;
    [Test] procedure Cache_DisksReadRarely_InvalidateForcesReread;
    [Test] procedure WmiFailure_KeepsPreviousAndUsesCounters;
    [Test] procedure ReliabilityDenied_RequiresElevation;
    [Test] procedure Health_FillsGapsKeepsReliabilityAndRefreshes;
    [Test] procedure Health_SmartDenied_Note;
    [Test] procedure NothingAvailable_Unavailable;
    [Test] procedure VolumeFreePercent;
  end;

  [TestFixture]
  [Category('Unit')]
  TDiskAnalysisTests = class
  public
    [Test] procedure SpaceLevels;
    [Test] procedure LowSpace_Findings;
    [Test] procedure Health_WearErrors_Findings;
    [Test] procedure HealthyDisk_NoFinding;
    [Test] procedure Health_BadSectorsAndNvmeCritical_Findings;
    [Test] procedure ExplainLoad_BusiestDiskTopIoAndSpace;
    [Test] procedure ProcessIo_RateFromCounters;
    [Test] procedure TopIo_OrderAndThreshold;
  end;

  [TestFixture]
  [Category('Integration')]
  TDiskIntegrationTests = class
  public
    [Test] procedure RealDisks_AreDetected;
  end;

/// Набор: диск 0 — HDD с C:, D:; диск 1 — NVMe SSD с E:.
function FakeDiskSet: TFakeDiskApi;

implementation

uses
  System.DateUtils, MineHunter.Collectors.Disks.WinApi, MineHunter.Analysis.Disks, MineHunter.Analysis.Engine,
  MineHunter.Collectors.Processes, MineHunter.Tests.FakeProcessApi;

function Volume(const AName: string; ATotalGb, AFreeGb: Double; const ADisks: TArray<Integer>;
  ASystem: Boolean = False): TMHVolumeInfo;
begin
  Result := Default(TMHVolumeInfo);
  Result.Name := AName;
  Result.FileSystem := 'NTFS';
  Result.TotalBytes := Round(ATotalGb * 1024 * 1024 * 1024);
  Result.FreeBytes := Round(AFreeGb * 1024 * 1024 * 1024);
  Result.DiskNumbers := ADisks;
  Result.IsSystem := ASystem;
end;

function FakeDiskSet: TFakeDiskApi;
var
  LDisk: TMHRawDisk;
  LRel: TMHRawReliability;
  LCounter: TMHRawDiskCounter;
begin
  Result := TFakeDiskApi.Create;
  LDisk := Default(TMHRawDisk);
  LDisk.Number := 0;
  LDisk.Model := 'ST2000DM008';
  LDisk.Media := dmHdd;
  LDisk.Bus := 'SATA';
  LDisk.SizeBytes := 2000398934016;
  LDisk.Health := dhHealthy;
  Result.Disks := [LDisk];
  LDisk.Number := 1;
  LDisk.Model := 'KINGSTON SNV2S500G';
  LDisk.Media := dmSsd;
  LDisk.Bus := 'NVMe';
  LDisk.SizeBytes := 500107862016;
  Result.Disks := Result.Disks + [LDisk];

  LRel := Default(TMHRawReliability);
  LRel.Number := 1;
  LRel.HasTemperature := True;
  LRel.Temperature := 48;
  LRel.TemperatureMax := 83;
  LRel.HasWear := True;
  LRel.Wear := 7;
  LRel.HasErrors := True;
  LRel.PowerOnHours := 1200;
  Result.Reliability := [LRel];

  Result.Volumes := [Volume('C:', 465, 62, [0], True), Volume('D:', 1400, 1200, []), Volume('E:', 465, 10, [1])];

  LCounter := Default(TMHRawDiskCounter);
  LCounter.Number := 0;
  LCounter.Letters := 'C: D:';
  LCounter.ActivePercent := 35;
  LCounter.ReadBytesPerSec := 1000;
  LCounter.WriteBytesPerSec := 2000;
  Result.Counters := [LCounter];
  LCounter.Number := 1;
  LCounter.Letters := 'E:';
  LCounter.ActivePercent := 120; // некорректное значение счётчика обрезается
  Result.Counters := Result.Counters + [LCounter];
end;

{ TFakeDiskApi }

constructor TFakeDiskApi.Create;
begin
  inherited Create;
  DisksOk := True;
  ReliabilityOk := True;
  VolumesOk := True;
  CountersOk := True;
end;

function TFakeDiskApi.ReadDisks(out ADisks: TArray<TMHRawDisk>; out AError: string): Boolean;
begin
  Inc(DiskReads);
  ADisks := Disks;
  AError := 'WMI недоступен';
  Result := DisksOk;
end;

function TFakeDiskApi.ReadReliability(out AItems: TArray<TMHRawReliability>; out AError: string;
  out AAccessDenied: Boolean): Boolean;
begin
  AItems := Reliability;
  AError := 'нужны права администратора';
  AAccessDenied := ReliabilityDenied;
  Result := ReliabilityOk;
end;

function TFakeDiskApi.ReadVolumes(out AVolumes: TArray<TMHVolumeInfo>; out AError: string): Boolean;
begin
  AVolumes := Volumes;
  AError := 'ошибка разделов';
  Result := VolumesOk;
end;

function TFakeDiskApi.ReadHealth(ANumber: Integer; const ABus: string; out AData: TMHDiskHealthData;
  out AError: string; out AAccessDenied: Boolean): Boolean;
var
  I: Integer;
begin
  Inc(HealthReads);
  AError := '';
  AAccessDenied := False;
  AData := TMHDiskHealthData.Create('');
  for I in HealthDenied do
    if I = ANumber then
    begin
      AAccessDenied := True;
      AError := 'Отказано в доступе';
      Exit(False);
    end;
  for I := 0 to High(HealthNumbers) do
    if HealthNumbers[I] = ANumber then
    begin
      AData := Health[I];
      Exit(True);
    end;
  Result := False;
end;

function TFakeDiskApi.ReadCounters(out ACounters: TArray<TMHRawDiskCounter>; out AError: string): Boolean;
begin
  ACounters := Counters;
  AError := 'счётчики недоступны';
  Result := CountersOk;
end;

function Collector(AApi: TFakeDiskApi): IMHCollector;
begin
  Result := TMHDiskCollector.Create(AApi, TFakeClock.Create(FAKE_NOW));
end;

function FindDisk(const AResult: TMHCollectionResult; ANumber: Integer): TMHDiskInfo;
var
  LDisk: TMHDiskInfo;
begin
  for LDisk in AResult.Disks do
    if LDisk.Number = ANumber then
      Exit(LDisk);
  raise Exception.CreateFmt('Диск %d не найден', [ANumber]);
end;

{ TDiskCollectorTests }

procedure TDiskCollectorTests.ParseInstance;
var
  LNumber: Integer;
  LLetters: string;
begin
  Assert.IsTrue(MHParseDiskInstance('1 f: h: i:', LNumber, LLetters));
  Assert.AreEqual(1, LNumber);
  Assert.AreEqual('F: H: I:', LLetters);
  Assert.IsTrue(MHParseDiskInstance('4 c:', LNumber, LLetters));
  Assert.AreEqual('C:', LLetters);
  Assert.IsTrue(MHParseDiskInstance('2', LNumber, LLetters), 'Диск без разделов с буквами');
  Assert.AreEqual('', LLetters);
  Assert.IsFalse(MHParseDiskInstance('_Total', LNumber, LLetters));
  Assert.IsFalse(MHParseDiskInstance('', LNumber, LLetters));
  Assert.IsFalse(MHParseDiskInstance('-1 c:', LNumber, LLetters));
  Assert.AreEqual('NVMe', MHBusTypeName(17));
  Assert.AreEqual('SATA', MHBusTypeName(11));
  Assert.AreEqual('', MHBusTypeName(999));
end;

procedure TDiskCollectorTests.Collect_MergesAllSources;
var
  LResult: TMHCollectionResult;
  LDisk: TMHDiskInfo;
  LVolume: TMHVolumeInfo;
begin
  LResult := Collector(FakeDiskSet).Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual(Ord(ssSuccess), Ord(LResult.Status.State), LResult.Status.Message);
  Assert.AreEqual(2, Integer(Length(LResult.Disks)));
  Assert.AreEqual(2, LResult.Status.ItemCount);

  LDisk := FindDisk(LResult, 0);
  Assert.AreEqual('ST2000DM008', LDisk.Model);
  Assert.AreEqual(Ord(dmHdd), Ord(LDisk.Media));
  Assert.IsTrue(LDisk.HasActivity);
  Assert.AreEqual(35.0, LDisk.ActivePercent, 0.001);
  Assert.AreEqual(2000.0, LDisk.WriteBytesPerSec, 0.001);
  Assert.AreEqual('C: D:', LDisk.Volumes, 'D: без сведений о расположении — по имени счётчика');
  Assert.IsFalse(LDisk.HasWear);
  Assert.AreEqual<Int64>(-1, LDisk.PowerOnHours);

  LDisk := FindDisk(LResult, 1);
  Assert.AreEqual('NVMe', LDisk.Bus);
  Assert.AreEqual(100.0, LDisk.ActivePercent, 0.001, 'Занятость ограничена 100%');
  Assert.IsTrue(LDisk.HasTemperature);
  Assert.AreEqual(48.0, LDisk.TemperatureCelsius, 0.001);
  Assert.AreEqual(83.0, LDisk.TemperatureLimitCelsius, 0.001);
  Assert.IsTrue(LDisk.HasWear);
  Assert.AreEqual(7.0, LDisk.WearPercent, 0.001);
  Assert.AreEqual<Int64>(1200, LDisk.PowerOnHours);
  Assert.AreEqual('E:', LDisk.Volumes);

  Assert.AreEqual(3, Integer(Length(LResult.Volumes)));
  for LVolume in LResult.Volumes do
    if LVolume.Name = 'D:' then
      Assert.AreEqual(0, LVolume.DiskNumbers[0], 'Номер диска восстановлен по счётчику');
end;

procedure TDiskCollectorTests.TemperatureFallback_FromSensors;
var
  LSnapshot: TMHSnapshot;
  LDisk: TMHDiskInfo;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Sensors := [TMHSensorReading.Create(skDisk, 'ST2000DM008', 'storage', 41, 60),
    TMHSensorReading.Create(skDisk, 'KINGSTON SNV2S500G', 'storage', 50, 70),
    TMHSensorReading.Create(skGpu, 'ST2000DM008', 'NVML', 90, 83)];
  LDisk := FindDisk(Collector(FakeDiskSet).Collect(LSnapshot), 0);
  Assert.IsTrue(LDisk.HasTemperature, 'Температура из коллектора датчиков по модели');
  Assert.AreEqual(41.0, LDisk.TemperatureCelsius, 0.001);
  Assert.AreEqual(60.0, LDisk.TemperatureLimitCelsius, 0.001);
  LDisk := FindDisk(Collector(FakeDiskSet).Collect(LSnapshot), 1);
  Assert.AreEqual(48.0, LDisk.TemperatureCelsius, 0.001, 'Счётчики надёжности приоритетнее');
  Assert.AreEqual(70.0, LDisk.TemperatureLimitCelsius, 0.001, 'Порог датчика — порог производителя');
end;

procedure TDiskCollectorTests.Cache_DisksReadRarely_InvalidateForcesReread;
var
  LApi: TFakeDiskApi;
  LIntf: IMHCollector;
begin
  LApi := FakeDiskSet;
  LIntf := TMHDiskCollector.Create(LApi, TFakeClock.Create(FAKE_NOW));
  LIntf.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  LIntf.Collect(TMHSnapshot.Create(2, IncSecond(FAKE_NOW, 30)));
  LIntf.Collect(TMHSnapshot.Create(3, IncMinute(FAKE_NOW, 9)));
  Assert.AreEqual(1, LApi.DiskReads, 'Список дисков — раз в 10 минут');
  LIntf.Collect(TMHSnapshot.Create(4, IncMinute(FAKE_NOW, 11)));
  Assert.AreEqual(2, LApi.DiskReads);
  (LIntf as IMHCacheInvalidation).Invalidate;
  LIntf.Collect(TMHSnapshot.Create(5, IncMinute(FAKE_NOW, 12)));
  Assert.AreEqual(3, LApi.DiskReads, '«Проверить сейчас» перечитывает сразу');
end;

function NvmeHealth(AHours, ACycles: Int64; AMediaErrors: Int64 = 0): TMHDiskHealthData;
begin
  Result := TMHDiskHealthData.Create(MH_HEALTH_SOURCE_NVME);
  Result.Attributes := [Default(TMHDiskAttribute)];
  Result.Attributes[0].Id := 12;
  Result.Attributes[0].Raw := AHours;
  Result.PowerOnHours := AHours;
  Result.PowerCycles := ACycles;
  Result.UnsafeShutdowns := 3;
  Result.MediaErrors := AMediaErrors;
  Result.HasTemperature := True;
  Result.TemperatureCelsius := 33;
  Result.HasWear := True;
  Result.WearPercent := 4;
  Result.TotalWrittenBytes := 1E12;
  Result.CriticalWarning := 0;
end;

function SmartHealth: TMHDiskHealthData;
begin
  Result := TMHDiskHealthData.Create(MH_HEALTH_SOURCE_SMART);
  Result.Attributes := [Default(TMHDiskAttribute)];
  Result.Attributes[0].Id := $C5;
  Result.Attributes[0].Raw := 8;
  Result.PowerOnHours := 25005;
  Result.PendingSectors := 8;
  Result.UncorrectableSectors := 8;
  Result.ReallocatedSectors := 0;
end;

procedure TDiskCollectorTests.Health_FillsGapsKeepsReliabilityAndRefreshes;
var
  LApi: TFakeDiskApi;
  LIntf: IMHCollector;
  LResult: TMHCollectionResult;
begin
  LApi := FakeDiskSet;
  // Диск 0 (SATA) — без счётчиков надёжности, SMART заполняет; диск 1 (NVMe) — счётчики есть.
  LApi.HealthNumbers := [0, 1];
  LApi.Health := [SmartHealth, NvmeHealth(1748, 266)];
  LIntf := TMHDiskCollector.Create(LApi, TFakeClock.Create(FAKE_NOW));
  LResult := LIntf.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual(2, LApi.HealthReads, 'Опрошены оба диска');
  Assert.AreEqual(MH_HEALTH_SOURCE_SMART, LResult.Disks[0].AttributesSource);
  Assert.AreEqual<Int64>(25005, LResult.Disks[0].PowerOnHours, 'Наработка из SMART, когда счётчиков нет');
  Assert.AreEqual<Int64>(8, LResult.Disks[0].PendingSectors);
  Assert.AreEqual(MH_HEALTH_SOURCE_NVME, LResult.Disks[1].AttributesSource);
  Assert.AreEqual(1, Integer(Length(LResult.Disks[1].Attributes)));
  Assert.AreEqual<Int64>(1200, LResult.Disks[1].PowerOnHours, 'Счётчики надёжности Windows — основной источник');
  Assert.AreEqual(48.0, LResult.Disks[1].TemperatureCelsius, 0.01);
  Assert.AreEqual(7.0, LResult.Disks[1].WearPercent, 0.01);
  Assert.AreEqual<Int64>(266, LResult.Disks[1].PowerCycles);
  Assert.AreEqual<Int64>(3, LResult.Disks[1].UnsafeShutdowns);
  Assert.AreEqual(Ord(ssSuccess), Ord(LResult.Status.State));

  // Без счётчиков надёжности ошибки носителя NVMe становятся ошибками чтения.
  LApi.Reliability := nil;
  LApi.Health := [SmartHealth, NvmeHealth(1749, 266, 5)];
  LResult := LIntf.Collect(TMHSnapshot.Create(2, IncSecond(FAKE_NOW, 30)));
  Assert.AreEqual(2, LApi.HealthReads, 'Через 30 с журнал не перечитывается');
  LResult := LIntf.Collect(TMHSnapshot.Create(3, IncSecond(FAKE_NOW, 61)));
  Assert.AreEqual(3, LApi.HealthReads, 'NVMe — раз в минуту, SMART SATA — реже');
  LResult := LIntf.Collect(TMHSnapshot.Create(4, IncMinute(FAKE_NOW, 11)));
  Assert.AreEqual(5, LApi.HealthReads, 'Через 10 минут перечитаны оба');
  Assert.AreEqual<Int64>(1749, LResult.Disks[1].PowerOnHours);
  Assert.IsTrue(LResult.Disks[1].HasErrors);
  Assert.AreEqual<Int64>(5, LResult.Disks[1].ReadErrors);
  Assert.AreEqual(33.0, LResult.Disks[1].TemperatureCelsius, 0.01);

  // Диск перестал отвечать — старые атрибуты не показываются.
  LApi.HealthNumbers := [0];
  LApi.Health := [SmartHealth];
  (LIntf as IMHCacheInvalidation).Invalidate;
  LResult := LIntf.Collect(TMHSnapshot.Create(5, IncMinute(FAKE_NOW, 12)));
  Assert.AreEqual('', LResult.Disks[1].AttributesSource);
  Assert.AreEqual(0, Integer(Length(LResult.Disks[1].Attributes)));
end;

procedure TDiskCollectorTests.Health_SmartDenied_Note;
var
  LApi: TFakeDiskApi;
  LResult: TMHCollectionResult;
begin
  LApi := FakeDiskSet;
  LApi.HealthDenied := [0];
  LResult := TMHDiskCollector.Create(LApi, TFakeClock.Create(FAKE_NOW)).Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual(Ord(ssPartial), Ord(LResult.Status.State));
  Assert.IsTrue(LResult.Status.RequiresElevation);
  Assert.IsTrue(LResult.Status.Message.Contains('SMART'), LResult.Status.Message);
end;

procedure TDiskCollectorTests.WmiFailure_KeepsPreviousAndUsesCounters;
var
  LApi: TFakeDiskApi;
  LIntf: IMHCollector;
  LResult: TMHCollectionResult;
begin
  LApi := FakeDiskSet;
  LIntf := TMHDiskCollector.Create(LApi, TFakeClock.Create(FAKE_NOW));
  LIntf.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  LApi.DisksOk := False;
  LApi.Disks := nil;
  LResult := LIntf.Collect(TMHSnapshot.Create(2, IncMinute(FAKE_NOW, 11)));
  Assert.AreEqual(Ord(ssPartial), Ord(LResult.Status.State));
  Assert.IsTrue(LResult.Status.Message.Contains('WMI недоступен'));
  Assert.AreEqual('ST2000DM008', FindDisk(LResult, 0).Model, 'Прежний список сохраняется');

  // Первый запуск без WMI: диски строятся по счётчикам нагрузки.
  LApi := FakeDiskSet;
  LApi.DisksOk := False;
  LApi.Disks := nil;
  LResult := Collector(LApi).Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual(2, Integer(Length(LResult.Disks)));
  Assert.IsTrue(FindDisk(LResult, 1).Model.Contains('1'));
  Assert.IsTrue(FindDisk(LResult, 1).HasActivity);
end;

procedure TDiskCollectorTests.ReliabilityDenied_RequiresElevation;
var
  LApi: TFakeDiskApi;
  LResult: TMHCollectionResult;
begin
  LApi := FakeDiskSet;
  LApi.ReliabilityOk := False;
  LApi.ReliabilityDenied := True;
  LApi.Reliability := nil;
  LResult := Collector(LApi).Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.AreEqual(Ord(ssPartial), Ord(LResult.Status.State));
  Assert.IsTrue(LResult.Status.RequiresElevation);
  Assert.IsTrue(LResult.Status.Message.Contains('администратора'));
  Assert.IsFalse(FindDisk(LResult, 1).HasWear);
  Assert.AreEqual(2, Integer(Length(LResult.Disks)), 'Остальные сведения на месте');
end;

procedure TDiskCollectorTests.NothingAvailable_Unavailable;
var
  LApi: TFakeDiskApi;
begin
  LApi := TFakeDiskApi.Create;
  LApi.CountersOk := False;
  Assert.AreEqual(Ord(ssUnavailable), Ord(Collector(LApi).Collect(TMHSnapshot.Create(1, FAKE_NOW)).Status.State));
  Assert.WillRaise(
    procedure
    begin
      TMHDiskCollector.Create(nil, TFakeClock.Create(FAKE_NOW)).Free;
    end, EArgumentNilException);
end;

procedure TDiskCollectorTests.VolumeFreePercent;
begin
  Assert.AreEqual(50.0, Volume('X:', 100, 50, []).FreePercent, 0.001);
  Assert.AreEqual(0.0, Volume('X:', 0, 0, []).FreePercent, 0.001, 'Пустой раздел — без деления на ноль');
end;

{ TDiskAnalysisTests }

function DiskWith(ANumber: Integer; AHealth: TMHDiskHealth; AWear: Double; AReadErrors: Int64): TMHDiskInfo;
begin
  Result := TMHDiskInfo.Create(ANumber, 'Model' + IntToStr(ANumber));
  Result.Health := AHealth;
  if AWear >= 0 then
  begin
    Result.HasWear := True;
    Result.WearPercent := AWear;
  end;
  if AReadErrors >= 0 then
  begin
    Result.HasErrors := True;
    Result.ReadErrors := AReadErrors;
  end;
end;

function FindByKey(const AFindings: TMHFindings; const AKey: string; out AFinding: TMHFinding): Boolean;
var
  LFinding: TMHFinding;
begin
  for LFinding in AFindings do
    if LFinding.Key = AKey then
    begin
      AFinding := LFinding;
      Exit(True);
    end;
  Result := False;
end;

procedure TDiskAnalysisTests.SpaceLevels;
var
  LVolume: TMHVolumeInfo;
begin
  Assert.AreEqual(Ord(slOk), Ord(MHVolumeSpaceLevel(Volume('D:', 1863, 1597, []))));
  Assert.AreEqual(Ord(slLow), Ord(MHVolumeSpaceLevel(Volume('F:', 146, 10, []))), '6,8% свободно');
  Assert.AreEqual(Ord(slOk), Ord(MHVolumeSpaceLevel(Volume('C:', 465, 62, [], True))), '13% на системном');
  Assert.AreEqual(Ord(slLow), Ord(MHVolumeSpaceLevel(Volume('C:', 60, 8, [], True))),
    'Системному разделу нужно не меньше 10 ГБ');
  Assert.AreEqual(Ord(slOk), Ord(MHVolumeSpaceLevel(Volume('X:', 60, 8, []))), 'Обычному хватает 5 ГБ');
  Assert.AreEqual(Ord(slCritical), Ord(MHVolumeSpaceLevel(Volume('C:', 465, 8, [], True))));
  Assert.AreEqual(Ord(slCritical), Ord(MHVolumeSpaceLevel(Volume('Y:', 100, 1.5, []))), 'Меньше 2 ГБ');
  Assert.AreEqual(Ord(slOk), Ord(MHVolumeSpaceLevel(Volume('Z:', 0.5, 0.01, []))), 'Маленький раздел не оценивается');
  LVolume := Volume('U:', 32, 0.1, []);
  LVolume.Removable := True;
  Assert.AreEqual(Ord(slOk), Ord(MHVolumeSpaceLevel(LVolume)), 'Флешки не оцениваются');
end;

procedure TDiskAnalysisTests.LowSpace_Findings;
var
  LSnapshot: TMHSnapshot;
  LFindings: TMHFindings;
  LFinding, LSystem: TMHFinding;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Volumes := [Volume('C:', 465, 8, [0], True), Volume('D:', 1863, 1597, [0]), Volume('F:', 146, 10, [1])];
  LFindings := MHAnalyzeDisks(LSnapshot, TMHRiskThresholds.Default, 'test');
  Assert.AreEqual(2, Integer(Length(LFindings)));
  Assert.IsTrue(FindByKey(LFindings, 'disk:space:f:', LFinding));
  Assert.AreEqual(Ord(fcPerformance), Ord(LFinding.Category), 'Причина замедления, а не угроза');
  Assert.IsTrue(LFinding.Title.Contains('F:'));
  Assert.IsTrue(LFinding.Evidence[0].Observed.Contains('6,8') or LFinding.Evidence[0].Observed.Contains('6.8'),
    LFinding.Evidence[0].Observed);
  Assert.IsTrue(FindByKey(LFindings, 'disk:space:c:', LSystem));
  Assert.IsTrue(LSystem.Score > LFinding.Score, 'Системный и почти полный — серьёзнее');
  Assert.IsTrue(LSystem.Title.Contains('почти заполнен'));
  Assert.IsTrue(LSystem.Recommendations[0].Contains('Windows'));
  Assert.IsFalse(FindByKey(LFindings, 'disk:space:d:', LFinding));
end;

procedure TDiskAnalysisTests.Health_WearErrors_Findings;
var
  LSnapshot: TMHSnapshot;
  LFindings: TMHFindings;
  LFinding: TMHFinding;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Disks := [DiskWith(0, dhUnhealthy, -1, -1), DiskWith(1, dhHealthy, 90, -1),
    DiskWith(2, dhHealthy, -1, 16), DiskWith(3, dhWarning, -1, 500)];
  LSnapshot.Disks[0].HealthDetails := 'прогнозируется отказ';
  LFindings := MHAnalyzeDisks(LSnapshot, TMHRiskThresholds.Default, 'test');
  Assert.AreEqual(4, Integer(Length(LFindings)));
  Assert.IsTrue(FindByKey(LFindings, 'disk:health:0:model0', LFinding));
  Assert.IsTrue(LFinding.Level >= rlSuspicious, 'Неисправный диск — повод действовать');
  Assert.IsTrue(LFinding.Evidence[0].Description.Contains('прогнозируется отказ'));
  Assert.IsTrue(LFinding.Recommendations[0].Contains('резервную копию'));
  Assert.IsTrue(FindByKey(LFindings, 'disk:health:1:model1', LFinding));
  Assert.AreEqual(EV_DISK_WEAR, LFinding.Evidence[0].Code);
  Assert.IsTrue(FindByKey(LFindings, 'disk:health:2:model2', LFinding));
  Assert.AreEqual(Ord(rlLow), Ord(LFinding.Level), 'Немного ошибок — только на заметку');
  Assert.IsTrue(LFinding.Evidence[0].Observed.Contains('16'));
  Assert.IsTrue(FindByKey(LFindings, 'disk:health:3:model3', LFinding));
  Assert.AreEqual(2, Integer(Length(LFinding.Evidence)), 'Предупреждение и ошибки — в одной находке');
  Assert.IsTrue(LFinding.Score >= 75);
end;

procedure TDiskAnalysisTests.HealthyDisk_NoFinding;
var
  LSnapshot: TMHSnapshot;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Disks := [DiskWith(0, dhHealthy, 3, 0), DiskWith(1, dhUnknown, -1, -1)];
  Assert.AreEqual(0, Integer(Length(MHAnalyzeDisks(LSnapshot, TMHRiskThresholds.Default, 'test'))));
end;

procedure TDiskAnalysisTests.Health_BadSectorsAndNvmeCritical_Findings;
var
  LSnapshot: TMHSnapshot;
  LFindings: TMHFindings;
  LFinding: TMHFinding;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Disks := [DiskWith(0, dhHealthy, -1, -1), DiskWith(1, dhHealthy, -1, -1), DiskWith(2, dhHealthy, -1, -1),
    DiskWith(3, dhHealthy, -1, -1)];
  // Диск 0 — нестабильные и неисправимые секторы (как ST500DM002 клиента).
  LSnapshot.Disks[0].PendingSectors := 8;
  LSnapshot.Disks[0].UncorrectableSectors := 8;
  LSnapshot.Disks[0].ReallocatedSectors := 0;
  // Диск 1 — только несколько переназначенных: на заметку.
  LSnapshot.Disks[1].ReallocatedSectors := 4;
  // Диск 2 — NVMe с критическим предупреждением.
  LSnapshot.Disks[2].CriticalWarning := 1;
  // Диск 3 — всё по нулям.
  LSnapshot.Disks[3].ReallocatedSectors := 0;
  LSnapshot.Disks[3].PendingSectors := 0;
  LSnapshot.Disks[3].CriticalWarning := 0;
  LFindings := MHAnalyzeDisks(LSnapshot, TMHRiskThresholds.Default, 'test');
  Assert.IsTrue(FindByKey(LFindings, 'disk:health:0:model0', LFinding));
  Assert.AreEqual(EV_DISK_SECTORS, LFinding.Evidence[0].Code);
  Assert.IsTrue(LFinding.Evidence[0].Observed.Contains('нестабильных: 8'), LFinding.Evidence[0].Observed);
  Assert.IsTrue(LFinding.Level >= rlLow);
  Assert.IsTrue(LFinding.Recommendations[High(LFinding.Recommendations)].Contains('подвисать'),
    'Объясняет, почему компьютер подтормаживает');
  Assert.IsTrue(FindByKey(LFindings, 'disk:health:1:model1', LFinding));
  Assert.IsTrue(LFinding.Score < 25, 'Немного переназначенных — слабый признак: ' + IntToStr(LFinding.Score));
  Assert.IsTrue(FindByKey(LFindings, 'disk:health:2:model2', LFinding));
  Assert.AreEqual(EV_DISK_NVME_CRITICAL, LFinding.Evidence[0].Code);
  Assert.IsTrue(LFinding.Evidence[0].Observed.Contains('запас ниже порога'));
  Assert.IsFalse(FindByKey(LFindings, 'disk:health:3:model3', LFinding), 'Нули — не признак');
end;

function ProcessWithIo(APid: Cardinal; const AName: string; ARead, AWrite: Double): TMHProcessInfo;
begin
  Result := TMHProcessInfo.Create(TMHProcessId.Create(APid, APid), AName, FAKE_NOW);
  Result.SourceId := 'processes';
  Result.IoRead := TMHMetric.Available(mkDiskReadBytesPerSec, ARead, FAKE_NOW);
  Result.IoWrite := TMHMetric.Available(mkDiskWriteBytesPerSec, AWrite, FAKE_NOW);
end;

procedure TDiskAnalysisTests.ExplainLoad_BusiestDiskTopIoAndSpace;
var
  LSnapshot: TMHSnapshot;
  LReason: TMHLoadReason;
  LDiskText, LSpaceText: string;
  LDisk: TMHDiskInfo;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  LSnapshot.Metrics := [TMHMetric.Available(mkDiskActivePercent, 90, FAKE_NOW)];
  LDisk := TMHDiskInfo.Create(0, 'ST2000DM008');
  LDisk.HasActivity := True;
  LDisk.ActivePercent := 5;
  LDisk.Volumes := 'D:';
  LSnapshot.Disks := [LDisk];
  LDisk := TMHDiskInfo.Create(1, 'ST500DM002');
  LDisk.HasActivity := True;
  LDisk.ActivePercent := 90;
  LDisk.Volumes := 'F: H: I:';
  LSnapshot.Disks := LSnapshot.Disks + [LDisk];
  LSnapshot.Processes := [ProcessWithIo(10, 'backup.exe', 30 * 1024 * 1024, 0),
    ProcessWithIo(11, 'quiet.exe', 100, 0), ProcessWithIo(12, 'indexer.exe', 1024 * 1024, 2 * 1024 * 1024)];
  LSnapshot.Volumes := [Volume('F:', 146, 10, [1])];
  LDiskText := '';
  LSpaceText := '';
  for LReason in MHExplainLoad(LSnapshot, 8) do
    if LReason.Resource = 'disk' then
      LDiskText := LReason.Text
    else if LReason.Resource = 'space' then
      LSpaceText := LReason.Text;
  Assert.IsTrue(LDiskText.Contains('Диск 1 (ST500DM002; F: H: I:)'), LDiskText);
  Assert.IsTrue(LDiskText.IndexOf('backup.exe') < LDiskText.IndexOf('indexer.exe'), LDiskText);
  Assert.IsFalse(LDiskText.Contains('quiet.exe'), 'Мелкий ввод-вывод не упоминается');
  Assert.IsTrue(LSpaceText.Contains('F:'), LSpaceText);
end;

procedure TDiskAnalysisTests.ProcessIo_RateFromCounters;
var
  LApi: TFakeProcessApi;
  LCollector: IMHCollector;
  LDetails: TMHRawProcessDetails;
  LResult: TMHCollectionResult;
  LInfo: TMHProcessInfo;
begin
  LApi := TFakeProcessApi.Create;
  LApi.Add(100, 4, 'copy.exe', FAKE_BASE_TIME);
  LDetails := LApi.GetDetails(100);
  LDetails.HasIo := True;
  LDetails.IoReadBytes := 1000;
  LDetails.IoWriteBytes := 0;
  LApi.SetDetails(100, LDetails);
  LCollector := TMHProcessCollector.Create(LApi, TFakeClock.Create(FAKE_NOW));
  LResult := LCollector.Collect(TMHSnapshot.Create(1, FAKE_NOW));
  Assert.IsFalse(LResult.Processes[0].IoRead.HasValue, 'Первый замер — без скорости');
  LApi.AdvanceWall(2 * FAKE_SECOND);
  LDetails.IoReadBytes := 1000 + 10 * 1024 * 1024;
  LDetails.IoWriteBytes := 4 * 1024 * 1024;
  LApi.SetDetails(100, LDetails);
  LResult := LCollector.Collect(TMHSnapshot.Create(2, FAKE_NOW));
  LInfo := LResult.Processes[0];
  Assert.IsTrue(LInfo.IoRead.HasValue);
  Assert.AreEqual(5.0 * 1024 * 1024, LInfo.IoRead.Value, 1, '10 МБ за 2 с');
  Assert.AreEqual(2.0 * 1024 * 1024, LInfo.IoWrite.Value, 1);
  // Счётчик уменьшился (другой процесс с тем же PID не пройдёт проверку времени создания,
  // но защитимся и от сброса счётчиков) — скорость не выдумывается.
  LApi.AdvanceWall(FAKE_SECOND);
  LDetails.IoReadBytes := 10;
  LApi.SetDetails(100, LDetails);
  Assert.IsFalse(LCollector.Collect(TMHSnapshot.Create(3, FAKE_NOW)).Processes[0].IoRead.HasValue);
end;

procedure TDiskAnalysisTests.TopIo_OrderAndThreshold;
var
  LSnapshot: TMHSnapshot;
begin
  LSnapshot := TMHSnapshot.Create(1, FAKE_NOW);
  Assert.AreEqual('', MHTopIoProcesses(LSnapshot));
  LSnapshot.Processes := [ProcessWithIo(1, 'a.exe', 200 * 1024, 0), ProcessWithIo(2, 'b.exe', 0, 5 * 1024 * 1024),
    ProcessWithIo(3, 'c.exe', 1024 * 1024, 0), ProcessWithIo(4, 'd.exe', 10, 10)];
  Assert.AreEqual('b.exe ' + FormatFloat('0.0', 5) + ' МБ/с, c.exe ' + FormatFloat('0.0', 1) + ' МБ/с',
    MHTopIoProcesses(LSnapshot, 2));
  Assert.IsTrue(MHFormatRate(512).EndsWith('КБ/с'));
  Assert.IsTrue(MHFormatSize(2.5 * 1024 * 1024 * 1024 * 1024).Contains('ТБ'));
end;

{ TDiskIntegrationTests }

procedure TDiskIntegrationTests.RealDisks_AreDetected;
var
  LApi: IMHDiskApi;
  LDisks: TArray<TMHRawDisk>;
  LVolumes: TArray<TMHVolumeInfo>;
  LCounters: TArray<TMHRawDiskCounter>;
  LReliability: TArray<TMHRawReliability>;
  LError: string;
  LDenied, LSystem: Boolean;
  LVolume: TMHVolumeInfo;
begin
  LApi := TMHWinDiskApi.Create;
  Assert.IsTrue(LApi.ReadDisks(LDisks, LError), LError);
  Assert.IsTrue(Length(LDisks) >= 1, 'Хотя бы один физический диск');
  Assert.IsNotEmpty(LDisks[0].Model);
  Assert.IsTrue(LApi.ReadVolumes(LVolumes, LError), LError);
  LSystem := False;
  for LVolume in LVolumes do
    if LVolume.IsSystem then
    begin
      LSystem := True;
      Assert.IsTrue(LVolume.TotalBytes > 0);
      Assert.IsTrue(Length(LVolume.DiskNumbers) >= 1, 'Системный раздел привязан к диску');
    end;
  Assert.IsTrue(LSystem, 'Раздел с Windows найден');
  Sleep(300);
  Assert.IsTrue(LApi.ReadCounters(LCounters, LError), LError);
  Assert.IsTrue(Length(LCounters) >= 1);
  // Счётчики надёжности: с правами — читаются, без прав — понятная причина.
  if not LApi.ReadReliability(LReliability, LError, LDenied) then
    Assert.IsNotEmpty(LError);
end;

initialization
  TDUnitX.RegisterTestFixture(TDiskCollectorTests);
  TDUnitX.RegisterTestFixture(TDiskAnalysisTests);
  TDUnitX.RegisterTestFixture(TDiskIntegrationTests);

end.
