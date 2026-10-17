unit MineHunter.Tests.SystemCollector;

interface

uses
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Core.Interfaces, MineHunter.Collectors.System,
  MineHunter.Tests.FakeSystemApi;

type
  [TestFixture]
  [Category('Unit')]
  TSystemCollectorTests = class
  private
    FApi: TFakeSystemMetricsApi;
    FApiIntf: IMHSystemMetricsApi;
    FCollector: IMHCollector;
    function Collect: TMHCollectionResult;
    function Metric(const AResult: TMHCollectionResult; AKind: TMHMetricKind): TMHMetric;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Create_NilArguments_Raise;
    [Test] procedure FirstCollect_CpuNoData_IsPartial;
    [TestCase('idle', '0')]
    [TestCase('quarter', '25')]
    [TestCase('half', '50')]
    [TestCase('full', '100')]
    procedure SecondCollect_ReferenceCpu(ABusy: Integer);
    [Test] procedure Memory_ReferenceValues;
    [Test] procedure Disk_ReferenceValues;
    [Test] procedure DiskUnavailable_IsPartialWithReason;
    [Test] procedure CountersGoingBackwards_CpuNoData;
    [Test] procedure InconsistentMemory_IsNoData;
    [Test] procedure EverythingFails_IsError;
    [Test] procedure DiskActivity_IsClampedTo100;
    [Test] procedure ContractFields;
    [Test] procedure Utility_IsCpuPercent_TimeIsSeparate;
    [Test] procedure Utility_Above100_IsClampedLikeTaskManager;
    [Test] procedure NoUtility_CpuPercentIsTime;
    [Test] procedure FrequencyAndLimit_Reported;
    [Test] procedure FrequencyAndLimit_Unavailable_NoDataAndStillSuccess;
    [Test] procedure Network_ReportedOrNoData;
  end;

implementation

uses
  System.SysUtils,
  MineHunter.Tests.Fakes;

const
  SECOND = 10000000;

procedure TSystemCollectorTests.Setup;
begin
  FApi := TFakeSystemMetricsApi.Create;
  FApiIntf := FApi;
  FCollector := TMHSystemCollector.Create(FApiIntf, TFakeClock.Create(FAKE_NOW));
end;

procedure TSystemCollectorTests.TearDown;
begin
  FCollector := nil;
  FApiIntf := nil;
  FApi := nil;
end;

function TSystemCollectorTests.Collect: TMHCollectionResult;
begin
  Result := FCollector.Collect(TMHSnapshot.Create(1, FAKE_NOW));
end;

function TSystemCollectorTests.Metric(const AResult: TMHCollectionResult;
  AKind: TMHMetricKind): TMHMetric;
var
  LMetric: TMHMetric;
begin
  Result := TMHMetric.NoData(AKind, 0);
  for LMetric in AResult.Metrics do
    if LMetric.Kind = AKind then
      Exit(LMetric);
  Assert.Fail('Метрика отсутствует: ' + IntToStr(Ord(AKind)));
end;

procedure TSystemCollectorTests.Create_NilArguments_Raise;
var
  LClock: IMHClock;
begin
  LClock := TFakeClock.Create(FAKE_NOW);
  Assert.WillRaise(
    procedure
    begin
      TMHSystemCollector.Create(nil, LClock).Free;
    end, EArgumentNilException);
  Assert.WillRaise(
    procedure
    begin
      TMHSystemCollector.Create(FApiIntf, nil).Free;
    end, EArgumentNilException);
end;

procedure TSystemCollectorTests.FirstCollect_CpuNoData_IsPartial;
var
  LResult: TMHCollectionResult;
begin
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.IsFalse(Metric(LResult, mkCpuPercent).HasValue);
  Assert.IsTrue(LResult.Status.Message.Contains('CPU'));
  Assert.IsTrue(Metric(LResult, mkMemoryLoadPercent).HasValue, 'Память доступна сразу');
end;

procedure TSystemCollectorTests.SecondCollect_ReferenceCpu(ABusy: Integer);
var
  LResult: TMHCollectionResult;
begin
  Collect;
  FApi.Advance(SECOND, 8, ABusy);
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State, LResult.Status.Message);
  Assert.AreEqual(Double(ABusy), Metric(LResult, mkCpuPercent).Value, 0.01);
end;

procedure TSystemCollectorTests.Memory_ReferenceValues;
var
  LResult: TMHCollectionResult;
begin
  LResult := Collect;
  Assert.AreEqual(Double(10 * GB), Metric(LResult, mkMemoryUsedBytes).Value, 1);
  Assert.AreEqual(Double(16 * GB), Metric(LResult, mkMemoryTotalBytes).Value, 1);
  // Точная доля занятой памяти: (16 - 6) / 16 = 62,5% (dwMemoryLoad округляет до 62).
  Assert.AreEqual(62.5, Metric(LResult, mkMemoryLoadPercent).Value, 0.001);
end;

procedure TSystemCollectorTests.Disk_ReferenceValues;
var
  LResult: TMHCollectionResult;
begin
  LResult := Collect;
  Assert.AreEqual(1048576.0, Metric(LResult, mkDiskReadBytesPerSec).Value, 0.001);
  Assert.AreEqual(524288.0, Metric(LResult, mkDiskWriteBytesPerSec).Value, 0.001);
  Assert.AreEqual(12.5, Metric(LResult, mkDiskActivePercent).Value, 0.001);
end;

procedure TSystemCollectorTests.DiskUnavailable_IsPartialWithReason;
var
  LResult: TMHCollectionResult;
begin
  Collect;
  FApi.Advance(SECOND, 4, 10);
  FApi.Disk := Default(TMHDiskCounters);
  FApi.Disk.Reason := 'счётчики отключены';
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssPartial, LResult.Status.State);
  Assert.IsTrue(LResult.Status.Message.Contains('счётчики отключены'));
  Assert.IsFalse(Metric(LResult, mkDiskReadBytesPerSec).HasValue, 'Нет данных, а не ноль');
  Assert.IsTrue(Metric(LResult, mkCpuPercent).HasValue, 'Отказ диска не влияет на CPU');
end;

procedure TSystemCollectorTests.CountersGoingBackwards_CpuNoData;
begin
  Collect;
  FApi.Times.Idle := 1;
  FApi.Times.Kernel := 2;
  FApi.Times.User := 1;
  Assert.IsFalse(Metric(Collect, mkCpuPercent).HasValue);
end;

procedure TSystemCollectorTests.InconsistentMemory_IsNoData;
var
  LResult: TMHCollectionResult;
begin
  FApi.Memory.AvailableBytes := FApi.Memory.TotalBytes + 1;
  LResult := Collect;
  Assert.IsFalse(Metric(LResult, mkMemoryUsedBytes).HasValue);
  Assert.IsTrue(LResult.Status.Message.Contains('Память'));
end;

procedure TSystemCollectorTests.EverythingFails_IsError;
var
  LResult: TMHCollectionResult;
begin
  FApi.TimesFail := True;
  FApi.MemoryFail := True;
  FApi.Disk := Default(TMHDiskCounters);
  LResult := Collect;
  Assert.AreEqual<TMHSourceState>(ssError, LResult.Status.State);
  Assert.IsTrue(LResult.Status.Message.Contains('simulated'));
end;

procedure TSystemCollectorTests.DiskActivity_IsClampedTo100;
begin
  FApi.Disk.ActivePercent := 140;
  Assert.AreEqual(100.0, Metric(Collect, mkDiskActivePercent).Value, 0.001);
  FApi.Disk.ActivePercent := -3;
  Assert.AreEqual(0.0, Metric(Collect, mkDiskActivePercent).Value, 0.001);
end;

procedure TSystemCollectorTests.ContractFields;
var
  LResult: TMHCollectionResult;
begin
  LResult := FCollector.Collect(Default(TMHSnapshot));
  Assert.AreEqual(TMHSystemCollector.SourceIdValue, LResult.Status.SourceId);
  Assert.AreEqual(Integer(Length(LResult.Metrics)), LResult.Status.ItemCount);
  Assert.AreEqual(0, Integer(Length(LResult.Processes)));
end;

procedure TSystemCollectorTests.Utility_IsCpuPercent_TimeIsSeparate;
var
  LResult: TMHCollectionResult;
begin
  Collect;
  FApi.Advance(SECOND, 8, 30);
  // Турбочастота: диспетчер задач показывает 41% при 30% времени работы.
  FApi.Processor.HasUtility := True;
  FApi.Processor.UtilityPercent := 41;
  LResult := Collect;
  Assert.AreEqual(41.0, Metric(LResult, mkCpuPercent).Value, 0.01);
  Assert.AreEqual(30.0, Metric(LResult, mkCpuTimePercent).Value, 0.01);
end;

procedure TSystemCollectorTests.Utility_Above100_IsClampedLikeTaskManager;
var
  LResult: TMHCollectionResult;
begin
  Collect;
  FApi.Advance(SECOND, 8, 90);
  FApi.Processor.HasUtility := True;
  FApi.Processor.UtilityPercent := 128;
  LResult := Collect;
  Assert.AreEqual(100.0, Metric(LResult, mkCpuPercent).Value, 0.01);
end;

procedure TSystemCollectorTests.NoUtility_CpuPercentIsTime;
var
  LResult: TMHCollectionResult;
begin
  Collect;
  FApi.Advance(SECOND, 8, 25);
  LResult := Collect;
  Assert.AreEqual(25.0, Metric(LResult, mkCpuPercent).Value, 0.01);
  Assert.AreEqual(25.0, Metric(LResult, mkCpuTimePercent).Value, 0.01);
end;

procedure TSystemCollectorTests.FrequencyAndLimit_Reported;
var
  LResult: TMHCollectionResult;
begin
  FApi.Processor.HasPerformance := True;
  FApi.Processor.PerformancePercent := 130;
  FApi.Processor.HasLimit := True;
  FApi.Processor.LimitPercent := 85;
  LResult := Collect;
  Assert.AreEqual(130.0, Metric(LResult, mkCpuFrequencyPercent).Value, 0.01, 'Турбочастота не обрезается');
  Assert.AreEqual(85.0, Metric(LResult, mkCpuPerformanceLimitPercent).Value, 0.01);
end;

procedure TSystemCollectorTests.FrequencyAndLimit_Unavailable_NoDataAndStillSuccess;
var
  LResult: TMHCollectionResult;
begin
  Collect;
  FApi.Advance(SECOND, 8, 10);
  LResult := Collect;
  Assert.IsFalse(Metric(LResult, mkCpuFrequencyPercent).HasValue);
  Assert.IsFalse(Metric(LResult, mkCpuPerformanceLimitPercent).HasValue);
  Assert.AreEqual<TMHSourceState>(ssSuccess, LResult.Status.State,
    'Необязательные счётчики не делают источник частичным');
end;

procedure TSystemCollectorTests.Network_ReportedOrNoData;
begin
  Assert.IsFalse(Metric(Collect, mkNetworkBytesPerSec).HasValue);
  FApi.Network.Available := True;
  FApi.Network.BytesPerSec := 2048;
  Assert.AreEqual(2048.0, Metric(Collect, mkNetworkBytesPerSec).Value, 0.01);
  FApi.Network.BytesPerSec := -5;
  Assert.AreEqual(0.0, Metric(Collect, mkNetworkBytesPerSec).Value, 0.01, 'Отрицательные значения отбрасываются');
end;

initialization
  TDUnitX.RegisterTestFixture(TSystemCollectorTests);

end.
