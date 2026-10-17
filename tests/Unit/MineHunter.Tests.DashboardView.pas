unit MineHunter.Tests.DashboardView;

{
  Модель страницы «Обзор»: карточки «Сейчас» (значения, пояснения, состояния)
  и список причин «почему тормозит или греется».
}

interface

uses
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.App.DashboardView;

type
  [TestFixture]
  [Category('Unit')]
  TDashboardViewTests = class
  private
    function Snapshot: TMHSnapshot;
    function TileOf(const ASnapshot: TMHSnapshot; AKind: TMHTileKind): TMHTileData;
  public
    [Test] procedure EmptySnapshot_AllTilesNoData;
    [Test] procedure Tiles_InFixedOrder;
    [Test] procedure Cpu_ValueFrequencyAndThrottlingWarning;
    [Test] procedure Cpu_StatesByThresholds;
    [Test] procedure Memory_ValueAndUsedOfTotal;
    [Test] procedure Disk_BusyIsWarningNotAlert;
    [Test] procedure Gpu_ComputeAndMemoryInDetail;
    [Test] procedure Temperature_ClosestToLimitAndOthers;
    [Test] procedure Temperature_AtLimitIsAlert;
    [Test] procedure Reasons_EmptySnapshot_SingleNoDataLine;
    [Test] procedure Reasons_AllNormal_SummaryFirst;
    [Test] procedure Reasons_HighFirstWithSummaryAndHeatAlert;
    [Test] procedure StateByThresholds_Boundaries;
  end;

implementation

uses
  System.SysUtils,
  MineHunter.App.Display, MineHunter.Tests.Fakes;

function TDashboardViewTests.Snapshot: TMHSnapshot;
begin
  Result := TMHSnapshot.Create(1, FAKE_NOW);
end;

function TDashboardViewTests.TileOf(const ASnapshot: TMHSnapshot; AKind: TMHTileKind): TMHTileData;
var
  LTile: TMHTileData;
begin
  for LTile in MHBuildDashboardTiles(ASnapshot) do
    if LTile.Kind = AKind then
      Exit(LTile);
  Assert.Fail('Нет карточки');
  Result := Default(TMHTileData);
end;

procedure AddMetric(var ASnapshot: TMHSnapshot; AKind: TMHMetricKind; AValue: Double);
begin
  ASnapshot.Metrics := ASnapshot.Metrics + [TMHMetric.Available(AKind, AValue, FAKE_NOW)];
end;

procedure TDashboardViewTests.EmptySnapshot_AllTilesNoData;
var
  LTile: TMHTileData;
begin
  for LTile in MHBuildDashboardTiles(Snapshot) do
  begin
    Assert.AreEqual(MH_NO_DATA, LTile.Value, LTile.Title);
    Assert.AreEqual<TMHTileState>(tsNoData, LTile.State, LTile.Title);
  end;
end;

procedure TDashboardViewTests.Tiles_InFixedOrder;
var
  LTiles: TArray<TMHTileData>;
  LKind: TMHTileKind;
begin
  LTiles := MHBuildDashboardTiles(Snapshot);
  Assert.AreEqual(Ord(High(TMHTileKind)) + 1, Integer(Length(LTiles)));
  for LKind := Low(TMHTileKind) to High(TMHTileKind) do
    Assert.AreEqual<TMHTileKind>(LKind, LTiles[Ord(LKind)].Kind);
  Assert.AreEqual('Процессор', LTiles[0].Title);
  Assert.AreEqual('Температура', LTiles[5].Title);
end;

procedure TDashboardViewTests.Cpu_ValueFrequencyAndThrottlingWarning;
var
  LSnapshot: TMHSnapshot;
  LTile: TMHTileData;
begin
  LSnapshot := Snapshot;
  AddMetric(LSnapshot, mkCpuPercent, 21);
  AddMetric(LSnapshot, mkCpuFrequencyPercent, 132);
  AddMetric(LSnapshot, mkCpuPerformanceLimitPercent, 100);
  LTile := TileOf(LSnapshot, tkCpu);
  Assert.AreEqual('21 %', LTile.Value);
  Assert.AreEqual('частота 132 % от базовой · без троттлинга', LTile.Detail);
  Assert.AreEqual<TMHTileState>(tsOk, LTile.State);

  LSnapshot := Snapshot;
  AddMetric(LSnapshot, mkCpuPercent, 40);
  AddMetric(LSnapshot, mkCpuPerformanceLimitPercent, 70);
  LTile := TileOf(LSnapshot, tkCpu);
  Assert.IsTrue(LTile.Detail.Contains('троттлинг: ограничен до 70 %'), LTile.Detail);
  Assert.AreEqual<TMHTileState>(tsWarning, LTile.State, 'Троттлинг — повод для внимания даже при низкой нагрузке');
end;

procedure TDashboardViewTests.Cpu_StatesByThresholds;
var
  LSnapshot: TMHSnapshot;
begin
  LSnapshot := Snapshot;
  AddMetric(LSnapshot, mkCpuPercent, 75);
  Assert.AreEqual<TMHTileState>(tsWarning, TileOf(LSnapshot, tkCpu).State);
  LSnapshot := Snapshot;
  AddMetric(LSnapshot, mkCpuPercent, 96);
  Assert.AreEqual<TMHTileState>(tsAlert, TileOf(LSnapshot, tkCpu).State);
end;

procedure TDashboardViewTests.Memory_ValueAndUsedOfTotal;
var
  LSnapshot: TMHSnapshot;
  LTile: TMHTileData;
begin
  LSnapshot := Snapshot;
  AddMetric(LSnapshot, mkMemoryLoadPercent, 49.2);
  AddMetric(LSnapshot, mkMemoryUsedBytes, 15.66 * 1073741824);
  AddMetric(LSnapshot, mkMemoryTotalBytes, 31.87 * 1073741824);
  LTile := TileOf(LSnapshot, tkMemory);
  Assert.AreEqual('49 %', LTile.Value);
  Assert.AreEqual('занято ' + MHFormatBytes(15.66 * 1073741824) + ' из ' + MHFormatBytes(31.87 * 1073741824),
    LTile.Detail);
end;

procedure TDashboardViewTests.Disk_BusyIsWarningNotAlert;
var
  LSnapshot: TMHSnapshot;
  LTile: TMHTileData;
begin
  LSnapshot := Snapshot;
  AddMetric(LSnapshot, mkDiskActivePercent, 100);
  AddMetric(LSnapshot, mkDiskReadBytesPerSec, 2048);
  AddMetric(LSnapshot, mkDiskWriteBytesPerSec, 0);
  LTile := TileOf(LSnapshot, tkDisk);
  Assert.AreEqual<TMHTileState>(tsWarning, LTile.State);
  Assert.IsTrue(LTile.Detail.StartsWith('чтение '), LTile.Detail);
end;

procedure TDashboardViewTests.Gpu_ComputeAndMemoryInDetail;
var
  LSnapshot: TMHSnapshot;
  LTile: TMHTileData;
begin
  LSnapshot := Snapshot;
  AddMetric(LSnapshot, mkGpuPercent, 27);
  AddMetric(LSnapshot, mkGpuComputePercent, 0);
  AddMetric(LSnapshot, mkGpuMemoryBytes, 1.7 * 1073741824);
  LTile := TileOf(LSnapshot, tkGpu);
  Assert.AreEqual('27 %', LTile.Value);
  Assert.AreEqual('вычисления 0 % · видеопамять ' + MHFormatBytes(1.7 * 1073741824), LTile.Detail);
end;

procedure TDashboardViewTests.Temperature_ClosestToLimitAndOthers;
var
  LSnapshot: TMHSnapshot;
  LTile: TMHTileData;
begin
  LSnapshot := Snapshot;
  // Видеокарта горячее (44 °C), но накопитель ближе к своему порогу (42 из 60).
  LSnapshot.Sensors := [TMHSensorReading.Create(skGpu, 'GeForce', 'D3DKMT', 44, 83),
    TMHSensorReading.Create(skDisk, 'HDD', 'storage', 42, 60),
    TMHSensorReading.Create(skDisk, 'NVMe', 'storage', 49, 83)];
  LTile := TileOf(LSnapshot, tkTemperature);
  Assert.AreEqual('42 °C', LTile.Value);
  Assert.AreEqual('у накопителя, порог 60 °C · видеокарта 44 °C', LTile.Detail);
  Assert.AreEqual<TMHTileState>(tsOk, LTile.State);
end;

procedure TDashboardViewTests.Temperature_AtLimitIsAlert;
var
  LSnapshot: TMHSnapshot;
begin
  LSnapshot := Snapshot;
  LSnapshot.Sensors := [TMHSensorReading.Create(skGpu, 'GeForce', 'D3DKMT', 80, 83)];
  Assert.AreEqual<TMHTileState>(tsWarning, TileOf(LSnapshot, tkTemperature).State, 'Ближе 5 °C к порогу');
  LSnapshot.Sensors := [TMHSensorReading.Create(skGpu, 'GeForce', 'D3DKMT', 84, 83)];
  Assert.AreEqual<TMHTileState>(tsAlert, TileOf(LSnapshot, tkTemperature).State);
end;

procedure TDashboardViewTests.Reasons_EmptySnapshot_SingleNoDataLine;
var
  LItems: TArray<TMHReasonItem>;
begin
  LItems := MHBuildDashboardReasons(Snapshot, 8);
  Assert.AreEqual(1, Integer(Length(LItems)));
  Assert.AreEqual<TMHTileState>(tsNoData, LItems[0].State);
end;

procedure TDashboardViewTests.Reasons_AllNormal_SummaryFirst;
var
  LSnapshot: TMHSnapshot;
  LItems: TArray<TMHReasonItem>;
begin
  LSnapshot := Snapshot;
  AddMetric(LSnapshot, mkCpuPercent, 10);
  AddMetric(LSnapshot, mkMemoryLoadPercent, 40);
  LItems := MHBuildDashboardReasons(LSnapshot, 8);
  Assert.AreEqual(3, Integer(Length(LItems)));
  Assert.IsTrue(LItems[0].Text.StartsWith('Компьютер не перегружен'));
  Assert.AreEqual<TMHTileState>(tsOk, LItems[1].State);
end;

procedure TDashboardViewTests.Reasons_HighFirstWithSummaryAndHeatAlert;
var
  LSnapshot: TMHSnapshot;
  LItems: TArray<TMHReasonItem>;
begin
  LSnapshot := Snapshot;
  AddMetric(LSnapshot, mkCpuPercent, 10);
  AddMetric(LSnapshot, mkDiskActivePercent, 95);
  LSnapshot.Sensors := [TMHSensorReading.Create(skGpu, 'GeForce', 'D3DKMT', 82, 83)];
  LItems := MHBuildDashboardReasons(LSnapshot, 8);
  Assert.IsTrue(LItems[0].Text.StartsWith('Требует внимания: 2 из 3'), LItems[0].Text);
  Assert.AreEqual<TMHTileState>(tsWarning, LItems[1].State, 'Занятый диск — внимание');
  Assert.IsTrue(LItems[1].Text.StartsWith('Диск'));
  Assert.AreEqual<TMHTileState>(tsAlert, LItems[2].State, 'Перегрев — тревога');
  Assert.IsTrue(LItems[2].Text.StartsWith('Видеокарта GeForce'));
  Assert.AreEqual<TMHTileState>(tsOk, LItems[3].State, 'Обычные показатели — после важных');
end;

procedure TDashboardViewTests.StateByThresholds_Boundaries;
begin
  Assert.AreEqual<TMHTileState>(tsOk, MHStateByThresholds(69.9, 70, 90));
  Assert.AreEqual<TMHTileState>(tsWarning, MHStateByThresholds(70, 70, 90));
  Assert.AreEqual<TMHTileState>(tsAlert, MHStateByThresholds(90, 70, 90));
end;

initialization
  TDUnitX.RegisterTestFixture(TDashboardViewTests);

end.
