unit MineHunter.Tests.AnalyzerGpu;

{
  Правила анализатора для видеокарты, температур и троттлинга:
  фоновые вычисления на GPU, оправдывающие факторы, системные находки
  «перегрев» и «троттлинг», объяснение «почему тормозит или греется».
}

interface

uses
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.Analysis.Engine, MineHunter.Tests.Scenarios;

type
  [TestFixture]
  [Category('Unit')]
  TAnalyzerGpuTests = class
  private
    function RunAll(const ASnapshots: TArray<TMHSnapshot>): TMHFindings;
  public
    [Test] procedure GpuComputeBackground_LowCpu_IsMiningWithExplanation;
    [Test] procedure GpuCompute_WithWindow_NoBackgroundEvidence;
    [Test] procedure GpuSustained_ShortHistory_NoEvidence;
    [Test] procedure GpuCompute_SignedKnownCompute_NotAlert;
    [Test] procedure CpuLoadWithoutGpuData_NotesMissingGpu;
    [Test] procedure SystemGpuHeat_AtLimit_PerformanceFinding;
    [Test] procedure SystemGpuHeat_BelowLimit_NoFinding;
    [Test] procedure DiskHeat_UsesDeviceWarning;
    [Test] procedure Throttling_SustainedLimit_Finding;
    [Test] procedure Throttling_ShortDip_NoFinding;
    [Test] procedure ExplainLoad_GpuTopConsumerWithCompute;
    [Test] procedure ExplainLoad_HeatNearLimitIsHigh;
    [Test] procedure ExplainLoad_ThrottleAndMemoryAsTaskManager;
    [Test] procedure TemperatureLimit_DefaultsAndDevice;
  end;

implementation

uses
  System.SysUtils, System.StrUtils;

function HasCode(const AFinding: TMHFinding; const ACode: string): Boolean;
var
  LEvidence: TMHEvidence;
begin
  for LEvidence in AFinding.Evidence do
    if LEvidence.Code = ACode then
      Exit(True);
  Result := False;
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
  AFinding := Default(TMHFinding);
  Result := False;
end;

function GpuProcess(APid: Cardinal; const AName, APath: string; ASignature: TMHSignatureState;
  const ASigner: string; ACpu, AGpu, ACompute: Double): TScenarioProcess;
begin
  Result := Proc(APid, AName, APath, ASignature, ASigner, [0, ACpu]);
  Result.Gpu := AGpu;
  Result.GpuCompute := ACompute;
end;

/// Добавляет во все снимки показание датчика и метрику предела производительности.
procedure AddSensors(var ASnapshots: TArray<TMHSnapshot>; const AReading: TMHSensorReading);
var
  I: Integer;
begin
  for I := 0 to High(ASnapshots) do
    ASnapshots[I].Sensors := ASnapshots[I].Sensors + [AReading];
end;

procedure AddMetric(var ASnapshots: TArray<TMHSnapshot>; AKind: TMHMetricKind; AValue: Double;
  AFromIndex: Integer = 0);
var
  I: Integer;
begin
  for I := AFromIndex to High(ASnapshots) do
    ASnapshots[I].Metrics := ASnapshots[I].Metrics +
      [TMHMetric.Available(AKind, AValue, ASnapshots[I].TimestampUtc)];
end;

function TAnalyzerGpuTests.RunAll(const ASnapshots: TArray<TMHSnapshot>): TMHFindings;
var
  LAnalyzer: TMHThreatAnalyzer;
  LIntf: IInterface;
  LSnapshot: TMHSnapshot;
begin
  LAnalyzer := TMHThreatAnalyzer.Create(SCENARIO_CPU_COUNT, 999999);
  LIntf := LAnalyzer;
  Result := nil;
  for LSnapshot in ASnapshots do
    Result := LAnalyzer.Analyze(LSnapshot, TMHBaseline.Empty);
end;

procedure TAnalyzerGpuTests.GpuComputeBackground_LowCpu_IsMiningWithExplanation;
var
  LFindings: TMHFindings;
  LFinding: TMHFinding;
begin
  LFindings := RunAll(BuildSnapshots([GpuProcess(4001, 'gpuhost.exe', USER_DIR + 'AppData\Roaming\gpuhost.exe',
    sgUnsigned, '', 2, 98, 98)], 900, False, nil));
  Assert.IsTrue(MaxLevelFor(LFindings, 'gpuhost.exe', LFinding) >= rlSuspicious,
    'Майнер на GPU с почти нулевой нагрузкой CPU должен быть найден');
  Assert.AreEqual<TMHFindingCategory>(fcMining, LFinding.Category);
  Assert.IsTrue(HasCode(LFinding, EV_GPU_COMPUTE_BACKGROUND));
  Assert.IsTrue(HasCode(LFinding, EV_GPU_SUSTAINED));
  Assert.IsTrue(HasCode(LFinding, EV_LOAD_BACKGROUND));
  Assert.IsTrue(HasCode(LFinding, EV_LOAD_WHILE_IDLE));
  Assert.IsFalse(HasCode(LFinding, EV_LOAD_SUSTAINED), 'Процессор почти не нагружен');
end;

procedure TAnalyzerGpuTests.GpuCompute_WithWindow_NoBackgroundEvidence;
var
  LFindings: TMHFindings;
  LFinding: TMHFinding;
  P: TScenarioProcess;
begin
  P := GpuProcess(4002, 'trainer.exe', 'C:\Program Files\Trainer\trainer.exe', sgSignedTrusted, 'Vendor',
    5, 90, 90);
  P.HasWindow := True;
  P.Foreground := True;
  LFindings := RunAll(BuildSnapshots([P], 5, False, nil));
  MaxLevelFor(LFindings, 'trainer.exe', LFinding);
  Assert.IsFalse(HasCode(LFinding, EV_GPU_COMPUTE_BACKGROUND), 'Программа с окном не «фоновая»');
  Assert.IsTrue(LFinding.Level <= rlLow);
end;

procedure TAnalyzerGpuTests.GpuSustained_ShortHistory_NoEvidence;
var
  LFindings: TMHFindings;
  LFinding: TMHFinding;
begin
  // 5 минут истории при требуемых 15 — длительность не подтверждена.
  LFindings := RunAll(BuildSnapshots([GpuProcess(4003, 'gpuhost.exe', USER_DIR + 'AppData\Roaming\gpuhost.exe',
    sgUnsigned, '', 2, 98, 98)], 900, False, nil, 5));
  MaxLevelFor(LFindings, 'gpuhost.exe', LFinding);
  Assert.IsFalse(HasCode(LFinding, EV_GPU_SUSTAINED));
  Assert.IsFalse(HasCode(LFinding, EV_GPU_COMPUTE_BACKGROUND));
end;

procedure TAnalyzerGpuTests.GpuCompute_SignedKnownCompute_NotAlert;
var
  LFindings: TMHFindings;
  LFinding: TMHFinding;
begin
  LFindings := RunAll(BuildSnapshots([GpuProcess(4004, 'FahCore_23.exe',
    'C:\Program Files\FAHClient\cores\FahCore_23.exe', sgSignedTrusted, 'Folding@home Consortium',
    4, 95, 95)], 900, False, nil));
  Assert.IsTrue(MaxLevelFor(LFindings, 'FahCore_23.exe', LFinding) <= rlLow,
    'Подписанные добровольные вычисления — не тревога');
  Assert.AreNotEqual<TMHFindingCategory>(fcMining, LFinding.Category);
end;

procedure TAnalyzerGpuTests.CpuLoadWithoutGpuData_NotesMissingGpu;
var
  LSnapshots: TArray<TMHSnapshot>;
  LFindings: TMHFindings;
  LFinding: TMHFinding;
  I, J: Integer;
  LMissing: string;
  LFound: Boolean;
begin
  LSnapshots := BuildSnapshots([Proc(4005, 'worker.exe', USER_DIR + 'AppData\Local\Temp\worker.exe',
    sgUnsigned, '', [0, 60])], 900, False, nil);
  // Источник gpu недоступен: метрик видеокарты нет ни у системы, ни у процессов.
  for I := 0 to High(LSnapshots) do
  begin
    for J := 0 to High(LSnapshots[I].Processes) do
    begin
      LSnapshots[I].Processes[J].Gpu := TMHMetric.NoData(mkGpuPercent, 0);
      LSnapshots[I].Processes[J].GpuCompute := TMHMetric.NoData(mkGpuComputePercent, 0);
    end;
    SetLength(LSnapshots[I].Metrics, 3); // без mkGpuPercent
  end;
  LFindings := RunAll(LSnapshots);
  Assert.IsTrue(MaxLevelFor(LFindings, 'worker.exe', LFinding) >= rlNeedsReview);
  LFound := False;
  for LMissing in LFinding.MissingData do
    if LMissing.Contains('видеокарты') then
      LFound := True;
  Assert.IsTrue(LFound, 'Недостающие данные о GPU перечислены в находке');
end;

procedure TAnalyzerGpuTests.SystemGpuHeat_AtLimit_PerformanceFinding;
var
  LSnapshots: TArray<TMHSnapshot>;
  LFinding: TMHFinding;
begin
  LSnapshots := BuildSnapshots(nil, 5, False, nil);
  AddSensors(LSnapshots, TMHSensorReading.Create(skGpu, 'GeForce GTX 1660 Ti', 'D3DKMT', 84, 83));
  Assert.IsTrue(FindByKey(RunAll(LSnapshots), 'system:heat:gpu', LFinding));
  Assert.AreEqual<TMHFindingCategory>(fcPerformance, LFinding.Category);
  Assert.IsTrue(HasCode(LFinding, EV_OVERHEAT));
  Assert.IsTrue(LFinding.Evidence[0].Observed.Contains('GeForce GTX 1660 Ti'));
  Assert.IsTrue(LFinding.Evidence[0].Observed.Contains('84 °C'));
  Assert.IsTrue(LFinding.Evidence[0].Observed.Contains('порог 83 °C'));
  Assert.IsTrue(Length(LFinding.Recommendations) > 0);
end;

procedure TAnalyzerGpuTests.SystemGpuHeat_BelowLimit_NoFinding;
var
  LSnapshots: TArray<TMHSnapshot>;
  LFinding: TMHFinding;
begin
  // 80 °C при пороге 83 °C — обычная температура видеокарты под нагрузкой.
  LSnapshots := BuildSnapshots(nil, 5, False, nil);
  AddSensors(LSnapshots, TMHSensorReading.Create(skGpu, 'GeForce', 'D3DKMT', 80, 83));
  Assert.IsFalse(FindByKey(RunAll(LSnapshots), 'system:heat:gpu', LFinding));
end;

procedure TAnalyzerGpuTests.DiskHeat_UsesDeviceWarning;
var
  LSnapshots: TArray<TMHSnapshot>;
  LFinding: TMHFinding;
begin
  // 61 °C: выше порога производителя 60 °C (жёсткий диск), хотя ниже общего 65 °C.
  LSnapshots := BuildSnapshots(nil, 5, False, nil);
  AddSensors(LSnapshots, TMHSensorReading.Create(skDisk, 'ST2000DM008', 'storage', 61, 60));
  AddSensors(LSnapshots, TMHSensorReading.Create(skDisk, 'KINGSTON SNV2S500G', 'storage', 62, 83));
  Assert.IsTrue(FindByKey(RunAll(LSnapshots), 'system:heat:disk', LFinding));
  Assert.IsTrue(LFinding.Evidence[0].Observed.Contains('ST2000DM008'),
    'Указан накопитель, превысивший свой порог, а не самый горячий');
end;

procedure TAnalyzerGpuTests.Throttling_SustainedLimit_Finding;
var
  LSnapshots: TArray<TMHSnapshot>;
  LFinding: TMHFinding;
begin
  LSnapshots := BuildSnapshots(nil, 5, False, nil);
  AddMetric(LSnapshots, mkCpuPerformanceLimitPercent, 70);
  Assert.IsTrue(FindByKey(RunAll(LSnapshots), 'system:throttle', LFinding));
  Assert.IsTrue(HasCode(LFinding, EV_THROTTLING));
  Assert.IsTrue(LFinding.Evidence[0].Observed.Contains('70%'));
end;

procedure TAnalyzerGpuTests.Throttling_ShortDip_NoFinding;
var
  LSnapshots: TArray<TMHSnapshot>;
  LFinding: TMHFinding;
begin
  // Ограничение только в последние 3 минуты из 15.
  LSnapshots := BuildSnapshots(nil, 5, False, nil);
  AddMetric(LSnapshots, mkCpuPerformanceLimitPercent, 100, 0);
  AddMetric(LSnapshots, mkCpuPerformanceLimitPercent, 60, Length(LSnapshots) - 18);
  Assert.IsFalse(FindByKey(RunAll(LSnapshots), 'system:throttle', LFinding));
end;

procedure TAnalyzerGpuTests.ExplainLoad_GpuTopConsumerWithCompute;
var
  LSnapshots: TArray<TMHSnapshot>;
  LReasons: TArray<TMHLoadReason>;
  LReason: TMHLoadReason;
  LFound: Boolean;
begin
  LSnapshots := BuildSnapshots([GpuProcess(4006, 'gpuhost.exe', 'C:\x\gpuhost.exe', sgUnsigned, '', 2, 92, 90),
    GpuProcess(4007, 'chrome.exe', 'C:\y\chrome.exe', sgSignedTrusted, 'Google', 2, 4, 0)], 5, False, nil, 1);
  LReasons := MHExplainLoad(LSnapshots[High(LSnapshots)], 8);
  LFound := False;
  for LReason in LReasons do
    if LReason.Resource = 'gpu' then
    begin
      LFound := True;
      Assert.IsTrue(LReason.IsHigh);
      Assert.IsTrue(LReason.Text.Contains('gpuhost.exe 92%, вычисления 90%'), LReason.Text);
      Assert.IsTrue(LReason.Text.IndexOf('gpuhost.exe') < LReason.Text.IndexOf('chrome.exe'));
    end;
  Assert.IsTrue(LFound);
end;

procedure TAnalyzerGpuTests.ExplainLoad_HeatNearLimitIsHigh;
var
  LSnapshot: TMHSnapshot;
  LReasons: TArray<TMHLoadReason>;
  LReason: TMHLoadReason;
  LCount: Integer;
begin
  LSnapshot := TMHSnapshot.Create(1, SCENARIO_START);
  LSnapshot.Sensors := [TMHSensorReading.Create(skGpu, 'GeForce', 'D3DKMT', 80, 83),
    TMHSensorReading.Create(skDisk, 'NVMe', 'storage', 45, 83)];
  LReasons := MHExplainLoad(LSnapshot, 8);
  LCount := 0;
  for LReason in LReasons do
  begin
    if LReason.Resource = 'heat:gpu' then
    begin
      Inc(LCount);
      Assert.IsTrue(LReason.IsHigh, '80 °C при пороге 83 °C — ближе 5 °C');
      Assert.IsTrue(LReason.Text.Contains('порог производителя 83 °C'), LReason.Text);
    end;
    if LReason.Resource = 'heat:disk' then
    begin
      Inc(LCount);
      Assert.IsFalse(LReason.IsHigh);
    end;
  end;
  Assert.AreEqual(2, LCount);
end;

procedure TAnalyzerGpuTests.ExplainLoad_ThrottleAndMemoryAsTaskManager;
var
  LSnapshot: TMHSnapshot;
  LInfo: TMHProcessInfo;
  LReasons: TArray<TMHLoadReason>;
  LReason: TMHLoadReason;
begin
  LSnapshot := TMHSnapshot.Create(1, SCENARIO_START);
  LSnapshot.Metrics := [TMHMetric.Available(mkMemoryLoadPercent, 90, SCENARIO_START),
    TMHMetric.Available(mkCpuPerformanceLimitPercent, 65, SCENARIO_START)];
  LInfo := TMHProcessInfo.Create(TMHProcessId.Create(10, 1), 'big.exe', SCENARIO_START);
  LInfo.WorkingSet := TMHMetric.Available(mkWorkingSetBytes, 900 * 1048576.0, SCENARIO_START);
  LInfo.PrivateWorkingSet := TMHMetric.Available(mkPrivateWorkingSetBytes, 300 * 1048576.0, SCENARIO_START);
  LSnapshot.Processes := [LInfo];
  LReasons := MHExplainLoad(LSnapshot, 8);
  for LReason in LReasons do
  begin
    if LReason.Resource = 'memory' then
      Assert.IsTrue(LReason.Text.Contains('big.exe 300 МБ'), 'Память — частный рабочий набор: ' + LReason.Text);
    if LReason.Resource = 'throttle' then
    begin
      Assert.IsTrue(LReason.IsHigh);
      Assert.IsTrue(LReason.Text.Contains('65%'));
    end;
  end;
end;

procedure TAnalyzerGpuTests.TemperatureLimit_DefaultsAndDevice;
begin
  Assert.AreEqual(83.0, MHTemperatureLimit(TMHSensorReading.Create(skGpu, 'a', 'b', 50, 83)), 1e-9);
  Assert.AreEqual(87.0, MHTemperatureLimit(TMHSensorReading.Create(skGpu, 'a', 'b', 50, 0)), 1e-9);
  Assert.AreEqual(65.0, MHTemperatureLimit(TMHSensorReading.Create(skDisk, 'a', 'b', 50, 0)), 1e-9);
  Assert.AreEqual(90.0, MHTemperatureLimit(TMHSensorReading.Create(skCpu, 'a', 'b', 50, 0)), 1e-9);
  Assert.AreEqual('heat:gpu', MHHeatResourceName(skGpu));
  Assert.AreEqual('heat:disk', MHHeatResourceName(skDisk));
  Assert.AreEqual('heat:cpu', MHHeatResourceName(skCpu));
end;

initialization
  TDUnitX.RegisterTestFixture(TAnalyzerGpuTests);

end.
