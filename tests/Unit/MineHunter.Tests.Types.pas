unit MineHunter.Tests.Types;

interface

uses
  DUnitX.TestFramework,
  MineHunter.Core.Types;

type
  [TestFixture]
  [Category('Unit')]
  TProcessIdTests = class
  public
    [Test] procedure SamePidAndTime_AreEqual;
    [Test] procedure ReusedPid_DifferentCreateTime_AreDifferentInstances;
    [Test] procedure EqualIds_HaveEqualHash;
    [Test] procedure Empty_IsEmpty;
    [Test] procedure PidZeroWithCreateTime_IsNotEmpty;
    [Test] procedure ToString_ContainsPidAndTime;
  end;

  [TestFixture]
  [Category('Unit')]
  TMetricTests = class
  public
    [Test] procedure NoData_HasNoValue;
    [Test] procedure Available_ZeroValue_IsStillAvailable;
  end;

  [TestFixture]
  [Category('Unit')]
  TRiskThresholdTests = class
  public
    [Test] procedure Default_IsValid;
    [TestCase('0 -> none', '0,0')]
    [TestCase('14 -> none', '14,0')]
    [TestCase('15 -> low', '15,1')]
    [TestCase('34 -> low', '34,1')]
    [TestCase('35 -> review', '35,2')]
    [TestCase('60 -> suspicious', '60,3')]
    [TestCase('84 -> suspicious', '84,3')]
    [TestCase('85 -> highly', '85,4')]
    [TestCase('100 -> highly', '100,4')]
    procedure Default_LevelOf(AScore, AExpectedLevel: Integer);
    [Test] procedure ScoreOutOfRange_IsClamped;
    [Test] procedure NonIncreasingThresholds_AreInvalid;
    [Test] procedure InvalidThresholds_LevelOfRaises;
    [Test] procedure CustomThresholds_AreApplied;
  end;

  [TestFixture]
  [Category('Unit')]
  TModelTests = class
  public
    [Test] procedure ProcessInfo_Create_MetricsAreNoData;
    [Test] procedure Evidence_NegativeWeight_IsNegativeFactor;
    [Test] procedure Snapshot_FindProcess_DistinguishesReusedPid;
    [Test] procedure Snapshot_FindProcess_EmptySnapshot;
    [Test] procedure Snapshot_FindSource_IsCaseInsensitive;
    [Test] procedure Baseline_Empty_IsNotEstablished;
    [Test] procedure Baseline_IsEstablished_RespectsMinimum;
    [Test] procedure StateAndLevelNames_AreNotEmpty;
  end;

implementation

uses
  System.SysUtils;

{ TProcessIdTests }

procedure TProcessIdTests.SamePidAndTime_AreEqual;
begin
  Assert.IsTrue(TMHProcessId.Create(42, 1000) = TMHProcessId.Create(42, 1000));
  Assert.IsFalse(TMHProcessId.Create(42, 1000) <> TMHProcessId.Create(42, 1000));
end;

procedure TProcessIdTests.ReusedPid_DifferentCreateTime_AreDifferentInstances;
begin
  Assert.IsFalse(TMHProcessId.Create(42, 1000) = TMHProcessId.Create(42, 2000),
    'Переиспользованный PID не должен считаться тем же процессом');
end;

procedure TProcessIdTests.EqualIds_HaveEqualHash;
begin
  Assert.AreEqual(TMHProcessId.Create(7, 123456789).GetHashCode,
    TMHProcessId.Create(7, 123456789).GetHashCode);
end;

procedure TProcessIdTests.Empty_IsEmpty;
begin
  Assert.IsTrue(TMHProcessId.Empty.IsEmpty);
  Assert.IsFalse(TMHProcessId.Empty.HasCreateTime);
end;

procedure TProcessIdTests.PidZeroWithCreateTime_IsNotEmpty;
begin
  // PID 0 — System Idle Process; при известном времени это валидный экземпляр.
  Assert.IsFalse(TMHProcessId.Create(0, 5).IsEmpty);
end;

procedure TProcessIdTests.ToString_ContainsPidAndTime;
begin
  Assert.AreEqual('42@FF', TMHProcessId.Create(42, 255).ToString);
end;

{ TMetricTests }

procedure TMetricTests.NoData_HasNoValue;
var
  LMetric: TMHMetric;
begin
  LMetric := TMHMetric.NoData(mkGpuPercent, 1);
  Assert.IsFalse(LMetric.HasValue);
  Assert.AreEqual<TMHMetricKind>(mkGpuPercent, LMetric.Kind);
end;

procedure TMetricTests.Available_ZeroValue_IsStillAvailable;
var
  LMetric: TMHMetric;
begin
  LMetric := TMHMetric.Available(mkCpuPercent, 0, 1);
  Assert.IsTrue(LMetric.HasValue, 'Ноль — это измерение, а не отсутствие данных');
end;

{ TRiskThresholdTests }

procedure TRiskThresholdTests.Default_IsValid;
begin
  Assert.IsTrue(TMHRiskThresholds.Default.IsValid);
end;

procedure TRiskThresholdTests.Default_LevelOf(AScore, AExpectedLevel: Integer);
begin
  Assert.AreEqual(AExpectedLevel, Integer(Ord(TMHRiskThresholds.Default.LevelOf(AScore))));
end;

procedure TRiskThresholdTests.ScoreOutOfRange_IsClamped;
begin
  Assert.AreEqual<TMHRiskLevel>(rlNone, TMHRiskThresholds.Default.LevelOf(-50));
  Assert.AreEqual<TMHRiskLevel>(rlHighlySuspicious, TMHRiskThresholds.Default.LevelOf(1000));
  Assert.AreEqual(0, MHClampScore(-1));
  Assert.AreEqual(100, MHClampScore(101));
  Assert.AreEqual(50, MHClampScore(50));
end;

procedure TRiskThresholdTests.NonIncreasingThresholds_AreInvalid;
var
  LThresholds: TMHRiskThresholds;
begin
  LThresholds := TMHRiskThresholds.Default;
  LThresholds.Suspicious := LThresholds.NeedsReview;
  Assert.IsFalse(LThresholds.IsValid);

  LThresholds := TMHRiskThresholds.Default;
  LThresholds.Low := 0;
  Assert.IsFalse(LThresholds.IsValid, 'Порог 0 сделал бы любой процесс «низким риском»');

  LThresholds := TMHRiskThresholds.Default;
  LThresholds.HighlySuspicious := 101;
  Assert.IsFalse(LThresholds.IsValid);
end;

procedure TRiskThresholdTests.InvalidThresholds_LevelOfRaises;
var
  LThresholds: TMHRiskThresholds;
begin
  LThresholds := Default(TMHRiskThresholds);
  Assert.WillRaise(
    procedure
    var
      LLevel: TMHRiskLevel;
    begin
      LLevel := LThresholds.LevelOf(50);
      Assert.Fail('Ожидалось исключение, получен уровень ' + MHRiskLevelToString(LLevel));
    end, EMHError);
end;

procedure TRiskThresholdTests.CustomThresholds_AreApplied;
var
  LThresholds: TMHRiskThresholds;
begin
  LThresholds.Low := 10;
  LThresholds.NeedsReview := 20;
  LThresholds.Suspicious := 30;
  LThresholds.HighlySuspicious := 40;
  Assert.AreEqual<TMHRiskLevel>(rlSuspicious, LThresholds.LevelOf(35));
  Assert.AreEqual<TMHRiskLevel>(rlHighlySuspicious, LThresholds.LevelOf(40));
end;

{ TModelTests }

procedure TModelTests.ProcessInfo_Create_MetricsAreNoData;
var
  LInfo: TMHProcessInfo;
begin
  LInfo := TMHProcessInfo.Create(TMHProcessId.Create(1, 2), 'a.exe', 3);
  Assert.IsFalse(LInfo.Cpu.HasValue);
  Assert.IsFalse(LInfo.WorkingSet.HasValue);
  Assert.IsFalse(LInfo.PrivateBytes.HasValue);
  Assert.AreEqual(MH_UNKNOWN_COUNT, LInfo.ThreadCount);
  Assert.AreEqual<TMHSignatureState>(sgNotChecked, LInfo.Signature);
  Assert.AreEqual<TMHAccessLevel>(alUnknown, LInfo.Access);
end;

procedure TModelTests.Evidence_NegativeWeight_IsNegativeFactor;
begin
  Assert.IsTrue(TMHEvidence.Create('GAME', 'Активна полноэкранная игра', -20).IsNegativeFactor);
  Assert.IsFalse(TMHEvidence.Create('CPU', 'Длительная нагрузка', 20).IsNegativeFactor);
end;

procedure TModelTests.Snapshot_FindProcess_DistinguishesReusedPid;
var
  LSnapshot: TMHSnapshot;
  LInfo: TMHProcessInfo;
begin
  LSnapshot := TMHSnapshot.Create(1, 1);
  LSnapshot.Processes := [
    TMHProcessInfo.Create(TMHProcessId.Create(100, 1), 'old.exe', 1),
    TMHProcessInfo.Create(TMHProcessId.Create(100, 2), 'new.exe', 1)];
  Assert.IsTrue(LSnapshot.FindProcess(TMHProcessId.Create(100, 2), LInfo));
  Assert.AreEqual('new.exe', LInfo.Name);
  Assert.IsFalse(LSnapshot.FindProcess(TMHProcessId.Create(100, 3), LInfo));
end;

procedure TModelTests.Snapshot_FindProcess_EmptySnapshot;
var
  LSnapshot: TMHSnapshot;
  LInfo: TMHProcessInfo;
begin
  LSnapshot := TMHSnapshot.Create(1, 1);
  Assert.IsFalse(LSnapshot.FindProcess(TMHProcessId.Create(1, 1), LInfo));
  Assert.AreEqual('', LInfo.Name);
end;

procedure TModelTests.Snapshot_FindSource_IsCaseInsensitive;
var
  LSnapshot: TMHSnapshot;
  LStatus: TMHSourceStatus;
begin
  LSnapshot := TMHSnapshot.Create(1, 1);
  LSnapshot.Sources := [TMHSourceStatus.Create('Processes', ssPartial, 'нет прав', 1)];
  Assert.IsTrue(LSnapshot.FindSource('processes', LStatus));
  Assert.AreEqual<TMHSourceState>(ssPartial, LStatus.State);
  Assert.IsFalse(LSnapshot.FindSource('network', LStatus));
end;

procedure TModelTests.Baseline_Empty_IsNotEstablished;
begin
  Assert.IsFalse(TMHBaseline.Empty.IsEstablished(1));
  Assert.IsFalse(TMHBaseline.Empty.IsEstablished(0), 'Минимум 0 не должен делать профиль готовым');
end;

procedure TModelTests.Baseline_IsEstablished_RespectsMinimum;
var
  LBaseline: TMHBaseline;
begin
  LBaseline := TMHBaseline.Empty;
  LBaseline.SampleCount := 99;
  Assert.IsFalse(LBaseline.IsEstablished(100));
  LBaseline.SampleCount := 100;
  Assert.IsTrue(LBaseline.IsEstablished(100));
end;

procedure TModelTests.StateAndLevelNames_AreNotEmpty;
var
  LState: TMHSourceState;
  LLevel: TMHRiskLevel;
begin
  for LState := Low(TMHSourceState) to High(TMHSourceState) do
    Assert.IsNotEmpty(MHSourceStateToString(LState));
  for LLevel := Low(TMHRiskLevel) to High(TMHRiskLevel) do
    Assert.IsNotEmpty(MHRiskLevelToString(LLevel));
end;

initialization
  TDUnitX.RegisterTestFixture(TProcessIdTests);
  TDUnitX.RegisterTestFixture(TMetricTests);
  TDUnitX.RegisterTestFixture(TRiskThresholdTests);
  TDUnitX.RegisterTestFixture(TModelTests);

end.
