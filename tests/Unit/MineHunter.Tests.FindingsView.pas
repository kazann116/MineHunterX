unit MineHunter.Tests.FindingsView;

interface

uses
  DUnitX.TestFramework,
  MineHunter.Core.Types, MineHunter.App.FindingsView;

type
  [TestFixture]
  [Category('Unit')]
  TFindingsViewTests = class
  private
    FModel: TMHFindingsModel;
  public
    [Setup] procedure Setup;
    [TearDown] procedure TearDown;
    [Test] procedure Repeats_AreMergedByKey;
    [Test] procedure StaleFindings_StopBeingActive;
    [Test] procedure Sorting_ByLevelThenScore;
    [Test] procedure MinLevelFilter;
    [Test] procedure RiskOf_UsesFullIdentity;
    [Test] procedure ActiveAlertCount_CountsReviewAndAbove;
    [Test] procedure HistoryMode_ShowsStoredFindings;
    [Test] procedure CardLines_ContainEvidenceBothWaysAndRuleset;
  end;

implementation

uses
  System.SysUtils, MineHunter.Core.Interfaces;

const
  T0 = 46311.5;
  SEC = 1 / SecsPerDay;

function F(const AKey: string; ALevel: TMHRiskLevel; AScore: Integer; APid: Cardinal; ATime: TDateTime): TMHFinding;
begin
  Result := Default(TMHFinding);
  Result.Key := AKey;
  Result.Level := ALevel;
  Result.Score := AScore;
  Result.Process := TMHProcessId.Create(APid, 100 + APid);
  Result.ProcessName := AKey + '.exe';
  Result.Title := 'Находка ' + AKey;
  Result.DetectedAtUtc := ATime;
  Result.RulesetVersion := 'MH-test';
  Result.Evidence := [TMHEvidence.Create('A', 'положительный', 20, 'было'),
    TMHEvidence.Create('B', 'оправдывающий', -10)];
  Result.MissingData := ['нет подписи'];
  Result.Recommendations := ['проверить'];
  Result.Confidence := 0.8;
end;

procedure TFindingsViewTests.Setup;
begin
  FModel := TMHFindingsModel.Create(60);
end;

procedure TFindingsViewTests.TearDown;
begin
  FreeAndNil(FModel);
end;

procedure TFindingsViewTests.Repeats_AreMergedByKey;
begin
  FModel.UpdateActive([F('a', rlSuspicious, 60, 1, T0)], T0);
  FModel.UpdateActive([F('a', rlHighlySuspicious, 90, 1, T0 + 2 * SEC)], T0 + 2 * SEC);
  FModel.UpdateActive([F('a', rlSuspicious, 70, 1, T0 + 4 * SEC)], T0 + 4 * SEC);
  Assert.AreEqual(1, FModel.Count);
  Assert.AreEqual(3, FModel[0].Occurrences);
  Assert.AreEqual(90, FModel[0].MaxScore);
  Assert.AreEqual(70, FModel[0].Finding.Score, 'Показывается последняя версия');
  Assert.AreEqual(T0, FModel[0].FirstSeenUtc, 1e-9);
end;

procedure TFindingsViewTests.StaleFindings_StopBeingActive;
begin
  FModel.UpdateActive([F('a', rlSuspicious, 60, 1, T0)], T0);
  FModel.UpdateActive([], T0 + 30 * SEC);
  Assert.AreEqual(1, FModel.Count);
  FModel.UpdateActive([], T0 + 61 * SEC);
  Assert.AreEqual(0, FModel.Count);
end;

procedure TFindingsViewTests.Sorting_ByLevelThenScore;
begin
  FModel.UpdateActive([F('low', rlLow, 20, 1, T0), F('high', rlHighlySuspicious, 95, 2, T0),
    F('mid1', rlSuspicious, 61, 3, T0), F('mid2', rlSuspicious, 75, 4, T0)], T0);
  Assert.AreEqual('high', FModel[0].Finding.Key);
  Assert.AreEqual('mid2', FModel[1].Finding.Key);
  Assert.AreEqual('mid1', FModel[2].Finding.Key);
  Assert.AreEqual('low', FModel[3].Finding.Key);
  Assert.AreEqual(2, FModel.IndexOfKey('mid1'));
  Assert.AreEqual(-1, FModel.IndexOfKey('none'));
end;

procedure TFindingsViewTests.MinLevelFilter;
begin
  FModel.UpdateActive([F('low', rlLow, 20, 1, T0), F('high', rlSuspicious, 70, 2, T0)], T0);
  FModel.MinLevel := rlNeedsReview;
  Assert.AreEqual(1, FModel.Count);
  FModel.MinLevel := rlLow;
  Assert.AreEqual(2, FModel.Count);
end;

procedure TFindingsViewTests.RiskOf_UsesFullIdentity;
begin
  FModel.UpdateActive([F('a', rlSuspicious, 70, 5, T0)], T0);
  Assert.AreEqual<TMHRiskLevel>(rlSuspicious, FModel.RiskOf(TMHProcessId.Create(5, 105)));
  Assert.AreEqual<TMHRiskLevel>(rlNone, FModel.RiskOf(TMHProcessId.Create(5, 999)),
    'Другой экземпляр с тем же PID');
end;

procedure TFindingsViewTests.ActiveAlertCount_CountsReviewAndAbove;
begin
  FModel.UpdateActive([F('low', rlLow, 20, 1, T0), F('rev', rlNeedsReview, 40, 2, T0),
    F('sus', rlSuspicious, 70, 3, T0)], T0);
  Assert.AreEqual(2, FModel.ActiveAlertCount);
  Assert.AreEqual(3, FModel.ActiveAlertCount(rlLow));
end;

procedure TFindingsViewTests.HistoryMode_ShowsStoredFindings;
var
  LStored: TMHStoredFinding;
begin
  LStored := Default(TMHStoredFinding);
  LStored.Finding := F('old', rlSuspicious, 65, 9, T0 - 1);
  LStored.FirstSeenUtc := T0 - 1;
  LStored.LastSeenUtc := T0 - 0.5;
  LStored.Occurrences := 12;
  LStored.MaxScore := 80;
  FModel.SetHistory([LStored]);
  Assert.AreEqual(0, FModel.Count, 'В режиме активных тревог история не видна');
  FModel.Mode := fmHistory;
  Assert.AreEqual(1, FModel.Count);
  Assert.AreEqual(12, FModel[0].Occurrences);
  Assert.IsFalse(FModel[0].Active);
end;

procedure TFindingsViewTests.CardLines_ContainEvidenceBothWaysAndRuleset;
var
  LRow: TMHFindingRow;
  LText: string;
  LProcess: TMHProcessInfo;
begin
  FModel.UpdateActive([F('a', rlSuspicious, 70, 5, T0)], T0);
  LRow := FModel[0];
  LProcess := TMHProcessInfo.Create(LRow.Finding.Process, 'a.exe', T0);
  LProcess.Signature := sgUnsigned;
  LText := string.Join(#10, MHFindingCardLines(LRow, LProcess, True, 'explorer.exe'));
  Assert.IsTrue(LText.Contains('+ положительный (+20): было'), LText);
  Assert.IsTrue(LText.Contains('− оправдывающий (-10)'), LText);
  Assert.IsTrue(LText.Contains('нет подписи'), LText);
  Assert.IsTrue(LText.Contains('Родительский процесс: explorer.exe'), LText);
  Assert.IsTrue(LText.Contains('без цифровой подписи'), LText);
  Assert.IsTrue(LText.Contains('Версия правил: MH-test'), LText);
  LText := string.Join(#10, MHFindingCardLines(LRow, LProcess, False, ''));
  Assert.IsTrue(LText.Contains('сейчас не выполняется'), LText);
end;

initialization
  TDUnitX.RegisterTestFixture(TFindingsViewTests);

end.
