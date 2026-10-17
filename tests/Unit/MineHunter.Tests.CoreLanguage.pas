unit MineHunter.Tests.CoreLanguage;

{
  Английские тексты библиотеки: при включённом английском языке объяснения
  находок (заголовок, сводка, признаки, рекомендации) во всех сценариях угроз,
  причины нагрузки и отчёт «Проверить сейчас» не содержат русского текста.
  Имена программ и пути из данных сценария не проверяются — они не переводятся.
}

interface

uses
  System.SysUtils,
  DUnitX.TestFramework;

type
  [TestFixture]
  [Category('Unit')]
  TCoreLanguageTests = class
  public
    [TearDown] procedure TearDown;
    [Test] procedure Default_IsRussian;
    [Test] procedure Findings_AllScenarios_EnglishOnly;
    [Test] procedure CheckReport_EnglishOnly;
  end;

implementation

uses
  MineHunter.Core.Types, MineHunter.Core.Lang, MineHunter.Analysis.Engine,
  MineHunter.Core.CheckReport, MineHunter.Tests.Scenarios;

function HasCyrillic(const AText: string): Boolean;
var
  C: Char;
begin
  for C in AText do
    if ((C >= #$0410) and (C <= #$044F)) or (C = #$0401) or (C = #$0451) then
      Exit(True);
  Result := False;
end;

/// Текст без данных сценария (имён процессов, путей, командных строк).
function Strip(const AText: string; const AData: TArray<string>): string;
var
  LItem: string;
begin
  Result := AText;
  for LItem in AData do
    if LItem <> '' then
      Result := Result.Replace(LItem, '', [rfReplaceAll, rfIgnoreCase]);
end;

procedure TCoreLanguageTests.TearDown;
begin
  MHSetCoreEnglish(False);
end;

procedure TCoreLanguageTests.Default_IsRussian;
begin
  Assert.IsFalse(MHCoreEnglish);
  Assert.AreEqual('да', MHL('да', 'yes'));
  MHSetCoreEnglish(True);
  Assert.AreEqual('yes', MHL('да', 'yes'));
end;

procedure TCoreLanguageTests.Findings_AllScenarios_EnglishOnly;
var
  LScenario: TScenario;
  LAnalyzer: TMHThreatAnalyzer;
  LFindings: TMHFindings;
  LFinding: TMHFinding;
  LEvidence: TMHEvidence;
  LSnapshot: TMHSnapshot;
  LInfo: TMHProcessInfo;
  LEntry: TMHAutostartEntry;
  LTamper: TMHTamperEntry;
  LData: TArray<string>;
  LText, LRecommendation: string;
  LChecked: Integer;
begin
  MHSetCoreEnglish(True);
  LChecked := 0;
  for LScenario in BuildScenarios do
  begin
    LData := nil;
    for LSnapshot in LScenario.Snapshots do
    begin
      for LInfo in LSnapshot.Processes do
        LData := LData + [LInfo.ImagePath, LInfo.Name, LInfo.CommandLine];
      for LEntry in LSnapshot.Autostart do
        LData := LData + [LEntry.Name, LEntry.Command, LEntry.ImagePath, LEntry.Location, LEntry.Details];
      for LTamper in LSnapshot.Tamper do
        LData := LData + [LTamper.Name, LTamper.Value, LTamper.Location, LTamper.ImagePath, LTamper.Details];
    end;
    LAnalyzer := TMHThreatAnalyzer.Create(SCENARIO_CPU_COUNT, 999999);
    try
      LAnalyzer.Exclusions := LScenario.Exclusions;
      LFindings := nil;
      for LSnapshot in LScenario.Snapshots do
        LFindings := LAnalyzer.Analyze(LSnapshot, TMHBaseline.Empty);
    finally
      LAnalyzer.Free;
    end;
    for LFinding in LFindings do
    begin
      Inc(LChecked);
      LText := LFinding.Title + ' | ' + LFinding.Summary;
      for LEvidence in LFinding.Evidence do
        LText := LText + ' | ' + LEvidence.Description + ' | ' + LEvidence.Observed;
      for LRecommendation in LFinding.Recommendations do
        LText := LText + ' | ' + LRecommendation;
      LText := Strip(LText, LData);
      Assert.IsFalse(HasCyrillic(LText), LScenario.Name + ': ' + LText);
    end;
  end;
  Assert.IsTrue(LChecked > 10, 'Проверено находок: ' + IntToStr(LChecked));
end;

procedure TCoreLanguageTests.CheckReport_EnglishOnly;
var
  LInput: TMHCheckReportInput;
  LFinding: TMHFinding;
  LReport: TMHCheckReport;
begin
  MHSetCoreEnglish(True);
  LInput := Default(TMHCheckReportInput);
  LInput.Snapshot := TMHSnapshot.Create(1, SCENARIO_START);
  LInput.Snapshot.Metrics := [TMHMetric.Available(mkCpuPercent, 95, SCENARIO_START),
    TMHMetric.Available(mkGpuPowerWatts, 180, SCENARIO_START),
    TMHMetric.Available(mkCpuPerformanceLimitPercent, 70, SCENARIO_START)];
  LInput.Snapshot.Sensors := [TMHSensorReading.Create(skGpu, 'GPU0', 'NVML', 90, 83)];
  LInput.Snapshot.Sources := [TMHSourceStatus.Create('network', ssPartial, '', SCENARIO_START)];
  LFinding := Default(TMHFinding);
  LFinding.Key := 'k';
  LFinding.Title := 'Hidden mining';
  LFinding.Level := rlHighlySuspicious;
  LFinding.Score := 99;
  LInput.Findings := [LFinding];
  LInput.CpuCount := 8;
  LInput.ChangesAvailable := True;
  LInput.ChangesDays := 7;
  LInput.ElectricityPrice := 6;
  LReport := MHBuildCheckReport(LInput);
  Assert.IsFalse(HasCyrillic(LReport.Headline), LReport.Headline);
  Assert.IsFalse(HasCyrillic(LReport.Text.Replace('₽', '')), LReport.Text);
end;

initialization
  TDUnitX.RegisterTestFixture(TCoreLanguageTests);

end.
